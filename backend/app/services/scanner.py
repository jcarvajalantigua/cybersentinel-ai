"""
CyberSentinel v2.0 - Scan Execution Service (Phase 3)
Executes real security tools inside the sandboxed container.
Uses Docker SDK to run commands in the 'sandbox' container.
"""
import asyncio
import json
import re
import time
from typing import Optional
from app.core.validators import validate_target, sanitize_scan_options, ValidationError

# Container name for the sandbox
SANDBOX_CONTAINER = "cybersentinel-v2-sandbox-1"


async def _run_in_sandbox(command: str, timeout: int = 120) -> dict:
    """Execute a command in the sandbox container via docker exec."""
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", SANDBOX_CONTAINER, "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "success": False,
                "error": f"Command timed out after {timeout}s",
                "command": command,
                "duration": timeout,
            }

        duration = round(time.time() - start, 2)
        out = stdout.decode("utf-8", errors="replace")[:50000]
        err = stderr.decode("utf-8", errors="replace")[:5000]
        # Keep stdout/stderr explicit and mark success from exit status.
        combined = out if out.strip() else err
        success = proc.returncode == 0
        return {
            "success": success,
            "status": "ok" if success else "error",
            "output": combined,
            "stdout": out,
            "stderr": err,
            "error": err if not success else "",
            "command": command,
            "duration": duration,
            "exit_code": proc.returncode,
        }
    except FileNotFoundError:
        return {"success": False, "error": "Docker CLI not available on backend", "command": command}
    except Exception as e:
        return {"success": False, "error": str(e)[:500], "command": command}


async def check_sandbox_health() -> dict:
    """Check if the sandbox container is running."""
    result = await _run_in_sandbox("echo ok", timeout=10)
    if result.get("success") and "ok" in result.get("output", ""):
        return {"status": "connected", "container": SANDBOX_CONTAINER}
    return {"status": "disconnected", "error": result.get("error", "Unknown")}


# ═══════════════════════════════════════════════
# SCAN FUNCTIONS - Each runs a real tool
# ═══════════════════════════════════════════════

def _sanitize(target: str) -> str:
    """Comprehensive sanitization against command injection."""
    if not target or not isinstance(target, str):
        return ""
    t = target.strip()
    # Strip all dangerous shell metacharacters
    for ch in [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "#", "\n", "\r", "\x00"]:
        t = t.replace(ch, "")
    # Remove common injection patterns
    t = re.sub(r'\$\(.*?\)', '', t)  # $(cmd)
    t = re.sub(r'`.*?`', '', t)      # `cmd`
    # Limit length to prevent buffer attacks
    t = t[:500]
    return t

def _strip_url(target: str) -> str:
    """Strip http:// https:// for tools that need bare domain/IP."""
    t = _sanitize(target)
    for prefix in ["https://", "http://"]:
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.rstrip("/").split("/")[0]  # Remove paths too
    # Reject if it starts with - (nmap flag injection)
    if t.startswith("-"):
        return ""
    return t


async def nmap_scan(target: str, options: str = "-sV -sC --top-ports 100") -> dict:
    """Run nmap port scan against a target."""
    try:
        # Validate target
        safe_target, target_type = validate_target(target, allow_urls=False)
        
        # Sanitize options
        safe_opts = sanitize_scan_options(options)
        
        # Build command using argument vector for better security
        # Note: Still using bash -c for now due to Docker exec limitations,
        # but with validated inputs this is much safer
        cmd = f"nmap {safe_opts} {safe_target} 2>&1"
        return await _run_in_sandbox(cmd, timeout=300)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "nmap"}


async def dns_recon(domain: str) -> dict:
    """Run DNS reconnaissance on a domain."""
    try:
        # Validate as domain only
        safe, target_type = validate_target(domain, allow_urls=False, allow_ips=False)
        
        commands = [
            f"echo '=== DNS Records ===' && dig {safe} ANY +short 2>&1",
            f"echo '\\n=== MX Records ===' && dig {safe} MX +short 2>&1",
            f"echo '\\n=== NS Records ===' && dig {safe} NS +short 2>&1",
            f"echo '\\n=== TXT Records ===' && dig {safe} TXT +short 2>&1",
            f"echo '\\n=== SPF Check ===' && dig {safe} TXT +short 2>&1 | grep -i spf",
            f"echo '\\n=== DMARC Check ===' && dig _dmarc.{safe} TXT +short 2>&1",
            f"echo '\\n=== DKIM Selector ===' && dig default._domainkey.{safe} TXT +short 2>&1",
        ]
        cmd = " && ".join(commands)
        return await _run_in_sandbox(cmd, timeout=60)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "dns"}


async def ssl_check(target: str) -> dict:
    """Check SSL/TLS certificate and configuration."""
    try:
        # Validate target (can be domain or IP)
        safe, target_type = validate_target(target, allow_urls=False)
        
        host = safe.split(":")[0]
        port = safe.split(":")[1] if ":" in safe else "443"
        
        # Validate port number
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return {"success": False, "error": f"Invalid port number: {port}", "command": "ssl"}
        except ValueError:
            return {"success": False, "error": f"Invalid port format: {port}", "command": "ssl"}
        
        commands = [
            f"echo '=== Certificate Info ===' && echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -text -dates -subject -issuer 2>&1",
            f"echo '\\n=== Supported Protocols ===' && for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do echo -n \"$proto: \"; echo | openssl s_client -connect {host}:{port} -$proto 2>&1 | grep -q 'Cipher is' && echo 'YES' || echo 'NO'; done",
            f"echo '\\n=== Certificate Chain ===' && echo | openssl s_client -connect {host}:{port} -servername {host} -showcerts 2>/dev/null | grep -E 's:|i:' | head -10",
        ]
        cmd = " && ".join(commands)
        return await _run_in_sandbox(cmd, timeout=30)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "ssl"}


async def whois_lookup(target: str) -> dict:
    """Run WHOIS lookup on domain or IP."""
    try:
        # Validate target
        safe, target_type = validate_target(target, allow_urls=False)
        return await _run_in_sandbox(f"whois {safe} 2>&1 | head -80", timeout=30)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "whois"}


async def nikto_scan(target: str) -> dict:
    """Run Nikto web vulnerability scanner."""
    try:
        # Validate target (can be URL or domain)
        safe, target_type = validate_target(target)
        
        # Nikto expects URLs
        if target_type != 'url':
            safe = f"http://{safe}"
        
        return await _run_in_sandbox(f"nikto -h {safe} -maxtime 120 2>&1", timeout=180)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "nikto"}


async def nuclei_scan(target: str, templates: str = "") -> dict:
    """Run Nuclei vulnerability scanner."""
    try:
        # Validate target
        safe, target_type = validate_target(target)
        
        # Nuclei expects URLs
        if target_type != 'url':
            safe = f"https://{safe}"
        
        # Sanitize template parameter if provided
        if templates:
            # Only allow alphanumeric, hyphens, slashes, commas for template paths
            if not re.match(r'^[\w\-/,]+$', templates):
                return {"success": False, "error": "Invalid template parameter", "command": "nuclei"}
            tmpl = f"-t {templates}"
        else:
            tmpl = "-severity critical,high"
        
        return await _run_in_sandbox(f"nuclei -u {safe} {tmpl} -stats -timeout 10 2>&1", timeout=300)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "nuclei"}


async def subfinder_enum(domain: str) -> dict:
    """Enumerate subdomains using subfinder."""
    try:
        # Validate as domain only
        safe, target_type = validate_target(domain, allow_urls=False, allow_ips=False)
        return await _run_in_sandbox(f"subfinder -d {safe} -silent 2>&1 | head -50", timeout=60)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "subfinder"}


async def traceroute_target(target: str) -> dict:
    """Run traceroute to target."""
    try:
        # Validate target
        safe, target_type = validate_target(target, allow_urls=False)
        return await _run_in_sandbox(f"traceroute -m 15 {safe} 2>&1", timeout=60)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "traceroute"}


async def ping_target(target: str, count: int = 4) -> dict:
    """Ping a target."""
    try:
        # Validate target
        safe, target_type = validate_target(target, allow_urls=False)
        
        # Validate count parameter
        if not isinstance(count, int) or count < 1 or count > 100:
            return {"success": False, "error": "Invalid count (must be 1-100)", "command": "ping"}
        
        return await _run_in_sandbox(f"ping -c {count} {safe} 2>&1", timeout=30)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "ping"}


async def curl_headers(url: str) -> dict:
    """Fetch HTTP headers from a URL."""
    try:
        # Validate as URL
        safe, target_type = validate_target(url)
        
        # curl_headers expects URLs
        if target_type != 'url':
            safe = f"https://{safe}"
        
        return await _run_in_sandbox(f"curl -sI -L --max-time 10 '{safe}' 2>&1", timeout=15)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "curl"}


async def sqlmap_scan(url: str) -> dict:
    """Run sqlmap SQL injection scanner."""
    try:
        # Validate as URL
        safe, target_type = validate_target(url)
        
        # sqlmap expects URLs
        if target_type != 'url':
            safe = f"http://{safe}"
        
        cmd = f"sqlmap -u '{safe}' --batch --level=1 --risk=1 --timeout=30 --retries=1 2>&1 | tail -80"
        return await _run_in_sandbox(cmd, timeout=120)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "sqlmap"}


async def zeek_analyze(target: str) -> dict:
    """Run Zeek network analysis on a target - generates connection logs, DNS, HTTP, SSL analysis.
    Can analyze a PCAP file or do live capture against a target."""
    try:
        # For PCAP files, just validate the path
        if target.endswith((".pcap", ".pcapng")):
            # Basic path validation - only allow alphanumeric, dots, slashes, underscores, hyphens
            if not re.match(r'^[\w\-/\.]+$', target):
                return {"success": False, "error": "Invalid PCAP file path", "command": "zeek"}
            safe = target
        else:
            # Validate as regular target
            safe, target_type = validate_target(target, allow_urls=False)
        
        # Zeek installs to /opt/zeek/bin - ensure it's in PATH
        zeek_path_prefix = "export PATH=/opt/zeek/bin:$PATH && "
        
        # If it looks like a pcap path, analyze it
        if target.endswith(".pcap") or target.endswith(".pcapng"):
            cmd = f"""{zeek_path_prefix}cd /tmp && zeek -r '{safe}' 2>&1
echo '=== conn.log ===' && cat conn.log 2>/dev/null | head -50
echo '=== dns.log ===' && cat dns.log 2>/dev/null | head -30
echo '=== http.log ===' && cat http.log 2>/dev/null | head -30
echo '=== ssl.log ===' && cat ssl.log 2>/dev/null | head -30
echo '=== notice.log ===' && cat notice.log 2>/dev/null | head -20"""
            return await _run_in_sandbox(cmd, timeout=60)
        else:
            # Live capture + analysis against target
            cmd = f"""{zeek_path_prefix}
# Start background capture
timeout 10 tcpdump -c 200 -w /tmp/capture.pcap host {safe} 2>/dev/null &
TCPDUMP_PID=$!
sleep 1
# Generate traffic to capture
curl -sI --max-time 3 http://{safe} 2>/dev/null
curl -sI --max-time 3 https://{safe} 2>/dev/null
nmap -sS -T4 --top-ports 20 {safe} 2>/dev/null > /dev/null
sleep 3
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

# Check capture file exists and has data
if [ ! -s /tmp/capture.pcap ]; then
  echo "ERROR: No traffic captured - target may be unreachable"
  exit 0
fi

echo "=== Capture Summary ==="
tcpdump -nn -r /tmp/capture.pcap 2>/dev/null | wc -l | xargs -I{{}} echo "Total packets captured: {{}}"

# Analyze with Zeek if available
if command -v zeek &>/dev/null; then
  echo "=== Zeek Analysis ==="
  cd /tmp && rm -f *.log 2>/dev/null
  zeek -r capture.pcap 2>&1
  echo "--- conn.log ---"
  cat /tmp/conn.log 2>/dev/null | head -40
  echo "--- dns.log ---"
  cat /tmp/dns.log 2>/dev/null | head -20
  echo "--- http.log ---"
  cat /tmp/http.log 2>/dev/null | head -20
  echo "--- ssl.log ---"
  cat /tmp/ssl.log 2>/dev/null | head -20
  echo "--- notice.log ---"
  cat /tmp/notice.log 2>/dev/null | head -10
  echo "--- files.log ---"
  cat /tmp/files.log 2>/dev/null | head -10
else
  echo "=== tcpdump Analysis (Zeek not installed) ==="
  tcpdump -nn -r /tmp/capture.pcap 2>/dev/null | head -60
fi"""
            return await _run_in_sandbox(cmd, timeout=45)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "zeek"}


async def zap_scan(target: str) -> dict:
    """Run OWASP ZAP baseline scan against a target URL with enhanced security checks."""
    try:
        # Validate as URL
        safe, target_type = validate_target(target)
        
        # ZAP expects URLs
        if target_type != 'url':
            safe = f"https://{safe}"
        
        # Enhanced ZAP scan with security header checks and common vulnerability paths
        cmd = f"""if command -v zap-cli &>/dev/null || [ -f /opt/ZAP_2.15.0/zap.sh ]; then
  echo "=== OWASP ZAP Baseline Scan ==="
  echo "Target: {safe}"
  # Use ZAP in headless/daemon mode with quick scan
  if [ -f /opt/ZAP_2.15.0/zap.sh ]; then
    /opt/ZAP_2.15.0/zap.sh -cmd -quickurl '{safe}' -quickout /tmp/zap_report.html -quickprogress 2>&1 | tail -40
    [ -f /tmp/zap_report.html ] && echo "=== Report generated ===" && cat /tmp/zap_report.html | python3 -c "import sys,html.parser; print(sys.stdin.read()[:3000])" 2>/dev/null || echo "Report saved"
  else
    python3 -c "
from zapv2 import ZAPv2
zap = ZAPv2(proxies={{'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}})
print('ZAP API available but daemon not running - use zap.sh')
" 2>&1
  fi
else
  echo "=== OWASP ZAP Not Available - Running Enhanced Security Checks ==="
  echo "Performing manual web security analysis..."
  echo ""
  echo "=== Security Headers Analysis ==="
  curl -sI --max-time 10 '{safe}' 2>&1 | grep -iE '(x-frame-options|x-content-type-options|strict-transport-security|content-security-policy|x-xss-protection|referrer-policy|permissions-policy)' || echo "WARNING: Missing security headers"
  echo ""
  echo "=== Missing Security Headers Check ==="
  headers=$(curl -sI --max-time 10 '{safe}' 2>&1)
  echo "$headers" | grep -iq 'x-frame-options' || echo "MISSING: X-Frame-Options (Clickjacking protection)"
  echo "$headers" | grep -iq 'x-content-type-options' || echo "MISSING: X-Content-Type-Options (MIME-sniffing protection)"
  echo "$headers" | grep -iq 'strict-transport-security' || echo "MISSING: Strict-Transport-Security (HSTS)"
  echo "$headers" | grep -iq 'content-security-policy' || echo "MISSING: Content-Security-Policy (XSS/injection protection)"
  echo ""
  echo "=== Common Vulnerability Paths ==="
  for path in robots.txt .env .git/config .git/HEAD admin login wp-admin wp-login.php .htaccess server-status .DS_Store backup.zip config.php phpinfo.php; do
    code=$(curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{safe}/$path' 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "FOUND [$code]: {safe}/$path"
  done
  echo ""
  echo "=== HTTP Methods Check ==="
  curl -sI -X OPTIONS --max-time 5 '{safe}' 2>&1 | grep -i allow || echo "OPTIONS method response not available"
  echo ""
  echo "=== SSL/TLS Security Analysis ==="
  host=$(echo '{safe}' | sed 's|https\\?://||;s|/.*||')
  if echo '{safe}' | grep -q '^https'; then
    echo | openssl s_client -connect $host:443 -brief 2>&1 | head -15
    echo ""
    echo "=== Cipher Strength ===" 
    echo | openssl s_client -connect $host:443 -cipher 'LOW:EXP' 2>&1 | grep -q 'Cipher is' && echo "WARNING: Weak ciphers enabled" || echo "OK: Weak ciphers disabled"
    echo ""
    echo "=== TLS Version Check ==="
    for ver in tls1 tls1_1; do
      echo | openssl s_client -connect $host:443 -$ver 2>&1 | grep -q 'Cipher is' && echo "WARNING: $ver enabled (deprecated)" || echo "OK: $ver disabled"
    done
  else
    echo "HTTPS not used - connection not encrypted"
  fi
fi"""
        return await _run_in_sandbox(cmd, timeout=90)
    except ValidationError as e:
        return {"success": False, "error": f"Validation error: {str(e)}", "command": "zap"}


# Map of scan types to functions
SCAN_REGISTRY = {
    "nmap": {"fn": nmap_scan, "desc": "Port scan & service detection", "params": ["target", "options"]},
    "dns": {"fn": dns_recon, "desc": "DNS records, SPF, DKIM, DMARC", "params": ["domain"]},
    "ssl": {"fn": ssl_check, "desc": "SSL/TLS certificate & protocol check", "params": ["target"]},
    "whois": {"fn": whois_lookup, "desc": "Domain/IP WHOIS registration", "params": ["target"]},
    "nikto": {"fn": nikto_scan, "desc": "Web vulnerability scanner", "params": ["target"]},
    "nuclei": {"fn": nuclei_scan, "desc": "CVE & misconfiguration scanner", "params": ["target", "templates"]},
    "subfinder": {"fn": subfinder_enum, "desc": "Subdomain enumeration", "params": ["domain"]},
    "traceroute": {"fn": traceroute_target, "desc": "Network path trace", "params": ["target"]},
    "ping": {"fn": ping_target, "desc": "ICMP connectivity test", "params": ["target"]},
    "headers": {"fn": curl_headers, "desc": "HTTP response headers", "params": ["url"]},
    "sqlmap": {"fn": sqlmap_scan, "desc": "SQL injection scanner", "params": ["url"]},
    "zeek": {"fn": zeek_analyze, "desc": "Network traffic analysis (Zeek/tcpdump)", "params": ["target"]},
    "zap": {"fn": zap_scan, "desc": "OWASP ZAP web app security scan", "params": ["target"]},
}
