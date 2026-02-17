"""
Input validation functions for security-critical operations.
Provides strict allowlist-based validation for domains, IPs, URLs, and other user inputs.
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_domain(domain: str, allow_wildcard: bool = False) -> str:
    """
    Validate and sanitize a domain name using strict rules.
    
    Args:
        domain: The domain to validate
        allow_wildcard: Whether to allow wildcard domains (*.example.com)
    
    Returns:
        Sanitized domain name
        
    Raises:
        ValidationError: If domain is invalid
    """
    if not domain or not isinstance(domain, str):
        raise ValidationError("Domain cannot be empty")
    
    domain = domain.strip().lower()
    
    # Remove http(s):// if present
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    
    # Remove trailing slashes and paths
    domain = domain.split('/')[0]
    
    # Remove port if present
    if ':' in domain and not domain.startswith('['):  # Not IPv6
        domain = domain.split(':')[0]
    
    # Check for wildcard
    if domain.startswith('*.'):
        if not allow_wildcard:
            raise ValidationError("Wildcard domains not allowed")
        domain = domain[2:]  # Remove *. for further validation
    
    # Domain validation regex (RFC 1035)
    # Allows: alphanumeric, hyphens, dots
    # Does not allow: starting/ending with hyphen, consecutive dots
    domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    
    if not re.match(domain_pattern, domain):
        raise ValidationError(f"Invalid domain format: {domain}")
    
    # Additional length checks
    if len(domain) > 253:
        raise ValidationError("Domain name too long (max 253 characters)")
    
    # Check each label (part between dots)
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            raise ValidationError(f"Domain label too long: {label} (max 63 characters)")
        if label.startswith('-') or label.endswith('-'):
            raise ValidationError(f"Domain label cannot start or end with hyphen: {label}")
    
    return domain


def validate_ip_address(ip: str, allow_private: bool = True) -> str:
    """
    Validate and sanitize an IP address (IPv4 or IPv6).
    
    Args:
        ip: The IP address to validate
        allow_private: Whether to allow private IP ranges
    
    Returns:
        Sanitized IP address
        
    Raises:
        ValidationError: If IP is invalid
    """
    if not ip or not isinstance(ip, str):
        raise ValidationError("IP address cannot be empty")
    
    ip = ip.strip()
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        if not allow_private and ip_obj.is_private:
            raise ValidationError(f"Private IP addresses not allowed: {ip}")
        
        # Reject loopback and other special addresses in most cases
        if ip_obj.is_loopback:
            raise ValidationError(f"Loopback addresses not allowed: {ip}")
        
        if ip_obj.is_multicast:
            raise ValidationError(f"Multicast addresses not allowed: {ip}")
        
        return str(ip_obj)
    
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip} ({str(e)})")


def validate_url(url: str, require_https: bool = False, allow_private: bool = True) -> str:
    """
    Validate and sanitize a URL.
    
    Args:
        url: The URL to validate
        require_https: Whether to require HTTPS scheme
        allow_private: Whether to allow private IP addresses in URL
    
    Returns:
        Sanitized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL cannot be empty")
    
    url = url.strip()
    
    # Add http:// if no scheme provided
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme not in ['http', 'https']:
            raise ValidationError(f"Invalid URL scheme: {parsed.scheme} (only http/https allowed)")
        
        if require_https and parsed.scheme != 'https':
            raise ValidationError("HTTPS required for this URL")
        
        # Validate hostname
        if not parsed.netloc:
            raise ValidationError("URL missing hostname")
        
        hostname = parsed.netloc.split(':')[0]  # Remove port
        
        # Try to validate as IP first
        try:
            validate_ip_address(hostname, allow_private=allow_private)
        except ValidationError:
            # Not an IP, validate as domain
            try:
                validate_domain(hostname)
            except ValidationError as e:
                raise ValidationError(f"Invalid URL hostname: {str(e)}")
        
        # Validate port if present
        if ':' in parsed.netloc:
            port_str = parsed.netloc.split(':')[1]
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValidationError(f"Invalid port number: {port}")
            except ValueError:
                raise ValidationError(f"Invalid port format: {port_str}")
        
        # Reconstruct clean URL
        return parsed.geturl()
    
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Invalid URL: {str(e)}")


def validate_target(target: str, allow_urls: bool = True, allow_domains: bool = True, 
                   allow_ips: bool = True, allow_private: bool = True) -> tuple[str, str]:
    """
    Validate a scan target (can be URL, domain, or IP).
    
    Args:
        target: The target to validate
        allow_urls: Whether to allow full URLs
        allow_domains: Whether to allow domain names
        allow_ips: Whether to allow IP addresses
        allow_private: Whether to allow private IPs
    
    Returns:
        Tuple of (sanitized_target, target_type) where type is 'url', 'domain', or 'ip'
        
    Raises:
        ValidationError: If target is invalid or not allowed
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target cannot be empty")
    
    target = target.strip()
    
    # Check for dangerous characters that should never appear
    dangerous_chars = [';', '&', '|', '`', '$', '\n', '\r', '\x00', '(', ')', '{', '}', '<', '>']
    for char in dangerous_chars:
        if char in target:
            raise ValidationError(f"Invalid character in target: {repr(char)}")
    
    # Check if it looks like a URL
    if target.startswith(('http://', 'https://')):
        if not allow_urls:
            raise ValidationError("URLs not allowed for this scan type")
        return validate_url(target, allow_private=allow_private), 'url'
    
    # Detect if this looks like an IP address by trying to parse it
    # This is more reliable than trying validation first
    is_ip = False
    try:
        import ipaddress
        ipaddress.ip_address(target.split(':')[0])  # Remove port if present
        is_ip = True
    except ValueError:
        pass
    
    if is_ip:
        # It's an IP address
        if not allow_ips:
            raise ValidationError("IP addresses not allowed for this scan type")
        validated_ip = validate_ip_address(target, allow_private=allow_private)
        return validated_ip, 'ip'
    else:
        # It's a domain name
        if not allow_domains:
            raise ValidationError("Domain names not allowed for this scan type")
        validated_domain = validate_domain(target)
        return validated_domain, 'domain'


def sanitize_scan_options(options: str, max_length: int = 200) -> str:
    """
    Sanitize scan options to prevent command injection.
    
    Args:
        options: The options string to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized options string
        
    Raises:
        ValidationError: If options contain dangerous patterns
    """
    if not options:
        return ""
    
    if not isinstance(options, str):
        raise ValidationError("Options must be a string")
    
    options = options.strip()
    
    # Check length
    if len(options) > max_length:
        raise ValidationError(f"Options too long (max {max_length} characters)")
    
    # Check for command injection patterns
    dangerous_patterns = [
        r'\$\(',  # Command substitution $(...)
        r'`',     # Backtick command substitution
        r';',     # Command separator
        r'\|',    # Pipe
        r'&',     # Background/AND
        r'>',     # Redirect
        r'<',     # Redirect
        r'\n',    # Newline
        r'\r',    # Carriage return
        r'\x00',  # Null byte
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, options):
            raise ValidationError(f"Dangerous pattern detected in options: {pattern}")
    
    # Allowlist common safe nmap options
    # This is a basic implementation - could be expanded with more sophisticated parsing
    allowed_option_pattern = r'^[\w\s\-\.,:/=]*$'
    if not re.match(allowed_option_pattern, options):
        raise ValidationError("Options contain invalid characters")
    
    return options
