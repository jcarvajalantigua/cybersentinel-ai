# Security Best Practices Guide

## Overview

This document outlines security best practices for deploying and operating CyberSentinel AI in production environments. Following these guidelines will help protect against the OWASP Top 10 vulnerabilities and other common security risks.

## 1. Authentication & Authorization

### API Key Configuration

**Always enable API authentication in production:**

```bash
API_AUTH_ENABLED=true
API_KEY=<generate-strong-random-key>
```

Generate strong API keys using:
```bash
# Generate a 48-character random API key
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Admin Key (Optional but Recommended)

For additional security on sensitive operations (settings updates, configuration changes):

```bash
ADMIN_API_KEY=<generate-different-strong-key>
```

When `ADMIN_API_KEY` is set:
- Regular `API_KEY` grants access to all endpoints
- `ADMIN_API_KEY` is required for `/api/settings/update` and other admin operations
- This implements role-based access control (RBAC)

### Security Recommendations

- **Never commit real API keys** to version control
- Use different keys for development, staging, and production
- Rotate API keys periodically (e.g., every 90 days)
- Use minimum 32-character keys (48+ recommended)
- Store keys in environment variables or secret management systems
- Audit admin operations and log all key usage

## 2. Secret Management

### Required Secrets for Production

Change ALL default passwords before deploying:

```bash
# Application
SECRET_KEY=<strong-random-value>
NEO4J_PASSWORD=<strong-password>

# External Services (if used)
SPLUNK_PASSWORD=<strong-password>
WAZUH_PASSWORD=<strong-password>
```

### Secret Storage Best Practices

1. **Never use default values in production** - the application will warn you on startup
2. **Disable plaintext persistence** of secrets:
   ```bash
   ALLOW_PLAINTEXT_SECRET_PERSISTENCE=false
   ```
3. **Use secret management systems** for production:
   - Docker Secrets
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Google Secret Manager

4. **Restrict file permissions** on `.env` files:
   ```bash
   chmod 600 .env
   chown app-user:app-user .env
   ```

## 3. CORS Configuration

### Development vs Production

**Development (default):**
```bash
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

**Production:**
```bash
# Set to your actual frontend URL(s)
CORS_ORIGINS=https://your-domain.com
# Or multiple origins
CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

### Security Rules

- ✅ **DO** specify exact origins in production
- ❌ **DON'T** use `*` (wildcard) in production
- ✅ **DO** use HTTPS origins in production
- ✅ **DO** limit to necessary origins only
- ❌ **DON'T** include development URLs in production config

## 4. Input Validation

All user inputs for scan targets are automatically validated using strict rules:

### Valid Target Types

1. **Domains:** `example.com`, `sub.example.com`
2. **IP Addresses:** `8.8.8.8`, `2001:db8::1`
3. **URLs:** `https://example.com`, `http://example.com:8080/path`

### Automatic Protection Against

- Command injection (`;`, `|`, `&&`, `$()`, backticks)
- Path traversal (`../`, `./`)
- Script injection (`<script>`, `${...}`)
- Null byte injection (`\x00`)
- Invalid characters in domains/IPs

### Scan Options Validation

Scan options are validated to prevent command injection:
- Maximum length: 200 characters
- Allowed characters: alphanumeric, hyphens, spaces, dots, colons, slashes, equals
- Blocked: pipes, semicolons, backticks, redirects, command substitution

## 5. Network Security

### Deployment Architecture

**Development:**
- All services on `localhost`
- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`

**Production:**
```
Internet
    ↓
[Reverse Proxy / Load Balancer]
    ├─→ Frontend (HTTPS only)
    └─→ Backend (internal network only)
         ├─→ Neo4j (internal)
         ├─→ Elasticsearch (internal)
         └─→ Sandbox (isolated)
```

### Security Checklist

- [ ] Use HTTPS for all external-facing services
- [ ] Keep backend on private network (not exposed to internet)
- [ ] Use reverse proxy (nginx/traefik) with rate limiting
- [ ] Implement IP allowlisting for admin endpoints
- [ ] Use network segmentation for sandbox container
- [ ] Enable TLS for all internal service connections
- [ ] Configure firewall rules to restrict traffic

## 6. Container Security

### Docker Best Practices

1. **Run as non-root user** in containers
2. **Scan images** for vulnerabilities regularly
3. **Use minimal base images** (alpine, distroless)
4. **Pin specific versions** of dependencies
5. **Enable Docker security features:**
   ```yaml
   security_opt:
     - no-new-privileges:true
   cap_drop:
     - ALL
   cap_add:
     - NET_BIND_SERVICE  # Only if needed
   ```

### Sandbox Isolation

The sandbox container is already isolated, but additional hardening:

```yaml
sandbox:
  security_opt:
    - apparmor=docker-default
    - seccomp=/path/to/seccomp-profile.json
  cap_drop:
    - ALL
  cap_add:
    - NET_RAW  # Required for nmap
  read_only: true
  tmpfs:
    - /tmp
```

## 7. Monitoring & Logging

### Security Event Logging

Enable logging for:
- All authentication attempts (success/failure)
- Admin operations (settings changes)
- Failed validation attempts
- Scan executions with target information
- API rate limit violations

### Log Analysis

Monitor logs for:
- Repeated authentication failures
- Command injection attempts (blocked by validators)
- Unusual scan patterns
- Access from unexpected IP addresses

### Recommended Tools

- **SIEM Integration:** ELK Stack, Splunk, Wazuh (already integrated!)
- **Alerting:** Set up alerts for security events
- **Audit Logs:** Maintain immutable audit trail

## 8. Regular Security Maintenance

### Weekly

- Review authentication logs for anomalies
- Check for failed scan attempts
- Monitor resource usage for DoS indicators

### Monthly

- Update Docker images and dependencies
- Review and rotate API keys if needed
- Scan for new CVEs in dependencies
- Review access logs and user activity

### Quarterly

- Conduct security review of code changes
- Penetration testing of API endpoints
- Review and update security policies
- Rotate all credentials and secrets

## 9. Incident Response

### If Credentials Are Compromised

1. **Immediately** regenerate and rotate all API keys
2. Review logs for unauthorized access
3. Check for malicious scan activity
4. Update affected systems
5. Notify stakeholders

### If Vulnerability Is Discovered

1. Assess severity and impact
2. Apply patches or mitigations immediately
3. Review logs for exploitation attempts
4. Document incident and response
5. Update security controls

## 10. Compliance & Standards

### OWASP Top 10 Mitigations

This application implements protections against:

1. **A01:2021 - Broken Access Control**
   - ✅ API key authentication on all endpoints
   - ✅ Admin role separation for sensitive operations

2. **A02:2021 - Cryptographic Failures**
   - ✅ Secrets validation and rotation guidance
   - ✅ HTTPS enforcement in production

3. **A03:2021 - Injection**
   - ✅ Strict input validation on all scan targets
   - ✅ Parameterized commands where possible
   - ✅ Allowlist-based validation

4. **A04:2021 - Insecure Design**
   - ✅ Defense in depth with multiple validation layers
   - ✅ Secure defaults (auth enabled in production)

5. **A05:2021 - Security Misconfiguration**
   - ✅ Security headers validation in scans
   - ✅ Configuration validation on startup
   - ✅ No default credentials allowed in production

6. **A06:2021 - Vulnerable Components**
   - ✅ Pinned dependencies
   - ✅ Regular update schedule
   - ✅ Dependency vulnerability scanning

7. **A07:2021 - Authentication Failures**
   - ✅ Strong key requirements (32+ characters)
   - ✅ No default/weak credentials
   - ✅ Rate limiting (via reverse proxy)

8. **A08:2021 - Data Integrity Failures**
   - ✅ Sandboxed execution environment
   - ✅ Exit code validation for scan results

9. **A09:2021 - Logging Failures**
   - ✅ Security event logging
   - ✅ SIEM integration support

10. **A10:2021 - SSRF**
    - ✅ Target validation with IP/domain restrictions
    - ✅ Sandbox isolation for all scans

## Quick Start Security Checklist

Before deploying to production:

- [ ] Generate and set strong `SECRET_KEY`
- [ ] Generate and set strong `API_KEY` (48+ chars)
- [ ] Set `API_AUTH_ENABLED=true`
- [ ] Generate and set strong `ADMIN_API_KEY`
- [ ] Change all default passwords (Neo4j, Splunk, Wazuh)
- [ ] Set `ALLOW_PLAINTEXT_SECRET_PERSISTENCE=false`
- [ ] Configure CORS with specific origins (no `*`)
- [ ] Set `APP_ENV=production`
- [ ] Enable HTTPS on all external endpoints
- [ ] Restrict backend to internal network
- [ ] Set up log monitoring and alerting
- [ ] Configure firewall rules
- [ ] Set restrictive file permissions on `.env`
- [ ] Review and test authentication
- [ ] Document recovery procedures

## Support & Updates

- Check for security updates regularly
- Subscribe to security advisories for dependencies
- Review the [OWASP Top 10](https://owasp.org/www-project-top-ten/) for latest threats
- Join the security community discussions

---

**Last Updated:** 2026-02-17  
**Version:** 3.0  
**Status:** Production Ready with Security Hardening
