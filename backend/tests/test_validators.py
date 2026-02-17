import unittest
from app.core.validators import (
    validate_domain, validate_ip_address, validate_url, validate_target,
    sanitize_scan_options, ValidationError
)


class DomainValidationTests(unittest.TestCase):
    def test_valid_domain(self):
        self.assertEqual(validate_domain("example.com"), "example.com")
        self.assertEqual(validate_domain("sub.example.com"), "sub.example.com")
        self.assertEqual(validate_domain("deep.sub.example.com"), "deep.sub.example.com")
    
    def test_domain_case_normalization(self):
        self.assertEqual(validate_domain("EXAMPLE.COM"), "example.com")
        self.assertEqual(validate_domain("Example.Com"), "example.com")
    
    def test_domain_strips_protocol(self):
        self.assertEqual(validate_domain("http://example.com"), "example.com")
        self.assertEqual(validate_domain("https://example.com"), "example.com")
    
    def test_domain_strips_path(self):
        self.assertEqual(validate_domain("example.com/path"), "example.com")
        self.assertEqual(validate_domain("example.com/path/to/page"), "example.com")
    
    def test_domain_strips_port(self):
        self.assertEqual(validate_domain("example.com:8080"), "example.com")
    
    def test_invalid_domain_empty(self):
        with self.assertRaises(ValidationError):
            validate_domain("")
    
    def test_invalid_domain_special_chars(self):
        with self.assertRaises(ValidationError):
            validate_domain("exa$mple.com")
        with self.assertRaises(ValidationError):
            validate_domain("example!.com")
    
    def test_wildcard_domain_not_allowed_by_default(self):
        with self.assertRaises(ValidationError):
            validate_domain("*.example.com")
    
    def test_wildcard_domain_allowed_when_specified(self):
        result = validate_domain("*.example.com", allow_wildcard=True)
        self.assertEqual(result, "example.com")


class IPValidationTests(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip_address("8.8.8.8"), "8.8.8.8")
    
    def test_valid_ipv6(self):
        self.assertEqual(validate_ip_address("2001:db8::1"), "2001:db8::1")
    
    def test_invalid_ip_loopback(self):
        with self.assertRaises(ValidationError):
            validate_ip_address("127.0.0.1")
        with self.assertRaises(ValidationError):
            validate_ip_address("::1")
    
    def test_invalid_ip_multicast(self):
        with self.assertRaises(ValidationError):
            validate_ip_address("224.0.0.1")
    
    def test_invalid_ip_format(self):
        with self.assertRaises(ValidationError):
            validate_ip_address("999.999.999.999")
        with self.assertRaises(ValidationError):
            validate_ip_address("not-an-ip")
    
    def test_private_ip_allowed_by_default(self):
        self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip_address("10.0.0.1"), "10.0.0.1")
    
    def test_private_ip_rejected_when_disallowed(self):
        with self.assertRaises(ValidationError):
            validate_ip_address("192.168.1.1", allow_private=False)


class URLValidationTests(unittest.TestCase):
    def test_valid_http_url(self):
        result = validate_url("http://example.com")
        self.assertTrue(result.startswith("http://"))
    
    def test_valid_https_url(self):
        result = validate_url("https://example.com")
        self.assertTrue(result.startswith("https://"))
    
    def test_url_adds_http_if_missing(self):
        result = validate_url("example.com")
        self.assertTrue(result.startswith("http://"))
    
    def test_url_with_port(self):
        result = validate_url("http://example.com:8080")
        self.assertIn(":8080", result)
    
    def test_url_with_path(self):
        result = validate_url("http://example.com/path")
        self.assertIn("/path", result)
    
    def test_invalid_url_scheme(self):
        with self.assertRaises(ValidationError):
            validate_url("ftp://example.com")
    
    def test_require_https(self):
        with self.assertRaises(ValidationError):
            validate_url("http://example.com", require_https=True)
        
        # Should pass with https
        result = validate_url("https://example.com", require_https=True)
        self.assertTrue(result.startswith("https://"))
    
    def test_invalid_port(self):
        with self.assertRaises(ValidationError):
            validate_url("http://example.com:99999")


class TargetValidationTests(unittest.TestCase):
    def test_target_url(self):
        target, ttype = validate_target("http://example.com")
        self.assertEqual(ttype, "url")
        self.assertIn("example.com", target)
    
    def test_target_domain(self):
        target, ttype = validate_target("example.com")
        self.assertEqual(ttype, "domain")
        self.assertEqual(target, "example.com")
    
    def test_target_ip(self):
        target, ttype = validate_target("8.8.8.8")
        self.assertEqual(ttype, "ip")
        self.assertEqual(target, "8.8.8.8")
    
    def test_target_rejects_dangerous_chars(self):
        dangerous = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">"]
        for char in dangerous:
            with self.assertRaises(ValidationError):
                validate_target(f"example.com{char}test")
    
    def test_target_type_restrictions(self):
        # URL not allowed
        with self.assertRaises(ValidationError):
            validate_target("http://example.com", allow_urls=False)
        
        # IP not allowed
        with self.assertRaises(ValidationError):
            validate_target("8.8.8.8", allow_ips=False)
        
        # Domain not allowed (but IP is, so use a clear domain)
        with self.assertRaises(ValidationError):
            validate_target("example.com", allow_domains=False, allow_ips=False)


class ScanOptionsValidationTests(unittest.TestCase):
    def test_valid_options(self):
        result = sanitize_scan_options("-sV -sC --top-ports 100")
        self.assertEqual(result, "-sV -sC --top-ports 100")
    
    def test_empty_options(self):
        result = sanitize_scan_options("")
        self.assertEqual(result, "")
    
    def test_options_too_long(self):
        long_opts = "x" * 300
        with self.assertRaises(ValidationError):
            sanitize_scan_options(long_opts)
    
    def test_dangerous_command_injection_patterns(self):
        dangerous = [
            "-sV; rm -rf /",
            "-sV | cat /etc/passwd",
            "-sV && echo pwned",
            "-sV > /tmp/output",
            "-sV < /etc/passwd",
            "-sV `whoami`",
            "-sV $(whoami)",
        ]
        for opts in dangerous:
            with self.assertRaises(ValidationError):
                sanitize_scan_options(opts)


if __name__ == "__main__":
    unittest.main()
