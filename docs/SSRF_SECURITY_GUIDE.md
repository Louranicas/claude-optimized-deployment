# SSRF Protection Security Guide

## Overview

Server-Side Request Forgery (SSRF) is a critical web security vulnerability that allows attackers to induce server-side applications to make HTTP requests to arbitrary domains chosen by the attacker. This guide documents the comprehensive SSRF protection implementation in the Claude Optimized Deployment system.

## Table of Contents

1. [SSRF Threat Overview](#ssrf-threat-overview)
2. [Protection Implementation](#protection-implementation)
3. [Configuration Options](#configuration-options)
4. [Usage Guidelines](#usage-guidelines)
5. [Testing and Validation](#testing-and-validation)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)

## SSRF Threat Overview

### What is SSRF?

SSRF vulnerabilities occur when a web application makes requests to URLs provided by users without proper validation. Attackers can exploit this to:

- Access internal network resources (private IPs, localhost)
- Read cloud metadata services (AWS, GCP, Azure)
- Port scan internal networks
- Bypass firewalls and access controls
- Exfiltrate sensitive data from internal services

### Common Attack Vectors

1. **Internal Network Access**: `http://192.168.1.1/admin`
2. **Localhost Bypass**: `http://127.0.0.1:22/`
3. **Cloud Metadata**: `http://169.254.169.254/latest/meta-data/`
4. **Port Scanning**: `http://internal.service:3306/`
5. **DNS Rebinding**: `http://attacker.com` → resolves to `127.0.0.1`
6. **IP Encoding**: `http://2130706433/` (decimal for 127.0.0.1)

## Protection Implementation

### Core Components

The SSRF protection system consists of three main components:

1. **SSRFProtector**: Core validation engine
2. **SSRFProtectedSession**: HTTP client wrapper
3. **Global Functions**: Convenience utilities

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───→│   SSRF Protector │───→│  HTTP Request   │
│     Code        │    │   Validation     │    │   (if safe)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Blocked/Logged │
                       │   (if dangerous) │
                       └──────────────────┘
```

### Protected Areas

The system applies SSRF protection to:

- **Circle of Experts**: AI API calls to external providers
- **Monitoring System**: Prometheus queries and alerts
- **Communication Hub**: Slack, Teams, webhook notifications
- **MCP Servers**: All external HTTP requests

## Configuration Options

### Configuration Presets

Three predefined configurations are available:

#### Strict Configuration (Production)
```python
STRICT_SSRF_CONFIG = {
    'allow_private_networks': False,
    'allow_metadata_endpoints': False,
    'max_redirects': 0,
    'dns_timeout': 5.0
}
```

#### Moderate Configuration (Staging)
```python
MODERATE_SSRF_CONFIG = {
    'allow_private_networks': False,
    'allow_metadata_endpoints': False,
    'max_redirects': 2,
    'dns_timeout': 10.0
}
```

#### Development Configuration (Local)
```python
DEVELOPMENT_SSRF_CONFIG = {
    'allow_private_networks': True,
    'allow_metadata_endpoints': False,
    'max_redirects': 3,
    'dns_timeout': 15.0
}
```

### Custom Configuration

```python
from src.core.ssrf_protection import SSRFProtector

protector = SSRFProtector(
    allow_private_networks=False,
    allow_metadata_endpoints=False,
    custom_blocked_networks=["203.0.113.0/24"],
    custom_allowed_domains=["api.trusted-partner.com"],
    max_redirects=1,
    dns_timeout=8.0
)
```

### Blocked Networks

The system automatically blocks access to:

#### IPv4 Networks
- **RFC 1918 Private**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Loopback**: 127.0.0.0/8
- **Link-Local**: 169.254.0.0/16
- **Multicast**: 224.0.0.0/4
- **Reserved**: 240.0.0.0/4
- **Carrier-Grade NAT**: 100.64.0.0/10
- **Test Networks**: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24

#### IPv6 Networks
- **Loopback**: ::1/128
- **Link-Local**: fe80::/10
- **Unique Local**: fc00::/7
- **Multicast**: ff00::/8
- **Documentation**: 2001:db8::/32

#### Cloud Metadata Endpoints
- **AWS**: 169.254.169.254, 169.254.170.2
- **GCP**: 169.254.169.254, metadata.google.internal
- **Azure**: 169.254.169.254
- **Alibaba**: 100.100.100.200

#### Dangerous Ports
- SSH (22), Telnet (23), SMTP (25), DNS (53)
- POP3 (110), IMAP (143), HTTPS (993), POP3S (995)
- SQL Server (1433), MySQL (3306), PostgreSQL (5432)
- Redis (6379), Elasticsearch (9200), Memcached (11211)
- MongoDB (27017)

## Usage Guidelines

### Basic Usage

```python
from src.core.ssrf_protection import is_url_safe, validate_url_safe

# Simple safety check
if is_url_safe("https://api.example.com/data"):
    # Proceed with request
    pass

# Detailed validation
result = validate_url_safe("https://suspicious.site.com/")
if not result.is_safe:
    logger.warning(f"Blocked URL: {result.reason}")
```

### Protected HTTP Requests

```python
from src.core.ssrf_protection import SSRFProtectedSession

async def make_api_call():
    async with SSRFProtectedSession() as session:
        # This will be validated before making the request
        response = await session.get("https://api.external-service.com/data")
        return await response.json()
```

### Integration in Expert Clients

```python
class CustomExpertClient(BaseExpertClient):
    async def __aenter__(self):
        """Initialize with SSRF protection."""
        self._ssrf_session = SSRFProtectedSession(self._ssrf_protector)
        await self._ssrf_session.__aenter__()
        self._session = self._ssrf_session.session
        return self
    
    async def _make_api_call(self, url: str, **kwargs):
        """Make HTTP request with SSRF protection."""
        return await self._ssrf_session._validate_and_request("POST", url, **kwargs)
```

### Custom Validation

```python
from src.core.ssrf_protection import SSRFProtector, STRICT_SSRF_CONFIG

# Create custom protector
protector = SSRFProtector(
    **STRICT_SSRF_CONFIG,
    custom_allowed_domains=["api.trusted-service.com"],
    custom_blocked_networks=["198.51.100.0/24"]
)

# Use for validation
result = protector.validate_url("https://api.trusted-service.com/endpoint")
```

## Testing and Validation

### Unit Tests

Run the comprehensive test suite:

```bash
pytest tests/unit/test_ssrf_protection.py -v
```

### Manual Testing

Test various attack vectors:

```python
from src.core.ssrf_protection import SSRFProtector

protector = SSRFProtector()

# These should be blocked
test_urls = [
    "http://127.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22/",
    "ftp://internal.server/",
]

for url in test_urls:
    result = protector.validate_url(url)
    assert not result.is_safe, f"Should block: {url}"
```

### Security Scanning

Use security tools to validate protection:

```bash
# Test with curl
curl -v "http://localhost:8000/api/fetch?url=http://127.0.0.1:22"

# Test with Python
python -c "
import requests
resp = requests.post('http://localhost:8000/api/expert', 
    json={'url': 'http://169.254.169.254/latest/meta-data/'})
print(resp.status_code)
"
```

## Security Best Practices

### 1. Use Appropriate Configuration

- **Production**: Always use `STRICT_SSRF_CONFIG`
- **Staging**: Use `MODERATE_SSRF_CONFIG` for testing
- **Development**: Only use `DEVELOPMENT_SSRF_CONFIG` locally

### 2. Validate All External URLs

```python
# ✅ Good: Always validate
if is_url_safe(user_provided_url):
    response = await make_request(user_provided_url)

# ❌ Bad: Direct usage
response = await make_request(user_provided_url)
```

### 3. Log Blocked Attempts

```python
result = validate_url_safe(url)
if not result.is_safe:
    logger.warning(
        "SSRF attempt blocked",
        extra={
            "url": url,
            "reason": result.reason,
            "threat_level": result.threat_level.value,
            "client_ip": request.remote_addr
        }
    )
```

### 4. Use Allow Lists for Trusted Domains

```python
protector = SSRFProtector(
    custom_allowed_domains=[
        "api.openai.com",
        "api.anthropic.com",
        "api.slack.com",
        "hooks.slack.com"
    ]
)
```

### 5. Monitor and Alert

Set up monitoring for SSRF attempts:

```python
# In your logging configuration
if result.threat_level == SSRFThreatLevel.BLOCKED:
    # Send security alert
    send_security_alert(
        f"SSRF attack blocked: {result.reason}",
        severity="HIGH",
        url=result.original_url,
        client_info=get_client_info()
    )
```

### 6. Regular Security Reviews

- Review allowed domains quarterly
- Audit configuration changes
- Test new bypass techniques
- Update threat intelligence

## Troubleshooting

### Common Issues

#### 1. Legitimate External API Blocked

**Problem**: Valid external API calls are being blocked.

**Solution**: Add the domain to allowed list:
```python
protector = SSRFProtector(
    custom_allowed_domains=["api.legitimate-service.com"]
)
```

#### 2. Development Environment Issues

**Problem**: Cannot access local services during development.

**Solution**: Use development configuration:
```python
protector = SSRFProtector(**DEVELOPMENT_SSRF_CONFIG)
```

#### 3. DNS Resolution Timeouts

**Problem**: Requests timing out during DNS resolution.

**Solution**: Increase DNS timeout:
```python
protector = SSRFProtector(dns_timeout=15.0)
```

#### 4. False Positives on Safe URLs

**Problem**: Safe URLs being flagged as suspicious.

**Solution**: Review validation logs and adjust patterns:
```python
# Check validation details
result = protector.validate_url(url)
print(f"Reason: {result.reason}")
print(f"Category: {result.blocked_category}")
print(f"Resolved IP: {result.resolved_ip}")
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```python
import logging
logging.getLogger('src.core.ssrf_protection').setLevel(logging.DEBUG)

# Detailed validation logging will be shown
result = protector.validate_url("https://example.com/")
```

### Testing Bypass Attempts

To ensure protection is working, test these bypass techniques:

```python
bypass_urls = [
    "http://127.0.0.1.nip.io/",        # DNS wildcard
    "http://2130706433/",              # Decimal IP
    "http://0x7f000001/",              # Hex IP
    "http://127.1/",                   # Short form
    "http://user@127.0.0.1/",          # URL auth
    "http://[::ffff:127.0.0.1]/",      # IPv4-mapped IPv6
]

for url in bypass_urls:
    result = protector.validate_url(url)
    assert not result.is_safe, f"Bypass should be blocked: {url}"
```

## Integration Checklist

When integrating SSRF protection into new components:

- [ ] Import appropriate configuration preset
- [ ] Use `SSRFProtectedSession` for HTTP requests
- [ ] Validate URLs before making requests
- [ ] Log blocked attempts with context
- [ ] Add appropriate allowed domains
- [ ] Write unit tests for SSRF scenarios
- [ ] Test with bypass techniques
- [ ] Document any custom configurations
- [ ] Review with security team

## Security Contacts

For security issues related to SSRF protection:

- **Security Team**: security@your-organization.com
- **Code Owners**: See CODEOWNERS file
- **Incident Response**: Follow security incident procedures

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Guide](https://portswigger.net/web-security/ssrf)
- [RFC 1918 - Private Address Space](https://tools.ietf.org/html/rfc1918)
- [RFC 3927 - Dynamic Configuration of IPv4 Link-Local Addresses](https://tools.ietf.org/html/rfc3927)
- [Cloud Metadata Security Best Practices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)