# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **DO NOT** open a public issue
2. Email security concerns to: security@claude-optimized-deployment.dev (or create a private security advisory on GitHub)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### Security Measures

This project implements several security measures:

1. **Input Validation**: All user inputs are validated
2. **Rate Limiting**: API endpoints are rate-limited
3. **Authentication**: MCP servers use token-based auth
4. **SSRF Protection**: Comprehensive Server-Side Request Forgery protection
5. **Dependency Scanning**: Regular vulnerability scans
6. **Code Analysis**: Static security analysis with Bandit
7. **Memory Safety**: Rust components for critical operations

### SSRF Protection

The system includes comprehensive SSRF (Server-Side Request Forgery) protection to prevent attacks against internal networks and cloud metadata services. See [SSRF Security Guide](docs/SSRF_SECURITY_GUIDE.md) for detailed information on:

- Protection mechanisms and architecture
- Configuration options and presets
- Usage guidelines and best practices
- Testing and validation procedures
- Troubleshooting common issues

**Key SSRF protections include:**
- Blocking access to private networks (RFC 1918)
- Preventing cloud metadata endpoint access
- Validating URL schemes and ports
- DNS rebinding attack prevention
- Pattern-based suspicious URL detection

### Security Best Practices

When using CODE:

1. **API Keys**: Store in environment variables, never commit
2. **Permissions**: Use least-privilege principle
3. **Updates**: Keep dependencies updated
4. **Monitoring**: Enable security logging
5. **Network**: Use TLS for all communications

### Recognition

We appreciate responsible disclosure and will acknowledge security researchers who:
- Follow responsible disclosure practices
- Give us reasonable time to address issues
- Don't exploit vulnerabilities beyond POC

## Security Automation

Our CI/CD pipeline includes:
- Dependency vulnerability scanning (Dependabot)
- Static code analysis (CodeQL, Bandit)
- Container scanning (Trivy)
- Secret detection (Gitleaks)

See `.github/workflows/security.yml` for details.

## Contact

For security concerns, please use one of these channels:
- GitHub Security Advisories (preferred)
- Email: security@claude-optimized-deployment.dev
- GPG Key: [Coming Soon]

Thank you for helping keep CODE secure!