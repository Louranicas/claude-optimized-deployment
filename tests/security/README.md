# Security Test Suite

Comprehensive security testing framework following OWASP guidelines for the Claude Optimized Deployment project.

## Overview

This security test suite provides thorough testing for common web application vulnerabilities, ensuring the application is protected against the OWASP Top 10 security risks.

## Test Categories

### 1. Authentication Bypass Tests (`test_authentication_bypass.py`)
- Null/empty token validation
- Malformed JWT attacks
- Algorithm confusion attacks
- Token signature stripping
- Expired token handling
- Header injection attempts
- SQL injection in login
- Brute force protection
- Privilege escalation attempts
- Session fixation protection
- Timing attack resistance
- Unicode normalization bypass
- Token replay attack protection

### 2. Command Injection Prevention (`test_command_injection.py`)
- Shell command injection
- Path traversal attempts
- Docker command injection
- Git command injection
- Environment variable injection
- Argument injection
- Null byte injection
- Unicode encoding bypass
- Command substitution prevention
- Whitelist command validation
- Chroot jail simulation
- Command length limits
- Recursive command prevention

### 3. SQL Injection Prevention (`test_sql_injection.py`)
- Classic SQL injection
- Blind SQL injection
- Second-order injection
- Numeric field injection
- LIKE operator injection
- ORDER BY injection
- INSERT statement injection
- UPDATE statement injection
- Stored procedure injection
- Column name injection
- Multi-query injection
- Hex encoding bypass
- Comment syntax injection
- Unicode bypass attempts

### 4. CSRF Protection (`test_csrf_protection.py`)
- Token generation and validation
- Missing token rejection
- Invalid token handling
- Header and form token validation
- Token rotation
- Safe method bypass
- Double-submit cookie pattern
- Referer header validation
- Origin header validation
- Custom header requirements
- Timing attack resistance
- Token expiration
- Per-session tokens
- Token binding
- Stateless CSRF protection

### 5. Rate Limiting (`test_rate_limiting.py`)
- Basic rate limiting
- Burst protection
- Per-IP limiting
- Endpoint-specific limits
- Authenticated user limits
- Distributed rate limiting
- Sliding window algorithm
- Token bucket algorithm
- Retry-After headers
- Rate limit headers
- IP whitelisting
- DDoS protection
- Gradual backoff
- API key-based limits
- Cost-based limiting
- Geographic limiting

### 6. Security Regression Tests (`test_security_regression.py`)
- Full regression suite
- OWASP Top 10 compliance
- Security headers validation
- Input validation testing
- Cryptography testing
- Data protection mechanisms

## Running the Tests

### Run All Security Tests
```bash
python run_security_tests.py
```

### Run Specific Category
```bash
pytest tests/security/test_authentication_bypass.py -v
pytest tests/security/test_command_injection.py -v
pytest tests/security/test_sql_injection.py -v
pytest tests/security/test_csrf_protection.py -v
pytest tests/security/test_rate_limiting.py -v
```

### Run with Coverage
```bash
pytest tests/security/ --cov=src --cov-report=html
```

### Run Regression Suite Only
```bash
pytest tests/security/test_security_regression.py -v
```

## Test Configuration

The test suite uses `conftest.py` for shared fixtures and configuration:

- **test_db**: In-memory SQLite database for testing
- **mock_redis**: Mocked Redis client for rate limiting
- **security_config**: Security configuration parameters
- **mock_user/mock_admin_user**: Test user fixtures
- **auth_headers**: Pre-configured authentication headers

## Security Test Reports

After running the test suite, reports are generated in the `security_reports/` directory:

- **JSON Report**: Detailed test results in machine-readable format
- **HTML Report**: Visual report for easy review
- **Vulnerability Summary**: List of detected vulnerabilities with severity ratings

## OWASP Compliance

The test suite covers all OWASP Top 10 (2021) categories:

| OWASP Category | Coverage |
|----------------|----------|
| A01: Broken Access Control | ✅ Authentication bypass, privilege escalation |
| A02: Cryptographic Failures | ✅ Password hashing, encryption tests |
| A03: Injection | ✅ SQL, command, and other injection tests |
| A04: Insecure Design | ✅ Rate limiting, input validation |
| A05: Security Misconfiguration | ✅ Security headers, CORS |
| A06: Vulnerable Components | ✅ Dependency scanning |
| A07: Authentication Failures | ✅ Authentication, session management |
| A08: Data Integrity Failures | ✅ CSRF protection, data validation |
| A09: Security Logging | ✅ Logging and monitoring tests |
| A10: SSRF | ✅ SSRF protection tests |

## Best Practices

1. **Run Before Deployment**: Always run the full security test suite before deploying to production
2. **Regular Testing**: Schedule regular security test runs (e.g., nightly builds)
3. **Fix Critical Issues**: Address all CRITICAL and HIGH severity findings immediately
4. **Update Tests**: Keep tests updated as new vulnerabilities are discovered
5. **Monitor Results**: Track security test metrics over time

## Integration with CI/CD

Add to your CI/CD pipeline:

```yaml
# GitHub Actions example
- name: Run Security Tests
  run: |
    python run_security_tests.py
    if [ $? -ne 0 ]; then
      echo "Security tests failed!"
      exit 1
    fi
```

## Contributing

When adding new security tests:

1. Follow the existing test structure
2. Use appropriate fixtures from `conftest.py`
3. Add tests to the regression suite
4. Document new test cases
5. Ensure tests are deterministic and reliable

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)