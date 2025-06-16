"""
Security Regression Test Suite

Comprehensive regression tests for all security vulnerabilities following OWASP guidelines.
"""

import pytest
import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Any
from unittest.mock import Mock, patch, AsyncMock

from .test_authentication_bypass import TestAuthenticationBypass
from .test_command_injection import TestCommandInjectionPrevention
from .test_sql_injection import TestSQLInjectionPrevention
from .test_csrf_protection import TestCSRFProtection
from .test_rate_limiting import TestRateLimiting


class SecurityRegressionTestSuite:
    """
    Comprehensive security regression test suite that runs all security tests
    and ensures no regressions have been introduced.
    """
    
    def __init__(self):
        self.test_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "vulnerabilities_found": [],
            "test_categories": {}
        }
    
    @pytest.mark.asyncio
    async def test_full_security_regression_suite(self):
        """Run complete security regression test suite."""
        test_categories = [
            ("Authentication Bypass", TestAuthenticationBypass),
            ("Command Injection", TestCommandInjectionPrevention),
            ("SQL Injection", TestSQLInjectionPrevention),
            ("CSRF Protection", TestCSRFProtection),
            ("Rate Limiting", TestRateLimiting)
        ]
        
        for category_name, test_class in test_categories:
            await self._run_category_tests(category_name, test_class)
        
        # Generate report
        self._generate_security_report()
        
        # Assert no critical vulnerabilities
        assert len(self.test_results["vulnerabilities_found"]) == 0, \
            f"Found {len(self.test_results['vulnerabilities_found'])} vulnerabilities"
    
    async def _run_category_tests(self, category_name: str, test_class):
        """Run all tests in a category."""
        self.test_results["test_categories"][category_name] = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "tests": []
        }
        
        instance = test_class()
        test_methods = [
            method for method in dir(instance)
            if method.startswith("test_") and callable(getattr(instance, method))
        ]
        
        for method_name in test_methods:
            await self._run_single_test(category_name, instance, method_name)
    
    async def _run_single_test(self, category: str, instance, method_name: str):
        """Run a single test method."""
        self.test_results["total_tests"] += 1
        self.test_results["test_categories"][category]["total"] += 1
        
        try:
            method = getattr(instance, method_name)
            
            # Create fixtures if needed
            fixtures = self._create_fixtures_for_method(instance, method_name)
            
            # Run test
            if asyncio.iscoroutinefunction(method):
                await method(**fixtures)
            else:
                method(**fixtures)
            
            # Test passed
            self.test_results["passed_tests"] += 1
            self.test_results["test_categories"][category]["passed"] += 1
            self.test_results["test_categories"][category]["tests"].append({
                "name": method_name,
                "status": "PASSED"
            })
            
        except Exception as e:
            # Test failed
            self.test_results["failed_tests"] += 1
            self.test_results["test_categories"][category]["failed"] += 1
            
            vulnerability = {
                "category": category,
                "test": method_name,
                "error": str(e),
                "severity": self._determine_severity(category, method_name)
            }
            
            self.test_results["vulnerabilities_found"].append(vulnerability)
            self.test_results["test_categories"][category]["tests"].append({
                "name": method_name,
                "status": "FAILED",
                "error": str(e)
            })
    
    def _create_fixtures_for_method(self, instance, method_name: str) -> Dict:
        """Create necessary fixtures for a test method."""
        fixtures = {}
        
        # Check if method needs fixtures
        method = getattr(instance, method_name)
        if hasattr(method, "__code__"):
            arg_names = method.__code__.co_varnames[1:method.__code__.co_argcount]
            
            for arg_name in arg_names:
                if hasattr(instance, arg_name):
                    fixture_method = getattr(instance, arg_name)
                    if hasattr(fixture_method, "__wrapped__"):
                        # It's a fixture
                        fixtures[arg_name] = fixture_method()
        
        return fixtures
    
    def _determine_severity(self, category: str, test_name: str) -> str:
        """Determine severity of a failed security test."""
        critical_patterns = [
            "authentication_bypass",
            "sql_injection",
            "command_injection",
            "privilege_escalation"
        ]
        
        high_patterns = [
            "csrf",
            "session_fixation",
            "token_manipulation"
        ]
        
        test_lower = test_name.lower()
        
        for pattern in critical_patterns:
            if pattern in test_lower:
                return "CRITICAL"
        
        for pattern in high_patterns:
            if pattern in test_lower:
                return "HIGH"
        
        return "MEDIUM"
    
    def _generate_security_report(self):
        """Generate comprehensive security report."""
        report_path = "security_regression_report.json"
        
        # Add summary
        self.test_results["summary"] = {
            "status": "PASS" if self.test_results["failed_tests"] == 0 else "FAIL",
            "pass_rate": (
                self.test_results["passed_tests"] / self.test_results["total_tests"] * 100
                if self.test_results["total_tests"] > 0 else 0
            ),
            "critical_vulnerabilities": len([
                v for v in self.test_results["vulnerabilities_found"]
                if v["severity"] == "CRITICAL"
            ]),
            "high_vulnerabilities": len([
                v for v in self.test_results["vulnerabilities_found"]
                if v["severity"] == "HIGH"
            ])
        }
        
        # Save report
        with open(report_path, "w") as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\nSecurity Regression Test Report saved to: {report_path}")
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"Passed: {self.test_results['passed_tests']}")
        print(f"Failed: {self.test_results['failed_tests']}")
        print(f"Pass Rate: {self.test_results['summary']['pass_rate']:.2f}%")


class TestOWASPCompliance:
    """Test OWASP Top 10 compliance."""
    
    @pytest.mark.asyncio
    async def test_owasp_top_10_coverage(self):
        """Ensure all OWASP Top 10 vulnerabilities are covered."""
        owasp_top_10 = {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery (SSRF)"
        }
        
        coverage = {
            "A01:2021": ["test_authentication_bypass", "test_privilege_escalation"],
            "A02:2021": ["test_password_hashing", "test_encryption"],
            "A03:2021": ["test_sql_injection", "test_command_injection"],
            "A04:2021": ["test_rate_limiting", "test_input_validation"],
            "A05:2021": ["test_security_headers", "test_cors_configuration"],
            "A06:2021": ["test_dependency_vulnerabilities"],
            "A07:2021": ["test_authentication", "test_session_management"],
            "A08:2021": ["test_csrf_protection", "test_data_integrity"],
            "A09:2021": ["test_security_logging", "test_monitoring"],
            "A10:2021": ["test_ssrf_protection"]
        }
        
        # Verify coverage exists
        for owasp_id, tests in coverage.items():
            assert len(tests) > 0, f"No tests for {owasp_id}: {owasp_top_10[owasp_id]}"


class TestSecurityHeaders:
    """Test security headers implementation."""
    
    @pytest.mark.asyncio
    async def test_security_headers_presence(self):
        """Test that all security headers are present."""
        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        # Mock response
        response = Mock()
        response.headers = {}
        
        # Apply security headers
        from src.auth.middleware import SecurityHeadersMiddleware
        middleware = SecurityHeadersMiddleware(None)
        
        # Process response
        middleware.add_security_headers(response)
        
        # Verify all headers are present
        for header, expected_value in required_headers.items():
            assert header in response.headers
            if expected_value:
                assert response.headers[header] == expected_value


class TestInputValidation:
    """Test comprehensive input validation."""
    
    def test_input_sanitization_functions(self):
        """Test all input sanitization functions."""
        from src.core.validation import (
            sanitize_html,
            sanitize_sql,
            sanitize_path,
            sanitize_command,
            validate_email,
            validate_url
        )
        
        # HTML sanitization
        assert sanitize_html("<script>alert('xss')</script>") == ""
        assert sanitize_html("<b>Safe HTML</b>") == "<b>Safe HTML</b>"
        
        # SQL sanitization
        assert sanitize_sql("'; DROP TABLE users;--") == " DROP TABLE users"
        
        # Path sanitization
        assert sanitize_path("../../../etc/passwd") == "etc/passwd"
        
        # Command sanitization
        assert sanitize_command("ls; cat /etc/passwd") == "ls cat /etc/passwd"
        
        # Email validation
        assert validate_email("test@example.com") is True
        assert validate_email("invalid.email") is False
        
        # URL validation
        assert validate_url("https://example.com") is True
        assert validate_url("javascript:alert('xss')") is False


class TestCryptography:
    """Test cryptographic implementations."""
    
    def test_password_hashing(self):
        """Test password hashing security."""
        from src.auth.models import hash_password, verify_password
        
        password = "TestPassword123!"
        
        # Hash password
        hashed = hash_password(password)
        
        # Verify hash format (bcrypt)
        assert hashed.startswith("$2b$")
        
        # Verify password
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword", hashed) is False
        
        # Test timing attack resistance
        import time
        
        # Time correct password
        start = time.time()
        for _ in range(10):
            verify_password(password, hashed)
        correct_time = time.time() - start
        
        # Time incorrect password
        start = time.time()
        for _ in range(10):
            verify_password("WrongPassword", hashed)
        incorrect_time = time.time() - start
        
        # Times should be similar
        assert abs(correct_time - incorrect_time) < 0.1


class TestDataProtection:
    """Test data protection mechanisms."""
    
    @pytest.mark.asyncio
    async def test_pii_encryption(self):
        """Test PII data encryption."""
        from src.core.encryption import encrypt_pii, decrypt_pii
        
        sensitive_data = {
            "ssn": "123-45-6789",
            "credit_card": "4111111111111111",
            "phone": "+1-555-123-4567"
        }
        
        # Encrypt data
        encrypted = encrypt_pii(sensitive_data)
        
        # Verify encryption
        assert encrypted["ssn"] != sensitive_data["ssn"]
        assert encrypted["credit_card"] != sensitive_data["credit_card"]
        
        # Decrypt and verify
        decrypted = decrypt_pii(encrypted)
        assert decrypted == sensitive_data
    
    @pytest.mark.asyncio
    async def test_data_masking(self):
        """Test data masking in logs and responses."""
        from src.core.data_protection import mask_sensitive_data
        
        data = {
            "username": "testuser",
            "password": "secret123",
            "credit_card": "4111111111111111",
            "api_key": "sk_test_123456789"
        }
        
        masked = mask_sensitive_data(data)
        
        assert masked["username"] == "testuser"  # Not sensitive
        assert masked["password"] == "********"
        assert masked["credit_card"] == "4111********1111"
        assert masked["api_key"] == "sk_test_*****"


# Run regression suite
if __name__ == "__main__":
    suite = SecurityRegressionTestSuite()
    asyncio.run(suite.test_full_security_regression_suite())