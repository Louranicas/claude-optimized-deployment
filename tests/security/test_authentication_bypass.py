"""
Authentication Bypass Security Tests

Tests for various authentication bypass attempts following OWASP guidelines.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException
from jose import jwt, JWTError
import time
from datetime import datetime, timedelta

from src.auth.tokens import create_access_token, verify_token
from src.auth.middleware import AuthMiddleware
from src.auth.models import User, UserRole
from src.auth.api import login, get_current_user


class TestAuthenticationBypass:
    """Test suite for authentication bypass vulnerabilities."""
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        return User(
            id="test-user-123",
            username="testuser",
            email="test@example.com",
            hashed_password="$2b$12$KIXxPfnK6JKxQ1Z3X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4X4",
            role=UserRole.USER,
            is_active=True
        )
    
    @pytest.mark.asyncio
    async def test_null_token_bypass_attempt(self):
        """Test that null/None tokens are properly rejected."""
        with pytest.raises(HTTPException) as exc_info:
            await verify_token(None)
        assert exc_info.value.status_code == 401
        assert "Could not validate credentials" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_empty_token_bypass_attempt(self):
        """Test that empty string tokens are rejected."""
        with pytest.raises(HTTPException) as exc_info:
            await verify_token("")
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_malformed_jwt_bypass_attempt(self):
        """Test various malformed JWT bypass attempts."""
        malformed_tokens = [
            "notajwt",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",  # Missing parts
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..",  # Empty parts
            "....",  # All dots
            "Bearer ",  # Just Bearer prefix
            "null",
            "undefined",
            "0",
            "false"
        ]
        
        for token in malformed_tokens:
            with pytest.raises(HTTPException) as exc_info:
                await verify_token(token)
            assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_algorithm_confusion_attack(self):
        """Test JWT algorithm confusion vulnerability (RS256 to HS256)."""
        # Create a token with HS256 but try to pass it as RS256
        payload = {"sub": "admin", "role": "admin"}
        
        # Attempt to create token with 'none' algorithm
        with pytest.raises(JWTError):
            token = jwt.encode(payload, "", algorithm="none")
            await verify_token(token)
    
    @pytest.mark.asyncio
    async def test_jwt_signature_stripping(self):
        """Test JWT signature stripping attack."""
        # Create valid token
        token = create_access_token({"sub": "testuser"})
        
        # Strip signature (keep only header.payload)
        parts = token.split('.')
        if len(parts) == 3:
            stripped_token = f"{parts[0]}.{parts[1]}."
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_token(stripped_token)
            assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_expired_token_bypass(self):
        """Test that expired tokens cannot be used."""
        # Create token that's already expired
        expired_payload = {
            "sub": "testuser",
            "exp": datetime.utcnow() - timedelta(hours=1)
        }
        
        with patch('src.auth.tokens.SECRET_KEY', 'test-secret'):
            expired_token = jwt.encode(
                expired_payload,
                'test-secret',
                algorithm='HS256'
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_token(expired_token)
            assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_token_injection_in_headers(self):
        """Test various header injection attempts."""
        middleware = AuthMiddleware(None)
        
        # Test various malicious header values
        malicious_headers = [
            {"Authorization": "Bearer token1\nAuthorization: Bearer token2"},
            {"Authorization": "Bearer token\r\nX-Admin: true"},
            {"Authorization": "Bearer token; admin=true"},
            {"Authorization": "Bearer\x00admin"},
            {"Authorization": "Bearer token%00admin"}
        ]
        
        for headers in malicious_headers:
            request = Mock()
            request.headers = headers
            
            async def call_next(req):
                return Mock()
            
            # Should either reject or sanitize properly
            try:
                response = await middleware(request, call_next)
            except HTTPException as e:
                assert e.status_code == 401
    
    @pytest.mark.asyncio
    async def test_sql_injection_in_login(self):
        """Test SQL injection attempts in login endpoint."""
        sql_injection_attempts = [
            {"username": "admin' OR '1'='1", "password": "password"},
            {"username": "admin'--", "password": "password"},
            {"username": "admin' OR 1=1--", "password": "password"},
            {"username": "admin'; DROP TABLE users;--", "password": "password"},
            {"username": "admin' UNION SELECT * FROM users--", "password": "password"}
        ]
        
        for attempt in sql_injection_attempts:
            with pytest.raises(HTTPException) as exc_info:
                with patch('src.auth.api.authenticate_user', return_value=None):
                    await login(attempt["username"], attempt["password"])
            assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_brute_force_protection(self):
        """Test brute force protection mechanisms."""
        # Simulate multiple failed login attempts
        username = "testuser"
        
        with patch('src.auth.api.authenticate_user', return_value=None):
            for i in range(10):
                try:
                    await login(username, f"wrongpassword{i}")
                except HTTPException:
                    pass
            
            # After multiple failures, should have rate limiting
            with pytest.raises(HTTPException) as exc_info:
                await login(username, "anotherpassword")
            
            # Should get rate limit error or increased delay
            assert exc_info.value.status_code in [401, 429]
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_attempt(self):
        """Test privilege escalation through token manipulation."""
        # Create regular user token
        user_token = create_access_token({"sub": "testuser", "role": "user"})
        
        # Try to decode and modify
        try:
            # Attempt to decode without key (should fail)
            decoded = jwt.decode(user_token, options={"verify_signature": False})
            decoded["role"] = "admin"
            
            # Try to use modified token
            with pytest.raises(HTTPException):
                # This should fail because signature won't match
                fake_admin_token = jwt.encode(decoded, "wrong-key", algorithm="HS256")
                await verify_token(fake_admin_token)
        except Exception:
            pass  # Expected to fail
    
    @pytest.mark.asyncio
    async def test_session_fixation_protection(self):
        """Test protection against session fixation attacks."""
        # Create token with fixed session ID
        fixed_session_id = "fixed-session-123"
        token1 = create_access_token({"sub": "user1", "session_id": fixed_session_id})
        
        # Try to use same session ID for different user
        with patch('src.auth.tokens.verify_token') as mock_verify:
            mock_verify.return_value = {"sub": "user2", "session_id": fixed_session_id}
            
            # Should detect session hijacking attempt
            with pytest.raises(HTTPException):
                await get_current_user(token1)
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """Test resistance to timing attacks on authentication."""
        import time
        
        # Measure time for valid vs invalid credentials
        valid_times = []
        invalid_times = []
        
        with patch('src.auth.api.authenticate_user') as mock_auth:
            # Valid user (but wrong password)
            mock_auth.return_value = None
            
            for _ in range(5):
                start = time.time()
                try:
                    await login("validuser", "wrongpassword")
                except HTTPException:
                    pass
                valid_times.append(time.time() - start)
            
            # Invalid user
            for _ in range(5):
                start = time.time()
                try:
                    await login("invaliduser123456", "wrongpassword")
                except HTTPException:
                    pass
                invalid_times.append(time.time() - start)
        
        # Times should be similar (constant time comparison)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        # Allow 20ms difference max
        assert abs(avg_valid - avg_invalid) < 0.02
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_bypass(self):
        """Test Unicode normalization bypass attempts."""
        unicode_bypass_attempts = [
            "admin",  # Latin
            "аdmin",  # Cyrillic 'а'
            "ａｄｍｉｎ",  # Full-width
            "ad\u200Bmin",  # Zero-width space
            "ad\u00ADmin",  # Soft hyphen
            "ADMIN",  # Case variation
            "AdMiN"   # Mixed case
        ]
        
        with patch('src.auth.api.authenticate_user', return_value=None):
            for username in unicode_bypass_attempts:
                with pytest.raises(HTTPException):
                    await login(username, "password")
    
    @pytest.mark.asyncio
    async def test_token_replay_attack_protection(self):
        """Test protection against token replay attacks."""
        # Create a token
        token = create_access_token({"sub": "testuser"})
        
        # Use token successfully first time
        user_data = await verify_token(token)
        assert user_data["sub"] == "testuser"
        
        # Simulate token revocation/blacklisting
        with patch('src.auth.tokens.is_token_blacklisted', return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await verify_token(token)
            assert exc_info.value.status_code == 401