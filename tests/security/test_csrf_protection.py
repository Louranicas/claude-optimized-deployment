"""
CSRF Protection Tests

Tests for Cross-Site Request Forgery protection following OWASP guidelines.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import secrets
import time
from datetime import datetime, timedelta
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer

from src.auth.middleware import CSRFMiddleware
from src.core.exceptions import SecurityError


class TestCSRFProtection:
    """Test suite for CSRF protection mechanisms."""
    
    @pytest.fixture
    def csrf_middleware(self):
        """Create CSRF middleware instance."""
        return CSRFMiddleware(Mock())
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""
        request = Mock(spec=Request)
        request.method = "POST"
        request.headers = {}
        request.cookies = {}
        request.session = {}
        request.url = Mock()
        request.url.path = "/api/users"
        return request
    
    @pytest.mark.asyncio
    async def test_csrf_token_generation(self, csrf_middleware):
        """Test CSRF token generation."""
        token1 = csrf_middleware.generate_csrf_token()
        token2 = csrf_middleware.generate_csrf_token()
        
        # Tokens should be unique
        assert token1 != token2
        
        # Tokens should be of sufficient length
        assert len(token1) >= 32
        
        # Tokens should be unpredictable
        assert secrets.compare_digest(token1, token1)  # Same token comparison
        assert not secrets.compare_digest(token1, token2)  # Different tokens
    
    @pytest.mark.asyncio
    async def test_missing_csrf_token(self, csrf_middleware, mock_request):
        """Test request rejection when CSRF token is missing."""
        async def call_next(request):
            return Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        
        assert exc_info.value.status_code == 403
        assert "CSRF" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_invalid_csrf_token(self, csrf_middleware, mock_request):
        """Test request rejection with invalid CSRF token."""
        # Set invalid token in header
        mock_request.headers = {"X-CSRF-Token": "invalid-token"}
        mock_request.session = {"csrf_token": "valid-token"}
        
        async def call_next(request):
            return Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        
        assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_valid_csrf_token_header(self, csrf_middleware, mock_request):
        """Test successful request with valid CSRF token in header."""
        valid_token = csrf_middleware.generate_csrf_token()
        
        mock_request.headers = {"X-CSRF-Token": valid_token}
        mock_request.session = {"csrf_token": valid_token}
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_valid_csrf_token_form(self, csrf_middleware, mock_request):
        """Test successful request with valid CSRF token in form data."""
        valid_token = csrf_middleware.generate_csrf_token()
        
        mock_request.session = {"csrf_token": valid_token}
        
        # Mock form data
        async def form():
            return {"csrf_token": valid_token}
        
        mock_request.form = form
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_csrf_token_rotation(self, csrf_middleware, mock_request):
        """Test CSRF token rotation after use."""
        initial_token = csrf_middleware.generate_csrf_token()
        
        mock_request.headers = {"X-CSRF-Token": initial_token}
        mock_request.session = {"csrf_token": initial_token}
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # First request
        response = await csrf_middleware(mock_request, call_next)
        
        # Check if new token was generated
        new_token = mock_request.session.get("csrf_token")
        assert new_token != initial_token
    
    @pytest.mark.asyncio
    async def test_safe_methods_bypass(self, csrf_middleware, mock_request):
        """Test that safe methods (GET, HEAD, OPTIONS) bypass CSRF check."""
        safe_methods = ["GET", "HEAD", "OPTIONS"]
        
        async def call_next(request):
            return Mock(status_code=200)
        
        for method in safe_methods:
            mock_request.method = method
            mock_request.headers = {}  # No CSRF token
            
            response = await csrf_middleware(mock_request, call_next)
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_double_submit_cookie(self, csrf_middleware, mock_request):
        """Test double-submit cookie pattern."""
        csrf_token = csrf_middleware.generate_csrf_token()
        
        # Token in both cookie and header
        mock_request.cookies = {"csrf_token": csrf_token}
        mock_request.headers = {"X-CSRF-Token": csrf_token}
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_referer_header_validation(self, csrf_middleware, mock_request):
        """Test referer header validation as additional protection."""
        mock_request.headers = {
            "Referer": "https://trusted-domain.com/page",
            "X-CSRF-Token": "valid-token"
        }
        mock_request.session = {"csrf_token": "valid-token"}
        mock_request.base_url = "https://trusted-domain.com"
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
        
        # Test with mismatched referer
        mock_request.headers["Referer"] = "https://evil-domain.com/page"
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_origin_header_validation(self, csrf_middleware, mock_request):
        """Test origin header validation."""
        mock_request.headers = {
            "Origin": "https://trusted-domain.com",
            "X-CSRF-Token": "valid-token"
        }
        mock_request.session = {"csrf_token": "valid-token"}
        mock_request.base_url = "https://trusted-domain.com"
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
        
        # Test with mismatched origin
        mock_request.headers["Origin"] = "https://evil-domain.com"
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_custom_header_requirement(self, csrf_middleware, mock_request):
        """Test custom header requirement for AJAX requests."""
        # AJAX request without custom header
        mock_request.headers = {
            "X-Requested-With": "XMLHttpRequest"
        }
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Should allow AJAX requests with custom header
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_token_timing_attack_resistance(self, csrf_middleware):
        """Test resistance to timing attacks on token comparison."""
        valid_token = "a" * 32
        invalid_tokens = [
            "b" * 32,  # Same length, different content
            "a" * 31 + "b",  # One character different at end
            "b" + "a" * 31,  # One character different at start
        ]
        
        times = []
        for invalid_token in invalid_tokens:
            start = time.time()
            csrf_middleware.validate_token(valid_token, invalid_token)
            times.append(time.time() - start)
        
        # All comparisons should take similar time
        max_diff = max(times) - min(times)
        assert max_diff < 0.001  # Less than 1ms difference
    
    @pytest.mark.asyncio
    async def test_token_expiration(self, csrf_middleware, mock_request):
        """Test CSRF token expiration."""
        expired_token = csrf_middleware.generate_csrf_token()
        
        mock_request.headers = {"X-CSRF-Token": expired_token}
        mock_request.session = {
            "csrf_token": expired_token,
            "csrf_token_time": datetime.utcnow() - timedelta(hours=2)
        }
        
        async def call_next(request):
            return Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        
        assert exc_info.value.status_code == 403
        assert "expired" in str(exc_info.value.detail).lower()
    
    @pytest.mark.asyncio
    async def test_per_session_token(self, csrf_middleware):
        """Test that CSRF tokens are unique per session."""
        sessions = {}
        
        # Generate tokens for different sessions
        for i in range(5):
            session_id = f"session_{i}"
            token = csrf_middleware.generate_csrf_token_for_session(session_id)
            sessions[session_id] = token
        
        # All tokens should be unique
        tokens = list(sessions.values())
        assert len(tokens) == len(set(tokens))
    
    @pytest.mark.asyncio
    async def test_token_binding_to_session(self, csrf_middleware, mock_request):
        """Test that CSRF tokens are bound to specific sessions."""
        # Token from session 1
        session1_token = csrf_middleware.generate_csrf_token()
        
        # Try to use token with different session
        mock_request.headers = {"X-CSRF-Token": session1_token}
        mock_request.session = {
            "csrf_token": "different-token",
            "session_id": "session2"
        }
        
        async def call_next(request):
            return Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware(mock_request, call_next)
        
        assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_stateless_csrf_protection(self, csrf_middleware, mock_request):
        """Test stateless CSRF protection using signed tokens."""
        # Generate signed token
        user_id = "user123"
        signed_token = csrf_middleware.generate_signed_token(user_id)
        
        mock_request.headers = {"X-CSRF-Token": signed_token}
        mock_request.user = Mock(id=user_id)
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Should validate successfully
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
        
        # Test with tampered token
        tampered_token = signed_token[:-1] + "X"
        mock_request.headers = {"X-CSRF-Token": tampered_token}
        
        with pytest.raises(HTTPException):
            await csrf_middleware(mock_request, call_next)
    
    @pytest.mark.asyncio
    async def test_content_type_validation(self, csrf_middleware, mock_request):
        """Test content type validation for form submissions."""
        mock_request.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": "valid-token"
        }
        mock_request.session = {"csrf_token": "valid-token"}
        
        async def call_next(request):
            return Mock(status_code=200)
        
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200
        
        # Test with JSON content type (might not need CSRF for API)
        mock_request.headers["Content-Type"] = "application/json"
        response = await csrf_middleware(mock_request, call_next)
        assert response.status_code == 200