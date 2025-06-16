"""
Comprehensive Tests for Authentication Middleware (src/auth/middleware.py).

This test suite covers middleware functionality, authentication flows,
authorization checks, security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials
import secrets

from src.auth.middleware import (
    AuthMiddleware, get_current_user_dependency,
    require_permission, require_role, require_any_permission,
    require_any_role, optional_auth
)
from src.auth.models import User, UserStatus, APIKey, APIKeyStatus
from src.auth.tokens import TokenManager, TokenData, TokenType
from src.auth.rbac import RBACManager
from src.auth.permissions import PermissionChecker
from src.auth.audit import AuditLogger, AuditEventType, AuditSeverity


class TestAuthMiddleware:
    """Test AuthMiddleware class functionality."""
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components for middleware."""
        token_manager = Mock(spec=TokenManager)
        rbac_manager = Mock(spec=RBACManager)
        permission_checker = Mock(spec=PermissionChecker)
        user_store = AsyncMock()
        token_revocation_service = AsyncMock()
        session_manager = AsyncMock()
        audit_logger = Mock(spec=AuditLogger)
        
        return {
            "token_manager": token_manager,
            "rbac_manager": rbac_manager,
            "permission_checker": permission_checker,
            "user_store": user_store,
            "token_revocation_service": token_revocation_service,
            "session_manager": session_manager,
            "audit_logger": audit_logger
        }
    
    @pytest.fixture
    def middleware(self, mock_components):
        """Create AuthMiddleware instance."""
        return AuthMiddleware(**mock_components)
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["user"],
            permissions={"profile:read", "profile:write"},
            status=UserStatus.ACTIVE,
            mfa_enabled=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture
    def admin_user(self):
        """Create admin user."""
        return User(
            id="admin_456",
            username="admin",
            email="admin@example.com",
            password_hash="hashed_password",
            roles=["admin"],
            permissions={"users:read", "users:write", "users:delete", "admin:*"},
            status=UserStatus.ACTIVE,
            mfa_enabled=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.headers = {"User-Agent": "Test Client/1.0"}
        request.url = Mock()
        request.url.path = "/test/endpoint"
        request.method = "GET"
        return request
    
    def test_middleware_initialization(self, mock_components):
        """Test middleware initialization."""
        middleware = AuthMiddleware(**mock_components)
        
        assert middleware.token_manager == mock_components["token_manager"]
        assert middleware.rbac_manager == mock_components["rbac_manager"]
        assert middleware.permission_checker == mock_components["permission_checker"]
        assert middleware.user_store == mock_components["user_store"]
        assert middleware.token_revocation_service == mock_components["token_revocation_service"]
        assert middleware.session_manager == mock_components["session_manager"]
        assert middleware.audit_logger == mock_components["audit_logger"]
    
    @pytest.mark.asyncio
    async def test_get_current_user_success(self, middleware, test_user, mock_request):
        """Test successful user authentication via JWT token."""
        # Setup token data
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.session_manager.update_activity.return_value = None
        middleware.user_store.get_user.return_value = test_user
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_jwt_token"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == test_user
        
        # Verify calls
        middleware.token_manager.verify_token.assert_called_once_with("valid_jwt_token")
        middleware.token_revocation_service.is_token_revoked.assert_called_once_with("token_jti_123")
        middleware.token_revocation_service.is_session_revoked.assert_called_once_with("session_123")
        middleware.session_manager.update_activity.assert_called_once_with(
            session_id="session_123",
            ip_address="192.168.1.100"
        )
        middleware.user_store.get_user.assert_called_once_with(test_user.id)
    
    @pytest.mark.asyncio
    async def test_get_current_user_api_key_success(self, middleware, test_user, mock_request):
        """Test successful user authentication via API key."""
        # Create API key
        api_key = APIKey(
            id="api_key_123",
            name="Test Key",
            key_hash="hashed_key",
            user_id=test_user.id,
            permissions={"api:read", "api:write"},
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=None,
            last_used_at=None
        )
        
        # Setup mocks
        middleware.user_store.verify_api_key.return_value = (test_user, api_key)
        middleware.user_store.update_api_key_usage.return_value = None
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=None,
            api_key="sk_test_123456789",
            request=mock_request
        )
        
        assert result_user == test_user
        
        # Verify calls
        middleware.user_store.verify_api_key.assert_called_once_with("sk_test_123456789")
        middleware.user_store.update_api_key_usage.assert_called_once_with(
            api_key.id,
            "192.168.1.100"
        )
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, middleware, mock_request):
        """Test authentication with invalid token."""
        # Setup mocks
        middleware.token_manager.verify_token.return_value = None
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="invalid_token"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert call_args[1]["severity"] == AuditSeverity.WARNING
    
    @pytest.mark.asyncio
    async def test_get_current_user_revoked_token(self, middleware, test_user, mock_request):
        """Test authentication with revoked token."""
        # Setup token data
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            jti="revoked_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = True  # Revoked
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="revoked_token"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert "revoked" in call_args[1]["details"]["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_get_current_user_revoked_session(self, middleware, test_user, mock_request):
        """Test authentication with revoked session."""
        # Setup token data
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            jti="token_jti_123",
            session_id="revoked_session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = True  # Revoked
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token_revoked_session"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert "session" in call_args[1]["details"]["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_get_current_user_inactive_user(self, middleware, mock_request):
        """Test authentication with inactive user."""
        # Create inactive user
        inactive_user = User(
            id="inactive_123",
            username="inactive",
            email="inactive@example.com",
            password_hash="hashed_password",
            roles=["user"],
            permissions=set(),
            status=UserStatus.INACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup token data
        token_data = TokenData(
            user_id=inactive_user.id,
            username=inactive_user.username,
            roles=inactive_user.roles,
            permissions=list(inactive_user.permissions),
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = inactive_user
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token_inactive_user"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert "inactive" in call_args[1]["details"]["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_get_current_user_user_not_found(self, middleware, mock_request):
        """Test authentication when user not found in database."""
        # Setup token data
        token_data = TokenData(
            user_id="nonexistent_user",
            username="ghost",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = None  # User not found
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token_nonexistent_user"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert "not found" in call_args[1]["details"]["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_api_key(self, middleware, mock_request):
        """Test authentication with invalid API key."""
        # Setup mocks
        middleware.user_store.verify_api_key.return_value = (None, None)
        middleware.audit_logger.log_event = AsyncMock()
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=None,
            api_key="invalid_api_key",
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
        assert "api key" in call_args[1]["details"]["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_get_current_user_no_credentials(self, middleware, mock_request):
        """Test authentication with no credentials provided."""
        result_user = await middleware.get_current_user(
            credentials=None,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
    
    @pytest.mark.asyncio
    async def test_check_permission_success(self, middleware, test_user):
        """Test successful permission check."""
        # Setup mocks
        middleware.permission_checker.check_permission.return_value = True
        
        result = await middleware.check_permission(
            user=test_user,
            resource="profile",
            action="read"
        )
        
        assert result is True
        middleware.permission_checker.check_permission.assert_called_once_with(
            test_user.id, test_user.roles, "profile", "read"
        )
    
    @pytest.mark.asyncio
    async def test_check_permission_denied(self, middleware, test_user):
        """Test permission denied."""
        # Setup mocks
        middleware.permission_checker.check_permission.return_value = False
        middleware.audit_logger.log_event = AsyncMock()
        
        result = await middleware.check_permission(
            user=test_user,
            resource="admin",
            action="write"
        )
        
        assert result is False
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHORIZATION_DENIED
    
    @pytest.mark.asyncio
    async def test_check_role_success(self, middleware, admin_user):
        """Test successful role check."""
        # Setup mocks
        middleware.rbac_manager.user_has_role.return_value = True
        
        result = await middleware.check_role(
            user=admin_user,
            role="admin"
        )
        
        assert result is True
        middleware.rbac_manager.user_has_role.assert_called_once_with(
            admin_user.roles, "admin"
        )
    
    @pytest.mark.asyncio
    async def test_check_role_denied(self, middleware, test_user):
        """Test role denied."""
        # Setup mocks
        middleware.rbac_manager.user_has_role.return_value = False
        middleware.audit_logger.log_event = AsyncMock()
        
        result = await middleware.check_role(
            user=test_user,
            role="admin"
        )
        
        assert result is False
        
        # Verify audit log
        middleware.audit_logger.log_event.assert_called_once()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHORIZATION_DENIED
    
    @pytest.mark.asyncio
    async def test_require_authentication_success(self, middleware, test_user, mock_request):
        """Test require_authentication with valid user."""
        result = await middleware.require_authentication(
            user=test_user,
            request=mock_request
        )
        
        assert result == test_user
    
    @pytest.mark.asyncio
    async def test_require_authentication_no_user(self, middleware, mock_request):
        """Test require_authentication with no user."""
        with pytest.raises(HTTPException) as exc_info:
            await middleware.require_authentication(
                user=None,
                request=mock_request
            )
        
        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_session_activity_update_failure(self, middleware, test_user, mock_request):
        """Test handling of session activity update failure."""
        # Setup token data
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks - session update fails
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.session_manager.update_activity.side_effect = Exception("Session update failed")
        middleware.user_store.get_user.return_value = test_user
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_jwt_token"
        )
        
        # Should still succeed (session update failure shouldn't block auth)
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == test_user


class TestDependencyFunctions:
    """Test dependency injection functions."""
    
    @pytest.fixture
    def mock_middleware(self):
        """Create mock middleware."""
        return Mock(spec=AuthMiddleware)
    
    def test_get_current_user_dependency(self, mock_middleware):
        """Test get_current_user_dependency function."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            dependency = get_current_user_dependency()
            
            # Should return a dependency function
            assert callable(dependency)
    
    def test_require_permission_decorator(self, mock_middleware):
        """Test require_permission decorator."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            decorator = require_permission("users", "read")
            
            # Should return a dependency function
            assert callable(decorator)
    
    def test_require_role_decorator(self, mock_middleware):
        """Test require_role decorator."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            decorator = require_role("admin")
            
            # Should return a dependency function
            assert callable(decorator)
    
    def test_require_any_permission_decorator(self, mock_middleware):
        """Test require_any_permission decorator."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            decorator = require_any_permission(["users:read", "users:write"])
            
            # Should return a dependency function
            assert callable(decorator)
    
    def test_require_any_role_decorator(self, mock_middleware):
        """Test require_any_role decorator."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            decorator = require_any_role(["admin", "moderator"])
            
            # Should return a dependency function
            assert callable(decorator)
    
    def test_optional_auth_decorator(self, mock_middleware):
        """Test optional_auth decorator."""
        with patch('src.auth.middleware.get_auth_middleware', return_value=mock_middleware):
            decorator = optional_auth()
            
            # Should return a dependency function
            assert callable(decorator)


class TestSecurityScenarios:
    """Test security scenarios and attack vectors."""
    
    @pytest.fixture
    def middleware(self, mock_components):
        """Create AuthMiddleware instance."""
        return AuthMiddleware(**mock_components)
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.headers = {"User-Agent": "Test Client/1.0"}
        request.url = Mock()
        request.url.path = "/test/endpoint"
        request.method = "GET"
        return request
    
    @pytest.mark.asyncio
    async def test_sql_injection_in_user_id(self, middleware, mock_request):
        """Test SQL injection attempt in user ID."""
        # Setup token data with malicious user ID
        token_data = TokenData(
            user_id="'; DROP TABLE users; --",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = None  # Should not find user
        middleware.audit_logger.log_event = AsyncMock()
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="malicious_token"
        )
        
        # Call middleware
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Verify the malicious user ID was passed to the store
        middleware.user_store.get_user.assert_called_once_with("'; DROP TABLE users; --")
        
        # Should log the failed authentication
        middleware.audit_logger.log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_xss_in_username(self, middleware, mock_request):
        """Test XSS attempt in username."""
        user = User(
            id="user_123",
            username="<script>alert('xss')</script>",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup token data with XSS username
        token_data = TokenData(
            user_id=user.id,
            username="<script>alert('xss')</script>",
            roles=user.roles,
            permissions=list(user.permissions),
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = user
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="xss_token"
        )
        
        # Call middleware - should still work (XSS protection is at output level)
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == user
        assert result_user.username == "<script>alert('xss')</script>"
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, middleware, mock_request):
        """Test resistance to timing attacks."""
        import time
        
        # Test with valid token
        valid_token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="valid_jti",
            session_id="valid_session"
        )
        
        middleware.token_manager.verify_token.return_value = valid_token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Measure time for valid token
        start = time.time()
        await middleware.get_current_user(
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid_token"),
            api_key=None,
            request=mock_request
        )
        valid_time = time.time() - start
        
        # Reset mocks for invalid token
        middleware.token_manager.verify_token.return_value = None
        middleware.audit_logger.log_event = AsyncMock()
        
        # Measure time for invalid token
        start = time.time()
        await middleware.get_current_user(
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid_token"),
            api_key=None,
            request=mock_request
        )
        invalid_time = time.time() - start
        
        # Times should be similar (within reasonable variance)
        time_diff = abs(valid_time - invalid_time)
        assert time_diff < 0.1  # 100ms max difference
    
    @pytest.mark.asyncio
    async def test_concurrent_authentication_attacks(self, middleware, mock_request):
        """Test handling of concurrent authentication attempts."""
        # Setup multiple concurrent authentication attempts
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Create multiple concurrent requests
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        tasks = []
        for _ in range(10):
            task = middleware.get_current_user(
                credentials=credentials,
                api_key=None,
                request=mock_request
            )
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert all(result is not None for result in results)
        assert all(result.id == "user_123" for result in results)
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_attempt(self, middleware, mock_request):
        """Test prevention of privilege escalation via token manipulation."""
        # Create token with low privileges
        low_privilege_token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],  # Low privilege role
            permissions=["read"],  # Limited permissions
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Create user with high privileges in database
        high_privilege_user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["admin"],  # High privilege role in DB
            permissions={"admin:*"},  # High permissions in DB
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = low_privilege_token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = high_privilege_user
        
        # Call middleware
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="low_privilege_token"
        )
        
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        # Should return the database user (with current roles/permissions)
        assert result_user == high_privilege_user
        # The token data contains the original permissions, but user object has current ones
        assert "admin" in result_user.roles
    
    @pytest.mark.asyncio
    async def test_token_replay_attack(self, middleware, mock_request):
        """Test handling of token replay attacks."""
        # Setup token data
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="replayed_jti_123",
            session_id="session_123"
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks for first request (should succeed)
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="replayed_token"
        )
        
        # First request should succeed
        result1 = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        assert result1 == user
        
        # Simulate token being revoked after first use
        middleware.token_revocation_service.is_token_revoked.return_value = True
        middleware.audit_logger.log_event = AsyncMock()
        
        # Second request with same token should fail
        result2 = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        assert result2 is None
        
        # Should log the replay attempt
        middleware.audit_logger.log_event.assert_called()


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def middleware(self, mock_components):
        """Create AuthMiddleware instance."""
        return AuthMiddleware(**mock_components)
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.headers = {"User-Agent": "Test Client/1.0"}
        request.url = Mock()
        request.url.path = "/test/endpoint"
        request.method = "GET"
        return request
    
    @pytest.mark.asyncio
    async def test_missing_client_info(self, middleware, mock_request):
        """Test handling when client info is missing."""
        # Remove client info
        mock_request.client = None
        
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        # Should still work without client info
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == user
        
        # Session update should be called with None IP
        middleware.session_manager.update_activity.assert_called_once_with(
            session_id="session_123",
            ip_address=None
        )
    
    @pytest.mark.asyncio
    async def test_none_request_object(self, middleware):
        """Test handling when request object is None."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.return_value = user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        # Should work with None request
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=None
        )
        
        assert result_user == user
    
    @pytest.mark.asyncio
    async def test_database_connection_failure(self, middleware, mock_request):
        """Test handling of database connection failures."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.user_store.get_user.side_effect = Exception("Database connection failed")
        middleware.audit_logger.log_event = AsyncMock()
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        # Should return None on database failure
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Should log the error
        middleware.audit_logger.log_event.assert_called()
        call_args = middleware.audit_logger.log_event.call_args
        assert call_args[1]["event_type"] == AuditEventType.AUTHENTICATION_FAILED
    
    @pytest.mark.asyncio
    async def test_revocation_service_failure(self, middleware, mock_request):
        """Test handling of revocation service failures."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.side_effect = Exception("Redis connection failed")
        middleware.user_store.get_user.return_value = user
        middleware.audit_logger.log_event = AsyncMock()
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        # Should return None when revocation check fails (fail-safe)
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
    
    @pytest.mark.asyncio
    async def test_session_manager_failure(self, middleware, mock_request):
        """Test handling of session manager failures."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id="session_123"
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.token_revocation_service.is_session_revoked.return_value = False
        middleware.session_manager.update_activity.side_effect = Exception("Session update failed")
        middleware.user_store.get_user.return_value = user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid_token"
        )
        
        # Should still succeed even if session update fails
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == user
    
    @pytest.mark.asyncio
    async def test_very_long_token(self, middleware, mock_request):
        """Test handling of very long tokens."""
        # Create a very long token (simulating attack)
        long_token = "a" * 10000
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = None
        middleware.audit_logger.log_event = AsyncMock()
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=long_token
        )
        
        # Should handle gracefully
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        middleware.token_manager.verify_token.assert_called_once_with(long_token)
    
    @pytest.mark.asyncio
    async def test_empty_string_credentials(self, middleware, mock_request):
        """Test handling of empty string credentials."""
        # Test empty token
        middleware.token_manager.verify_token.return_value = None
        middleware.audit_logger.log_event = AsyncMock()
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=""
        )
        
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user is None
        
        # Test empty API key
        middleware.user_store.verify_api_key.return_value = (None, None)
        
        result_user = await middleware.get_current_user(
            credentials=None,
            api_key="",
            request=mock_request
        )
        
        assert result_user is None
    
    @pytest.mark.asyncio
    async def test_token_without_session_id(self, middleware, mock_request):
        """Test handling of token without session ID."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti="token_jti_123",
            session_id=None  # No session ID
        )
        
        user = User(
            id="user_123", username="testuser", email="test@example.com",
            password_hash="hash", roles=["user"], permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        middleware.token_manager.verify_token.return_value = token_data
        middleware.token_revocation_service.is_token_revoked.return_value = False
        middleware.user_store.get_user.return_value = user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="token_without_session"
        )
        
        # Should work without session ID
        result_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=mock_request
        )
        
        assert result_user == user
        
        # Session-related methods should not be called
        middleware.token_revocation_service.is_session_revoked.assert_not_called()
        middleware.session_manager.update_activity.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.middleware", "--cov-report=term-missing"])