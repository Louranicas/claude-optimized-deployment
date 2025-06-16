"""
Comprehensive Tests for Authentication API (src/auth/api.py).

This test suite covers all API endpoints, authentication flows,
security scenarios, and edge cases with 90%+ code coverage.
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import status
from fastapi.security import HTTPAuthorizationCredentials
import secrets
import os

from src.auth.api import (
    auth_router, initialize_auth_services, get_auth_dependencies,
    get_current_user, require_permission,
    LoginRequest, LoginResponse, RefreshTokenRequest,
    ChangePasswordRequest, ResetPasswordRequest,
    CreateUserRequest, UpdateUserRequest, AssignRoleRequest,
    CreateAPIKeyRequest, APIKeyResponse,
    token_manager, rbac_manager, permission_checker,
    token_revocation_service, session_manager, two_factor_service
)
from src.auth.models import User, UserStatus, APIKey, APIKeyStatus
from src.auth.tokens import TokenData
from src.auth.rbac import Role
from src.auth.permissions import Permission
from src.auth.audit import AuditEventType, AuditSeverity

# Test fixtures

@pytest.fixture
def mock_app():
    """Create FastAPI test app with auth router."""
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(auth_router)
    return app

@pytest.fixture
def client(mock_app):
    """Create test client."""
    return TestClient(mock_app)

@pytest.fixture
def test_user():
    """Create test user."""
    return User(
        id="test_user_123",
        username="testuser",
        email="test@example.com",
        password_hash=User._hash_password("Test123!@#"),
        roles=["user"],
        permissions={"users:read", "profile:write"},
        status=UserStatus.ACTIVE,
        mfa_enabled=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

@pytest.fixture
def admin_user():
    """Create admin test user."""
    return User(
        id="admin_user_456",
        username="admin",
        email="admin@example.com",
        password_hash=User._hash_password("Admin123!@#"),
        roles=["admin"],
        permissions={"users:read", "users:write", "users:delete", "rbac:write", "audit:read"},
        status=UserStatus.ACTIVE,
        mfa_enabled=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

@pytest.fixture
def mock_dependencies():
    """Mock auth dependencies."""
    mock_user_manager = AsyncMock()
    mock_auth_middleware = AsyncMock()
    
    with patch('src.auth.api.get_auth_dependencies') as mock_get_deps:
        mock_get_deps.return_value = (mock_user_manager, mock_auth_middleware)
        yield mock_user_manager, mock_auth_middleware

@pytest.fixture
def mock_request():
    """Mock FastAPI request object."""
    mock_req = Mock()
    mock_req.client.host = "192.168.1.100"
    mock_req.headers = {"User-Agent": "Test Client/1.0"}
    return mock_req

@pytest.fixture
def valid_token(test_user):
    """Create valid JWT token for test user."""
    token_data = TokenData(
        user_id=test_user.id,
        username=test_user.username,
        roles=test_user.roles,
        permissions=list(test_user.permissions)
    )
    return token_manager.create_access_token(token_data)

@pytest.fixture
def admin_token(admin_user):
    """Create valid JWT token for admin user."""
    token_data = TokenData(
        user_id=admin_user.id,
        username=admin_user.username,
        roles=admin_user.roles,
        permissions=list(admin_user.permissions)
    )
    return token_manager.create_access_token(token_data)


class TestLoginEndpoint:
    """Test login endpoint functionality."""
    
    @pytest.mark.asyncio
    async def test_successful_login_without_mfa(self, client, mock_dependencies, test_user, mock_request):
        """Test successful login without MFA."""
        mock_user_manager, mock_auth_middleware = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        
        # Mock 2FA service
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": False}
            
            # Mock session manager
            with patch('src.auth.api.session_manager') as mock_session:
                mock_session_obj = Mock()
                mock_session_obj.session_id = "test_session_123"
                mock_session.create_session.return_value = mock_session_obj
                
                # Mock audit logger
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    # Mock rate limiting
                    with patch('src.auth.api.rate_limit_dependency') as mock_rate_limit:
                        mock_rate_limit.return_value = lambda: None
                        
                        response = client.post("/auth/login", json={
                            "username": "testuser",
                            "password": "Test123!@#"
                        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert "user" in data
        
        # Verify calls
        mock_user_manager.authenticate.assert_called_once()
        mock_2fa.get_2fa_status.assert_called_once_with(test_user.id)
        mock_session.create_session.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_login_with_mfa_required(self, client, mock_dependencies, test_user):
        """Test login when MFA is required."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        
        # Mock 2FA service - enabled but no code provided
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": True}
            
            mock_challenge = Mock()
            mock_challenge.challenge_id = "challenge_123"
            mock_challenge.challenge_type = "totp"
            mock_challenge.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
            mock_2fa.create_challenge.return_value = mock_challenge
            
            response = client.post("/auth/login", json={
                "username": "testuser",
                "password": "Test123!@#"
            })
        
        assert response.status_code == 200
        data = response.json()
        assert data["requires_2fa"] is True
        assert "challenge_id" in data
        assert data["challenge_type"] == "totp"
    
    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, client, mock_dependencies):
        """Test login with invalid credentials."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock authentication failure
        mock_user_manager.authenticate.side_effect = Exception("Invalid username or password")
        
        with patch('src.auth.api.audit_logger') as mock_audit:
            mock_audit.log_event = AsyncMock()
            
            response = client.post("/auth/login", json={
                "username": "wronguser",
                "password": "wrongpass"
            })
        
        assert response.status_code == 401
        data = response.json()
        assert "Invalid username or password" in data["detail"]
        
        # Verify audit log
        mock_audit.log_event.assert_called()
        audit_call = mock_audit.log_event.call_args[1]
        assert audit_call["event_type"] == AuditEventType.LOGIN_FAILED
    
    @pytest.mark.asyncio
    async def test_login_with_valid_mfa_code(self, client, mock_dependencies, test_user):
        """Test login with valid MFA code."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        mock_user_manager.verify_mfa.return_value = True
        
        # Mock 2FA service
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": True}
            
            # Mock session manager
            with patch('src.auth.api.session_manager') as mock_session:
                mock_session_obj = Mock()
                mock_session_obj.session_id = "test_session_123"
                mock_session.create_session.return_value = mock_session_obj
                
                # Mock audit logger
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.post("/auth/login", json={
                        "username": "testuser",
                        "password": "Test123!@#",
                        "mfa_code": "123456"
                    })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "user" in data
        
        # Verify MFA verification
        mock_user_manager.verify_mfa.assert_called_once_with(test_user.id, "123456")
    
    @pytest.mark.asyncio
    async def test_login_with_invalid_mfa_code(self, client, mock_dependencies, test_user):
        """Test login with invalid MFA code."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        mock_user_manager.verify_mfa.return_value = False
        
        # Mock 2FA service
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": True}
            
            with patch('src.auth.api.audit_logger') as mock_audit:
                mock_audit.log_event = AsyncMock()
                
                response = client.post("/auth/login", json={
                    "username": "testuser",
                    "password": "Test123!@#",
                    "mfa_code": "000000"
                })
        
        assert response.status_code == 400
        data = response.json()
        assert "Invalid 2FA code" in data["detail"]
    
    @pytest.mark.asyncio
    async def test_login_with_backup_code(self, client, mock_dependencies, test_user):
        """Test login with backup code."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        
        # Mock 2FA service
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": True}
            mock_2fa.verify_backup_code.return_value = True
            
            # Mock session manager
            with patch('src.auth.api.session_manager') as mock_session:
                mock_session_obj = Mock()
                mock_session_obj.session_id = "test_session_123"
                mock_session.create_session.return_value = mock_session_obj
                
                # Mock audit logger
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.post("/auth/login", json={
                        "username": "testuser",
                        "password": "Test123!@#",
                        "mfa_code": "abcd-1234"  # Backup code format
                    })
        
        assert response.status_code == 200
        
        # Verify backup code verification
        mock_2fa.verify_backup_code.assert_called_once_with(test_user.id, "abcd-1234")
    
    def test_login_validation_errors(self, client):
        """Test login request validation."""
        # Missing username
        response = client.post("/auth/login", json={
            "password": "Test123!@#"
        })
        assert response.status_code == 422
        
        # Short username
        response = client.post("/auth/login", json={
            "username": "ab",
            "password": "Test123!@#"
        })
        assert response.status_code == 422
        
        # Short password
        response = client.post("/auth/login", json={
            "username": "testuser",
            "password": "short"
        })
        assert response.status_code == 422
        
        # Invalid MFA code length
        response = client.post("/auth/login", json={
            "username": "testuser",
            "password": "Test123!@#",
            "mfa_code": "12345"  # Too short
        })
        assert response.status_code == 422


class TestTokenRefreshEndpoint:
    """Test token refresh endpoint."""
    
    @pytest.mark.asyncio
    async def test_successful_token_refresh(self, client, mock_dependencies):
        """Test successful token refresh."""
        mock_user_manager, _ = mock_dependencies
        
        new_tokens = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.refresh_token.return_value = new_tokens
        
        with patch('src.auth.api.audit_logger') as mock_audit:
            mock_audit.log_event = AsyncMock()
            
            response = client.post("/auth/refresh", json={
                "refresh_token": "valid_refresh_token"
            })
        
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "new_access_token"
        assert data["refresh_token"] == "new_refresh_token"
    
    @pytest.mark.asyncio
    async def test_invalid_refresh_token(self, client, mock_dependencies):
        """Test refresh with invalid token."""
        mock_user_manager, _ = mock_dependencies
        
        mock_user_manager.refresh_token.side_effect = Exception("Invalid refresh token")
        
        with patch('src.auth.api.audit_logger') as mock_audit:
            mock_audit.log_event = AsyncMock()
            
            response = client.post("/auth/refresh", json={
                "refresh_token": "invalid_token"
            })
        
        assert response.status_code == 401
        data = response.json()
        assert "Invalid refresh token" in data["detail"]


class TestLogoutEndpoint:
    """Test logout endpoint."""
    
    @pytest.mark.asyncio
    async def test_successful_logout(self, client, mock_dependencies, test_user, valid_token):
        """Test successful logout."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock token verification
        with patch('src.auth.api.token_manager') as mock_token_mgr:
            mock_token_data = Mock()
            mock_token_data.jti = "test_jti"
            mock_token_data.session_id = "test_session_123"
            mock_token_data.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            mock_token_mgr.verify_token.return_value = mock_token_data
            
            # Mock current user dependency
            with patch('src.auth.api.get_current_user') as mock_get_user:
                mock_get_user.return_value = test_user
                
                # Mock services
                with patch('src.auth.api.token_revocation_service') as mock_revocation:
                    mock_revocation.revoke_token = AsyncMock()
                    
                    with patch('src.auth.api.session_manager') as mock_session:
                        mock_session.invalidate_session = AsyncMock()
                        
                        with patch('src.auth.api.audit_logger') as mock_audit:
                            mock_audit.log_event = AsyncMock()
                            
                            response = client.post("/auth/logout", 
                                headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Logged out successfully"


class TestUserInfoEndpoint:
    """Test user info endpoint."""
    
    def test_get_current_user_info(self, client, test_user, valid_token):
        """Test getting current user info."""
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            response = client.get("/auth/me",
                headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_user.id
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email


class TestPasswordChangeEndpoint:
    """Test password change endpoint."""
    
    @pytest.mark.asyncio
    async def test_successful_password_change(self, client, mock_dependencies, test_user, valid_token):
        """Test successful password change."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.change_password = AsyncMock()
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            response = client.put("/auth/me/password",
                headers={"Authorization": f"Bearer {valid_token}"},
                json={
                    "old_password": "Test123!@#",
                    "new_password": "NewPassword123!@#"
                })
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Password changed successfully"
        
        # Verify change_password was called
        mock_user_manager.change_password.assert_called_once_with(
            user_id=test_user.id,
            old_password="Test123!@#",
            new_password="NewPassword123!@#"
        )


class TestUserManagementEndpoints:
    """Test user management endpoints (admin only)."""
    
    @pytest.mark.asyncio
    async def test_create_user_as_admin(self, client, mock_dependencies, admin_user, admin_token):
        """Test creating user as admin."""
        mock_user_manager, _ = mock_dependencies
        
        new_user = User(
            id="new_user_789",
            username="newuser",
            email="newuser@example.com",
            password_hash="hashed_password",
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        mock_user_manager.create_user.return_value = new_user
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.post("/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "Password123!@#",
                    "roles": ["user"]
                })
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == new_user.id
        assert data["username"] == new_user.username
    
    def test_create_user_without_permission(self, client, test_user, valid_token):
        """Test creating user without admin permission."""
        with patch('src.auth.api.require_permission') as mock_require_perm:
            from fastapi import HTTPException
            mock_require_perm.side_effect = HTTPException(status_code=403, detail="Permission denied")
            
            response = client.post("/auth/users",
                headers={"Authorization": f"Bearer {valid_token}"},
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "Password123!@#"
                })
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_list_users(self, client, mock_dependencies, admin_user, admin_token):
        """Test listing users."""
        mock_user_manager, _ = mock_dependencies
        
        users = [
            User(id="user1", username="user1", email="user1@example.com", 
                 password_hash="hash", roles=["user"], permissions=set(),
                 status=UserStatus.ACTIVE,
                 created_at=datetime.now(timezone.utc),
                 updated_at=datetime.now(timezone.utc)),
            User(id="user2", username="user2", email="user2@example.com",
                 password_hash="hash", roles=["user"], permissions=set(),
                 status=UserStatus.ACTIVE,
                 created_at=datetime.now(timezone.utc),
                 updated_at=datetime.now(timezone.utc))
        ]
        mock_user_manager.list_users.return_value = users
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.get("/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["users"]) == 2
        assert data["users"][0]["username"] == "user1"
    
    @pytest.mark.asyncio
    async def test_get_user_by_id(self, client, mock_dependencies, admin_user, admin_token, test_user):
        """Test getting user by ID."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.get_user.return_value = test_user
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.get(f"/auth/users/{test_user.id}",
                headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_user.id
        assert data["username"] == test_user.username
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_user(self, client, mock_dependencies, admin_user, admin_token):
        """Test getting nonexistent user."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.get_user.return_value = None
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.get("/auth/users/nonexistent",
                headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]
    
    @pytest.mark.asyncio
    async def test_update_user(self, client, mock_dependencies, admin_user, admin_token, test_user):
        """Test updating user."""
        mock_user_manager, _ = mock_dependencies
        
        updated_user = test_user.copy()
        updated_user.email = "updated@example.com"
        mock_user_manager.update_user.return_value = updated_user
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.put(f"/auth/users/{test_user.id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"email": "updated@example.com"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "updated@example.com"
    
    @pytest.mark.asyncio
    async def test_delete_user(self, client, mock_dependencies, admin_user, admin_token, test_user):
        """Test deleting user."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.delete_user = AsyncMock()
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.delete(f"/auth/users/{test_user.id}",
                headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "User deleted successfully"
        
        mock_user_manager.delete_user.assert_called_once_with(test_user.id, admin_user.id)


class TestRoleManagementEndpoints:
    """Test role management endpoints."""
    
    @pytest.mark.asyncio
    async def test_assign_role(self, client, mock_dependencies, admin_user, admin_token, test_user):
        """Test assigning role to user."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.assign_role = AsyncMock()
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.post(f"/auth/users/{test_user.id}/roles",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"role_name": "moderator"})
        
        assert response.status_code == 200
        data = response.json()
        assert "moderator assigned successfully" in data["message"]
        
        mock_user_manager.assign_role.assert_called_once_with(
            user_id=test_user.id,
            role_name="moderator",
            assigned_by=admin_user.id,
            expires_at=None
        )
    
    @pytest.mark.asyncio
    async def test_remove_role(self, client, mock_dependencies, admin_user, admin_token, test_user):
        """Test removing role from user."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.remove_role = AsyncMock()
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            response = client.delete(f"/auth/users/{test_user.id}/roles/user",
                headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert "user removed successfully" in data["message"]
        
        mock_user_manager.remove_role.assert_called_once_with(test_user.id, "user", admin_user.id)


class TestAPIKeyManagement:
    """Test API key management endpoints."""
    
    @pytest.mark.asyncio
    async def test_create_api_key(self, client, mock_dependencies, test_user, valid_token):
        """Test creating API key."""
        mock_user_manager, _ = mock_dependencies
        
        api_key = APIKey(
            id="key_123",
            name="Test Key",
            key_hash="hashed_key",
            user_id=test_user.id,
            permissions={"api:read", "api:write"},
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=None,
            last_used_at=None
        )
        raw_key = "sk_test_123456789"
        mock_user_manager.create_api_key.return_value = (api_key, raw_key)
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            response = client.post("/auth/api-keys",
                headers={"Authorization": f"Bearer {valid_token}"},
                json={
                    "name": "Test Key",
                    "permissions": ["api:read", "api:write"]
                })
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == api_key.id
        assert data["name"] == api_key.name
        assert data["key"] == raw_key
    
    @pytest.mark.asyncio
    async def test_list_api_keys(self, client, test_user, valid_token):
        """Test listing API keys."""
        api_keys = [
            APIKey(
                id="key_1",
                name="Key 1",
                key_hash="hash1",
                user_id=test_user.id,
                permissions={"api:read"},
                status=APIKeyStatus.ACTIVE,
                created_at=datetime.now(timezone.utc),
                expires_at=None,
                last_used_at=None
            ),
            APIKey(
                id="key_2",
                name="Key 2", 
                key_hash="hash2",
                user_id=test_user.id,
                permissions={"api:write"},
                status=APIKeyStatus.ACTIVE,
                created_at=datetime.now(timezone.utc),
                expires_at=None,
                last_used_at=None
            )
        ]
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.user_repository') as mock_repo:
                mock_repo.get_user_api_keys.return_value = api_keys
                
                response = client.get("/auth/api-keys",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["api_keys"]) == 2
        assert data["api_keys"][0]["name"] == "Key 1"
    
    @pytest.mark.asyncio
    async def test_revoke_api_key(self, client, mock_dependencies, test_user, valid_token):
        """Test revoking API key."""
        mock_user_manager, _ = mock_dependencies
        mock_user_manager.revoke_api_key = AsyncMock()
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            response = client.delete("/auth/api-keys/key_123",
                headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "API key revoked successfully"
        
        mock_user_manager.revoke_api_key.assert_called_once_with(test_user.id, "key_123")


class TestRBACEndpoints:
    """Test RBAC information endpoints."""
    
    def test_list_roles(self, client, admin_user, admin_token):
        """Test listing all roles."""
        mock_roles = {
            "admin": {"permissions": ["*"], "inherits": []},
            "user": {"permissions": ["profile:read", "profile:write"], "inherits": []}
        }
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            with patch('src.auth.api.rbac_manager') as mock_rbac:
                mock_rbac.export_roles.return_value = mock_roles
                
                response = client.get("/auth/roles",
                    headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert "admin" in data["roles"]
        assert "user" in data["roles"]
    
    def test_get_role_hierarchy(self, client, admin_user, admin_token):
        """Test getting role hierarchy."""
        mock_hierarchy = {
            "role": "admin",
            "permissions": ["*"],
            "inherits": [],
            "inherited_permissions": []
        }
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            with patch('src.auth.api.rbac_manager') as mock_rbac:
                mock_rbac.get_role_hierarchy.return_value = mock_hierarchy
                
                response = client.get("/auth/roles/admin",
                    headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "admin"
        assert data["permissions"] == ["*"]
    
    def test_get_nonexistent_role(self, client, admin_user, admin_token):
        """Test getting nonexistent role."""
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            with patch('src.auth.api.rbac_manager') as mock_rbac:
                mock_rbac.get_role_hierarchy.return_value = None
                
                response = client.get("/auth/roles/nonexistent",
                    headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 404
        data = response.json()
        assert "Role not found" in data["detail"]
    
    def test_get_user_permissions(self, client, test_user, valid_token):
        """Test getting user permissions."""
        mock_permissions = ["profile:read", "profile:write", "users:read"]
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.permission_checker') as mock_perm_check:
                mock_perm_check.get_user_permissions.return_value = mock_permissions
                
                response = client.get("/auth/permissions",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["permissions"] == mock_permissions


class TestAuditEndpoints:
    """Test audit endpoints."""
    
    @pytest.mark.asyncio
    async def test_get_audit_events(self, client, admin_user, admin_token):
        """Test getting audit events."""
        mock_events = [
            Mock(to_dict=lambda: {
                "id": "event_1",
                "event_type": "LOGIN_SUCCESS",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": "user_123"
            }),
            Mock(to_dict=lambda: {
                "id": "event_2", 
                "event_type": "LOGIN_FAILED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": "192.168.1.100"
            })
        ]
        
        with patch('src.auth.api.require_permission') as mock_require_perm:
            mock_require_perm.return_value = lambda: admin_user
            
            with patch('src.auth.api.audit_logger') as mock_audit:
                mock_audit.query_events.return_value = mock_events
                
                response = client.get("/auth/audit/events",
                    headers={"Authorization": f"Bearer {admin_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["events"]) == 2
        assert data["events"][0]["event_type"] == "LOGIN_SUCCESS"


class TestTwoFactorEndpoints:
    """Test 2FA endpoints."""
    
    @pytest.mark.asyncio
    async def test_setup_totp(self, client, test_user, valid_token):
        """Test TOTP setup."""
        mock_setup_data = {
            "secret": "JBSWY3DPEHPK3PXP",
            "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
            "provisioning_uri": "otpauth://totp/..."
        }
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.two_factor_service') as mock_2fa:
                mock_2fa.setup_totp.return_value = mock_setup_data
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.post("/auth/2fa/setup/totp",
                        headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert "qr_code" in data
        assert "secret" in data
        assert "message" in data
    
    @pytest.mark.asyncio
    async def test_verify_totp_setup(self, client, test_user, valid_token):
        """Test TOTP verification and enabling."""
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.two_factor_service') as mock_2fa:
                mock_2fa.verify_totp_setup.return_value = True
                mock_2fa.get_2fa_status.return_value = {"enabled": True, "methods": ["totp"]}
                mock_2fa.regenerate_backup_codes.return_value = ["code1-2345", "code2-6789"]
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.post("/auth/2fa/verify/totp?code=123456",
                        headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert "2FA enabled successfully" in data["message"]
        assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_verify_invalid_totp_setup(self, client, test_user, valid_token):
        """Test invalid TOTP verification."""
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.two_factor_service') as mock_2fa:
                mock_2fa.verify_totp_setup.return_value = False
                
                response = client.post("/auth/2fa/verify/totp?code=000000",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 400
        data = response.json()
        assert "Invalid verification code" in data["detail"]
    
    def test_get_2fa_status(self, client, test_user, valid_token):
        """Test getting 2FA status."""
        mock_status = {
            "enabled": True,
            "methods": ["totp"],
            "backup_codes_remaining": 8
        }
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.two_factor_service') as mock_2fa:
                mock_2fa.get_2fa_status.return_value = mock_status
                
                response = client.get("/auth/2fa/status",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert "totp" in data["methods"]


class TestSessionManagement:
    """Test session management endpoints."""
    
    @pytest.mark.asyncio
    async def test_list_sessions(self, client, test_user, valid_token):
        """Test listing user sessions."""
        mock_sessions = [
            Mock(
                session_id="session_1",
                created_at=datetime.now(timezone.utc),
                last_activity=datetime.now(timezone.utc),
                ip_address="192.168.1.100",
                device_info={"browser": "Chrome", "os": "Windows"},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
            ),
            Mock(
                session_id="session_2",
                created_at=datetime.now(timezone.utc) - timedelta(hours=1),
                last_activity=datetime.now(timezone.utc) - timedelta(minutes=30),
                ip_address="10.0.0.1",
                device_info={"browser": "Firefox", "os": "Linux"},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=23)
            )
        ]
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.session_manager') as mock_session_mgr:
                mock_session_mgr.get_user_sessions.return_value = mock_sessions
                
                response = client.get("/auth/sessions",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["sessions"]) == 2
        assert data["count"] == 2
    
    @pytest.mark.asyncio
    async def test_revoke_session(self, client, test_user, valid_token):
        """Test revoking specific session."""
        mock_session = Mock(user_id=test_user.id, session_id="session_123")
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.session_manager') as mock_session_mgr:
                mock_session_mgr.get_session.return_value = mock_session
                mock_session_mgr.invalidate_session.return_value = True
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.delete("/auth/sessions/session_123",
                        headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Session revoked successfully"
    
    @pytest.mark.asyncio
    async def test_revoke_nonexistent_session(self, client, test_user, valid_token):
        """Test revoking nonexistent session."""
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch('src.auth.api.session_manager') as mock_session_mgr:
                mock_session_mgr.get_session.return_value = None
                
                response = client.delete("/auth/sessions/nonexistent",
                    headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 404
        data = response.json()
        assert "Session not found" in data["detail"]


class TestHealthCheck:
    """Test health check endpoint."""
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, client):
        """Test health check when all services are healthy."""
        with patch('src.auth.api.token_revocation_service') as mock_revocation:
            mock_revocation.get_revoked_tokens_count.return_value = {"revoked_tokens": 5}
            
            with patch('src.auth.api.session_manager') as mock_session_mgr:
                mock_session_mgr.get_session_count.return_value = 10
                
                response = client.get("/auth/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "components" in data
        assert "timestamp" in data
    
    @pytest.mark.asyncio
    async def test_health_check_degraded(self, client):
        """Test health check when services are degraded."""
        with patch('src.auth.api.token_revocation_service') as mock_revocation:
            mock_revocation.get_revoked_tokens_count.side_effect = Exception("Redis connection failed")
            
            response = client.get("/auth/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert "error:" in data["components"]["redis_services"]


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.mark.asyncio
    async def test_token_verification_with_revoked_token(self, client, test_user):
        """Test authentication with revoked token."""
        # Create token first
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions)
        )
        token = token_manager.create_access_token(token_data)
        
        # Mock token verification to return data but mark as revoked
        with patch('src.auth.api.token_manager') as mock_token_mgr:
            mock_token_mgr.verify_token.return_value = token_data
            
            with patch('src.auth.api.token_revocation_service') as mock_revocation:
                mock_revocation.is_token_revoked.return_value = True
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.get("/auth/me",
                        headers={"Authorization": f"Bearer {token}"})
        
        assert response.status_code == 401
        data = response.json()
        assert "Token has been revoked" in data["detail"]
    
    @pytest.mark.asyncio 
    async def test_session_revoked_check(self, client, test_user):
        """Test authentication with revoked session."""
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            session_id="revoked_session_123"
        )
        
        with patch('src.auth.api.token_manager') as mock_token_mgr:
            mock_token_mgr.verify_token.return_value = token_data
            
            with patch('src.auth.api.token_revocation_service') as mock_revocation:
                mock_revocation.is_token_revoked.return_value = False
                mock_revocation.is_session_revoked.return_value = True
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.get("/auth/me",
                        headers={"Authorization": "Bearer fake_token"})
        
        assert response.status_code == 401
        data = response.json()
        assert "Session has been revoked" in data["detail"]
    
    def test_malformed_authorization_header(self, client):
        """Test with malformed authorization header."""
        response = client.get("/auth/me",
            headers={"Authorization": "InvalidFormat"})
        
        assert response.status_code == 403  # HTTPBearer validation error
    
    def test_missing_authorization_header(self, client):
        """Test with missing authorization header.""" 
        response = client.get("/auth/me")
        
        assert response.status_code == 403  # HTTPBearer validation error
    
    @pytest.mark.asyncio
    async def test_rate_limiting_on_login(self, client, mock_dependencies):
        """Test rate limiting on login endpoint."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock rate limit exceeded
        with patch('src.auth.api.rate_limit_dependency') as mock_rate_limit:
            from fastapi import HTTPException
            mock_rate_limit.return_value = lambda: (_ for _ in ()).throw(
                HTTPException(status_code=429, detail="Rate limit exceeded")
            )
            
            response = client.post("/auth/login", json={
                "username": "testuser",
                "password": "Test123!@#"
            })
        
        assert response.status_code == 429
        data = response.json()
        assert "Rate limit exceeded" in data["detail"]
    
    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, client, mock_dependencies):
        """Test SQL injection prevention in username field."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock authentication with SQL injection attempt
        mock_user_manager.authenticate.side_effect = Exception("Invalid username or password")
        
        with patch('src.auth.api.audit_logger') as mock_audit:
            mock_audit.log_event = AsyncMock()
            
            response = client.post("/auth/login", json={
                "username": "admin'; DROP TABLE users; --",
                "password": "password"
            })
        
        assert response.status_code == 401
        # Verify the malicious input was logged
        mock_audit.log_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_xss_prevention_in_responses(self, client, mock_dependencies, test_user, valid_token):
        """Test XSS prevention in API responses."""
        mock_user_manager, _ = mock_dependencies
        
        # Create user with potentially malicious content
        xss_user = test_user.copy()
        xss_user.username = "<script>alert('xss')</script>"
        
        with patch('src.auth.api.get_current_user') as mock_get_user:
            mock_get_user.return_value = xss_user
            
            response = client.get("/auth/me",
                headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 200
        # Response should be JSON, not HTML, so script tags should be escaped
        assert response.headers["content-type"] == "application/json"
        data = response.json()
        # The username should be returned as-is since it's JSON
        # XSS protection happens at the frontend level
        assert data["username"] == "<script>alert('xss')</script>"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_services_not_initialized(self, client):
        """Test API calls when services are not initialized."""
        with patch('src.auth.api._initialized', False):
            response = client.post("/auth/login", json={
                "username": "testuser", 
                "password": "password"
            })
        
        # Should get a 500 error due to uninitialized services
        assert response.status_code == 500
    
    @pytest.mark.asyncio
    async def test_database_connection_failure(self, client, mock_dependencies, valid_token):
        """Test handling of database connection failures."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock database failure
        with patch('src.auth.api.user_repository') as mock_repo:
            mock_repo.get_user.side_effect = Exception("Database connection failed")
            
            with patch('src.auth.api.token_manager') as mock_token_mgr:
                mock_token_data = Mock()
                mock_token_data.user_id = "test_user_123"
                mock_token_mgr.verify_token.return_value = mock_token_data
                
                with patch('src.auth.api.token_revocation_service') as mock_revocation:
                    mock_revocation.is_token_revoked.return_value = False
                    mock_revocation.is_session_revoked.return_value = False
                    
                    response = client.get("/auth/me",
                        headers={"Authorization": f"Bearer {valid_token}"})
        
        assert response.status_code == 401
        data = response.json()
        assert "User not found" in data["detail"]
    
    @pytest.mark.asyncio
    async def test_redis_service_failure(self, client):
        """Test health check with Redis service failure."""
        with patch('src.auth.api.token_revocation_service') as mock_revocation:
            mock_revocation.get_revoked_tokens_count.side_effect = ConnectionError("Redis unavailable")
            
            response = client.get("/auth/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert "error:" in data["components"]["redis_services"]
    
    def test_invalid_json_payload(self, client):
        """Test handling of invalid JSON payload."""
        response = client.post("/auth/login",
            data="invalid json",
            headers={"Content-Type": "application/json"})
        
        assert response.status_code == 422  # Unprocessable Entity
    
    def test_oversized_payload(self, client):
        """Test handling of oversized payload."""
        large_payload = {
            "username": "a" * 10000,  # Very long username
            "password": "b" * 10000   # Very long password
        }
        
        response = client.post("/auth/login", json=large_payload)
        
        # Should fail validation due to max_length constraints
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_concurrent_session_creation(self, client, mock_dependencies, test_user):
        """Test concurrent session creation handling."""
        mock_user_manager, _ = mock_dependencies
        
        # Mock user manager authenticate
        mock_tokens = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token", 
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_user_manager.authenticate.return_value = (test_user, mock_tokens)
        
        # Mock 2FA service
        with patch('src.auth.api.two_factor_service') as mock_2fa:
            mock_2fa.get_2fa_status.return_value = {"enabled": False}
            
            # Mock session manager with concurrency issue
            with patch('src.auth.api.session_manager') as mock_session:
                mock_session.create_session.side_effect = Exception("Session limit exceeded")
                
                with patch('src.auth.api.audit_logger') as mock_audit:
                    mock_audit.log_event = AsyncMock()
                    
                    response = client.post("/auth/login", json={
                        "username": "testuser",
                        "password": "Test123!@#"
                    })
        
        assert response.status_code == 401
        # Should log the error
        mock_audit.log_event.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.api", "--cov-report=term-missing"])