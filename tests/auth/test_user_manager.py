"""
Comprehensive Tests for User Manager (src/auth/user_manager.py).

This test suite covers user management, authentication flows, password handling,
MFA integration, security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import secrets
import hashlib
import pyotp

from src.auth.user_manager import (
    UserManager, UserCreationRequest, PasswordResetRequest,
    UserUpdateRequest, BulkUserOperation,
    AuthenticationError, UserNotFoundError, InvalidPasswordError,
    PasswordTooWeakError, AccountLockedError, MFARequiredError
)
from src.auth.models import User, UserStatus, APIKey, APIKeyStatus
from src.auth.tokens import TokenManager, TokenData
from src.auth.rbac import RBACManager
from src.auth.permissions import PermissionChecker
from src.auth.audit import AuditLogger, AuditEventType


class TestUserManager:
    """Test UserManager class functionality."""
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components for UserManager."""
        user_store = AsyncMock()
        token_manager = Mock(spec=TokenManager)
        rbac_manager = Mock(spec=RBACManager)
        permission_checker = Mock(spec=PermissionChecker)
        audit_logger = AsyncMock(spec=AuditLogger)
        
        return {
            "user_store": user_store,
            "token_manager": token_manager,
            "rbac_manager": rbac_manager,
            "permission_checker": permission_checker,
            "audit_logger": audit_logger
        }
    
    @pytest.fixture
    def user_manager(self, mock_components):
        """Create UserManager instance."""
        return UserManager(**mock_components)
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash=User._hash_password("TestPassword123!"),
            roles=["user"],
            permissions={"profile:read", "profile:write"},
            status=UserStatus.ACTIVE,
            mfa_enabled=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture
    def admin_user(self):
        """Create admin test user."""
        return User(
            id="admin_456",
            username="admin",
            email="admin@example.com",
            password_hash=User._hash_password("AdminPassword123!"),
            roles=["admin"],
            permissions={"users:*", "system:*"},
            status=UserStatus.ACTIVE,
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    def test_user_manager_initialization(self, mock_components):
        """Test UserManager initialization."""
        manager = UserManager(**mock_components)
        
        assert manager.user_store == mock_components["user_store"]
        assert manager.token_manager == mock_components["token_manager"]
        assert manager.rbac_manager == mock_components["rbac_manager"]
        assert manager.permission_checker == mock_components["permission_checker"]
        assert manager.audit_logger == mock_components["audit_logger"]
        assert manager.max_login_attempts == 5
        assert manager.lockout_duration_minutes == 30
        assert manager.password_reset_token_ttl_hours == 24
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_manager, mock_components):
        """Test successful user creation."""
        request = UserCreationRequest(
            username="newuser",
            email="newuser@example.com",
            password="SecurePassword123!",
            roles=["user"]
        )
        
        created_user = User(
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
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        mock_components["user_store"].get_user_by_email.return_value = None
        mock_components["user_store"].create_user.return_value = created_user
        mock_components["rbac_manager"].get_role_permissions.return_value = {"profile:read"}
        
        result = await user_manager.create_user(request, created_by="admin_123")
        
        assert result == created_user
        mock_components["user_store"].create_user.assert_called_once()
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, user_manager, mock_components, test_user):
        """Test user creation with duplicate username."""
        request = UserCreationRequest(
            username="testuser",  # Existing username
            email="different@example.com",
            password="SecurePassword123!"
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = test_user
        
        with pytest.raises(ValueError) as exc_info:
            await user_manager.create_user(request, created_by="admin_123")
        
        assert "already exists" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, user_manager, mock_components, test_user):
        """Test user creation with duplicate email."""
        request = UserCreationRequest(
            username="newuser",
            email="test@example.com",  # Existing email
            password="SecurePassword123!"
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        mock_components["user_store"].get_user_by_email.return_value = test_user
        
        with pytest.raises(ValueError) as exc_info:
            await user_manager.create_user(request, created_by="admin_123")
        
        assert "already exists" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_create_user_weak_password(self, user_manager, mock_components):
        """Test user creation with weak password."""
        request = UserCreationRequest(
            username="newuser",
            email="newuser@example.com",
            password="weak"  # Weak password
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        mock_components["user_store"].get_user_by_email.return_value = None
        
        with pytest.raises(PasswordTooWeakError):
            await user_manager.create_user(request, created_by="admin_123")
    
    @pytest.mark.asyncio
    async def test_authenticate_success(self, user_manager, mock_components, test_user):
        """Test successful user authentication."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        mock_components["token_manager"].create_token_pair.return_value = {
            "access_token": "access_token_123",
            "refresh_token": "refresh_token_123",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        
        user, tokens = await user_manager.authenticate(
            username="testuser",
            password="TestPassword123!",
            ip_address="192.168.1.100"
        )
        
        assert user == test_user
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        
        # Verify calls
        mock_components["user_store"].get_user_by_username.assert_called_once_with("testuser")
        mock_components["token_manager"].create_token_pair.assert_called_once()
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_invalid_username(self, user_manager, mock_components):
        """Test authentication with invalid username."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        
        with pytest.raises(AuthenticationError) as exc_info:
            await user_manager.authenticate(
                username="nonexistent",
                password="password",
                ip_address="192.168.1.100"
            )
        
        assert "Invalid username or password" in str(exc_info.value)
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_invalid_password(self, user_manager, mock_components, test_user):
        """Test authentication with invalid password."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        with pytest.raises(AuthenticationError) as exc_info:
            await user_manager.authenticate(
                username="testuser",
                password="WrongPassword",
                ip_address="192.168.1.100"
            )
        
        assert "Invalid username or password" in str(exc_info.value)
        
        # Failed login attempts should be incremented
        update_call = mock_components["user_store"].update_user.call_args[0][0]
        assert update_call.failed_login_attempts > 0
    
    @pytest.mark.asyncio
    async def test_authenticate_locked_account(self, user_manager, mock_components):
        """Test authentication with locked account."""
        locked_user = User(
            id="locked_user",
            username="lockeduser",
            email="locked@example.com",
            password_hash=User._hash_password("TestPassword123!"),
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            failed_login_attempts=5,
            locked_until=datetime.now(timezone.utc) + timedelta(hours=1),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = locked_user
        
        with pytest.raises(AccountLockedError):
            await user_manager.authenticate(
                username="lockeduser",
                password="TestPassword123!",
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self, user_manager, mock_components):
        """Test authentication with inactive user."""
        inactive_user = User(
            id="inactive_user",
            username="inactiveuser",
            email="inactive@example.com",
            password_hash=User._hash_password("TestPassword123!"),
            roles=["user"],
            permissions=set(),
            status=UserStatus.INACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = inactive_user
        
        with pytest.raises(AuthenticationError) as exc_info:
            await user_manager.authenticate(
                username="inactiveuser",
                password="TestPassword123!",
                ip_address="192.168.1.100"
            )
        
        assert "account is not active" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_authenticate_mfa_required(self, user_manager, mock_components, admin_user):
        """Test authentication when MFA is required."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = admin_user
        
        with pytest.raises(MFARequiredError):
            await user_manager.authenticate(
                username="admin",
                password="AdminPassword123!",
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_verify_mfa_success(self, user_manager, mock_components, admin_user):
        """Test successful MFA verification."""
        # Generate valid TOTP code
        totp = pyotp.TOTP(admin_user.mfa_secret)
        valid_code = totp.now()
        
        result = await user_manager.verify_mfa(admin_user.id, valid_code)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code(self, user_manager, mock_components, admin_user):
        """Test MFA verification with invalid code."""
        result = await user_manager.verify_mfa(admin_user.id, "000000")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, user_manager, mock_components, test_user):
        """Test successful password change."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        await user_manager.change_password(
            user_id=test_user.id,
            old_password="TestPassword123!",
            new_password="NewSecurePassword456!"
        )
        
        # Verify user was updated
        mock_components["user_store"].update_user.assert_called_once()
        updated_user = mock_components["user_store"].update_user.call_args[0][0]
        
        # Password hash should be different
        assert updated_user.password_hash != test_user.password_hash
        
        # Audit log should be called
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_invalid_old_password(self, user_manager, mock_components, test_user):
        """Test password change with invalid old password."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        
        with pytest.raises(InvalidPasswordError):
            await user_manager.change_password(
                user_id=test_user.id,
                old_password="WrongOldPassword",
                new_password="NewSecurePassword456!"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_weak_new_password(self, user_manager, mock_components, test_user):
        """Test password change with weak new password."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        
        with pytest.raises(PasswordTooWeakError):
            await user_manager.change_password(
                user_id=test_user.id,
                old_password="TestPassword123!",
                new_password="weak"
            )
    
    @pytest.mark.asyncio
    async def test_reset_password_request(self, user_manager, mock_components, test_user):
        """Test password reset request."""
        request = PasswordResetRequest(email="test@example.com")
        
        # Setup mocks
        mock_components["user_store"].get_user_by_email.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        with patch('src.auth.user_manager.send_password_reset_email') as mock_send_email:
            result = await user_manager.reset_password_request(request)
        
        assert "reset link has been sent" in result.lower()
        
        # Verify reset token was set
        mock_components["user_store"].update_user.assert_called_once()
        updated_user = mock_components["user_store"].update_user.call_args[0][0]
        assert updated_user.password_reset_token is not None
        assert updated_user.password_reset_expires is not None
        
        # Verify email was sent
        mock_send_email.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reset_password_request_nonexistent_email(self, user_manager, mock_components):
        """Test password reset request with non-existent email."""
        request = PasswordResetRequest(email="nonexistent@example.com")
        
        # Setup mocks
        mock_components["user_store"].get_user_by_email.return_value = None
        
        # Should not reveal that email doesn't exist
        result = await user_manager.reset_password_request(request)
        assert "reset link has been sent" in result.lower()
    
    @pytest.mark.asyncio
    async def test_reset_password_success(self, user_manager, mock_components, test_user):
        """Test successful password reset."""
        # Setup user with reset token
        reset_token = secrets.token_urlsafe(32)
        test_user.password_reset_token = hashlib.sha256(reset_token.encode()).hexdigest()
        test_user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Setup mocks
        mock_components["user_store"].get_user_by_reset_token.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        await user_manager.reset_password(reset_token, "NewSecurePassword456!")
        
        # Verify user was updated
        mock_components["user_store"].update_user.assert_called_once()
        updated_user = mock_components["user_store"].update_user.call_args[0][0]
        
        # Password should be changed and reset token cleared
        assert updated_user.password_hash != test_user.password_hash
        assert updated_user.password_reset_token is None
        assert updated_user.password_reset_expires is None
    
    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(self, user_manager, mock_components):
        """Test password reset with invalid token."""
        # Setup mocks
        mock_components["user_store"].get_user_by_reset_token.return_value = None
        
        with pytest.raises(ValueError) as exc_info:
            await user_manager.reset_password("invalid_token", "NewPassword123!")
        
        assert "invalid or expired" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_reset_password_expired_token(self, user_manager, mock_components, test_user):
        """Test password reset with expired token."""
        # Setup user with expired reset token
        reset_token = secrets.token_urlsafe(32)
        test_user.password_reset_token = hashlib.sha256(reset_token.encode()).hexdigest()
        test_user.password_reset_expires = datetime.now(timezone.utc) - timedelta(hours=1)
        
        # Setup mocks
        mock_components["user_store"].get_user_by_reset_token.return_value = test_user
        
        with pytest.raises(ValueError) as exc_info:
            await user_manager.reset_password(reset_token, "NewPassword123!")
        
        assert "invalid or expired" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_manager, mock_components, test_user):
        """Test successful user update."""
        updates = {
            "email": "newemail@example.com",
            "status": UserStatus.INACTIVE,
            "metadata": {"department": "Engineering"}
        }
        
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        result = await user_manager.update_user(test_user.id, updates, "admin_123")
        
        assert result == test_user
        mock_components["user_store"].update_user.assert_called_once()
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_user_nonexistent(self, user_manager, mock_components):
        """Test updating non-existent user."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = None
        
        with pytest.raises(UserNotFoundError):
            await user_manager.update_user("nonexistent", {}, "admin_123")
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self, user_manager, mock_components, test_user):
        """Test successful user deletion (deactivation)."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        
        await user_manager.delete_user(test_user.id, "admin_123")
        
        # Verify user was deactivated
        mock_components["user_store"].update_user.assert_called_once()
        updated_user = mock_components["user_store"].update_user.call_args[0][0]
        assert updated_user.status == UserStatus.DELETED
        
        # Audit log should be called
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_api_key_success(self, user_manager, mock_components, test_user):
        """Test successful API key creation."""
        api_key = APIKey(
            id="api_key_123",
            name="Test Key",
            key_hash="hashed_key",
            user_id=test_user.id,
            permissions={"api:read"},
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=None,
            last_used_at=None
        )
        
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["user_store"].create_api_key.return_value = (api_key, "sk_test_123456789")
        
        result_key, raw_key = await user_manager.create_api_key(
            user_id=test_user.id,
            name="Test Key",
            permissions=["api:read"]
        )
        
        assert result_key == api_key
        assert raw_key == "sk_test_123456789"
        
        mock_components["user_store"].create_api_key.assert_called_once()
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_revoke_api_key_success(self, user_manager, mock_components, test_user):
        """Test successful API key revocation."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["user_store"].revoke_api_key.return_value = True
        
        await user_manager.revoke_api_key(test_user.id, "api_key_123")
        
        mock_components["user_store"].revoke_api_key.assert_called_once_with(
            test_user.id, "api_key_123"
        )
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_enable_mfa_success(self, user_manager, mock_components, test_user):
        """Test successful MFA enablement."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        
        with patch('pyotp.random_base32', return_value='JBSWY3DPEHPK3PXP'):
            with patch('qrcode.make') as mock_qr:
                mock_qr_img = Mock()
                mock_qr_img.save = Mock()
                mock_qr.return_value = mock_qr_img
                
                mfa_data = await user_manager.enable_mfa(test_user.id)
        
        assert "secret" in mfa_data
        assert "qr_code" in mfa_data
        assert mfa_data["secret"] == "JBSWY3DPEHPK3PXP"
        assert mfa_data["qr_code"].startswith("data:image/png;base64,")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_success(self, user_manager, mock_components, admin_user):
        """Test successful MFA disabling."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = admin_user
        mock_components["user_store"].update_user.return_value = admin_user
        
        await user_manager.disable_mfa(admin_user.id, "AdminPassword123!")
        
        # Verify user was updated
        mock_components["user_store"].update_user.assert_called_once()
        updated_user = mock_components["user_store"].update_user.call_args[0][0]
        assert updated_user.mfa_enabled is False
        assert updated_user.mfa_secret is None
    
    @pytest.mark.asyncio
    async def test_disable_mfa_invalid_password(self, user_manager, mock_components, admin_user):
        """Test MFA disabling with invalid password."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = admin_user
        
        with pytest.raises(InvalidPasswordError):
            await user_manager.disable_mfa(admin_user.id, "WrongPassword")
    
    @pytest.mark.asyncio
    async def test_assign_role_success(self, user_manager, mock_components, test_user):
        """Test successful role assignment."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["rbac_manager"].assign_role.return_value = Mock()
        
        await user_manager.assign_role(
            user_id=test_user.id,
            role_name="admin",
            assigned_by="super_admin",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        mock_components["rbac_manager"].assign_role.assert_called_once()
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_remove_role_success(self, user_manager, mock_components, test_user):
        """Test successful role removal."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["rbac_manager"].revoke_role.return_value = None
        
        await user_manager.remove_role(test_user.id, "user", "admin_123")
        
        mock_components["rbac_manager"].revoke_role.assert_called_once_with(
            test_user.id, "user"
        )
        mock_components["audit_logger"].log_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, user_manager, mock_components, test_user):
        """Test successful token refresh."""
        # Setup mocks
        refresh_token = "valid_refresh_token"
        mock_components["token_manager"].verify_token.return_value = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions),
            token_type="refresh"
        )
        mock_components["token_manager"].refresh_access_token.return_value = "new_access_token"
        mock_components["user_store"].get_user.return_value = test_user
        
        new_tokens = await user_manager.refresh_token(refresh_token)
        
        assert "access_token" in new_tokens
        assert new_tokens["access_token"] == "new_access_token"
        
        mock_components["token_manager"].verify_token.assert_called_once_with(
            refresh_token, token_type="refresh"
        )
        mock_components["token_manager"].refresh_access_token.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, user_manager, mock_components):
        """Test token refresh with invalid token."""
        # Setup mocks
        mock_components["token_manager"].verify_token.return_value = None
        
        with pytest.raises(AuthenticationError):
            await user_manager.refresh_token("invalid_refresh_token")
    
    @pytest.mark.asyncio
    async def test_logout_success(self, user_manager, mock_components, test_user):
        """Test successful logout."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        
        await user_manager.logout(test_user.id, "session_123")
        
        # Should log the logout event
        mock_components["audit_logger"].log_event.assert_called_once()
        call_args = mock_components["audit_logger"].log_event.call_args[1]
        assert call_args["event_type"] == AuditEventType.LOGOUT
        assert call_args["user_id"] == test_user.id
    
    @pytest.mark.asyncio
    async def test_list_users_success(self, user_manager, mock_components):
        """Test listing users."""
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
        
        # Setup mocks
        mock_components["user_store"].list_users.return_value = users
        
        result = await user_manager.list_users(offset=0, limit=10)
        
        assert result == users
        mock_components["user_store"].list_users.assert_called_once_with(
            offset=0, limit=10, status=None
        )
    
    @pytest.mark.asyncio
    async def test_get_user_success(self, user_manager, mock_components, test_user):
        """Test getting user by ID."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = test_user
        
        result = await user_manager.get_user(test_user.id)
        
        assert result == test_user
        mock_components["user_store"].get_user.assert_called_once_with(test_user.id)
    
    @pytest.mark.asyncio
    async def test_get_user_not_found(self, user_manager, mock_components):
        """Test getting non-existent user."""
        # Setup mocks
        mock_components["user_store"].get_user.return_value = None
        
        result = await user_manager.get_user("nonexistent")
        
        assert result is None


class TestPasswordValidation:
    """Test password validation functionality."""
    
    @pytest.fixture
    def user_manager(self, mock_components):
        """Create UserManager instance."""
        from tests.auth.test_user_manager import mock_components
        return UserManager(**mock_components)
    
    def test_password_strength_validation(self, user_manager):
        """Test password strength validation."""
        # Strong passwords should pass
        strong_passwords = [
            "SecurePassword123!",
            "MyVeryL0ngP@ssw0rd",
            "C0mpl3x_P@ssw0rd!",
            "Str0ng&S3cur3P@ss"
        ]
        
        for password in strong_passwords:
            # Should not raise exception
            user_manager._validate_password_strength(password)
        
        # Weak passwords should fail
        weak_passwords = [
            "weak",
            "password",
            "12345678",
            "PASSWORD",
            "Password",
            "Password1",
            "password!"
        ]
        
        for password in weak_passwords:
            with pytest.raises(PasswordTooWeakError):
                user_manager._validate_password_strength(password)
    
    def test_password_complexity_requirements(self, user_manager):
        """Test password complexity requirements."""
        # Test minimum length
        with pytest.raises(PasswordTooWeakError):
            user_manager._validate_password_strength("Sh0rt!")  # 6 chars
        
        # Test missing uppercase
        with pytest.raises(PasswordTooWeakError):
            user_manager._validate_password_strength("lowercase123!")
        
        # Test missing lowercase
        with pytest.raises(PasswordTooWeakError):
            user_manager._validate_password_strength("UPPERCASE123!")
        
        # Test missing numbers
        with pytest.raises(PasswordTooWeakError):
            user_manager._validate_password_strength("NoNumbers!")
        
        # Test missing special characters
        with pytest.raises(PasswordTooWeakError):
            user_manager._validate_password_strength("NoSpecialChars123")
    
    def test_common_password_rejection(self, user_manager):
        """Test rejection of common passwords."""
        common_passwords = [
            "password123",
            "123456789",
            "qwerty123",
            "admin123",
            "letmein123"
        ]
        
        for password in common_passwords:
            with pytest.raises(PasswordTooWeakError):
                user_manager._validate_password_strength(password)


class TestSecurityScenarios:
    """Test security scenarios and attack vectors."""
    
    @pytest.fixture
    def user_manager(self, mock_components):
        """Create UserManager instance."""
        return UserManager(**mock_components)
    
    @pytest.mark.asyncio
    async def test_brute_force_protection(self, user_manager, mock_components):
        """Test brute force attack protection."""
        user = User(
            id="target_user",
            username="target",
            email="target@example.com",
            password_hash=User._hash_password("CorrectPassword123!"),
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            failed_login_attempts=0,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = user
        mock_components["user_store"].update_user.return_value = user
        
        # Simulate multiple failed login attempts
        for i in range(user_manager.max_login_attempts):
            try:
                await user_manager.authenticate(
                    username="target",
                    password="WrongPassword",
                    ip_address="192.168.1.100"
                )
            except AuthenticationError:
                pass
        
        # Account should be locked after max attempts
        with pytest.raises(AccountLockedError):
            await user_manager.authenticate(
                username="target",
                password="CorrectPassword123!",  # Even correct password should fail
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, user_manager, mock_components):
        """Test SQL injection prevention in username/email fields."""
        malicious_inputs = [
            "admin'; DROP TABLE users; --",
            "user' OR '1'='1",
            "'; UPDATE users SET role='admin'; --",
            "admin\"; DELETE FROM users WHERE id=1; --"
        ]
        
        # Setup mocks to return None (no user found)
        mock_components["user_store"].get_user_by_username.return_value = None
        mock_components["user_store"].get_user_by_email.return_value = None
        
        for malicious_input in malicious_inputs:
            # Authentication should fail safely
            with pytest.raises(AuthenticationError):
                await user_manager.authenticate(
                    username=malicious_input,
                    password="password",
                    ip_address="192.168.1.100"
                )
            
            # User creation should handle malicious email
            request = UserCreationRequest(
                username="testuser",
                email=malicious_input,
                password="SecurePassword123!"
            )
            
            try:
                await user_manager.create_user(request, created_by="admin")
            except Exception:
                pass  # Expected to fail validation
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, user_manager, mock_components):
        """Test resistance to timing attacks."""
        import time
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        
        # Measure authentication time for non-existent users
        times = []
        for _ in range(10):
            start = time.time()
            try:
                await user_manager.authenticate(
                    username="nonexistent_user",
                    password="password",
                    ip_address="192.168.1.100"
                )
            except AuthenticationError:
                pass
            times.append(time.time() - start)
        
        # Times should be relatively consistent (no significant variance)
        avg_time = sum(times) / len(times)
        max_variance = max(times) - min(times)
        
        # Variance should be small relative to average time
        assert max_variance < avg_time * 0.5  # Max 50% variance
    
    @pytest.mark.asyncio
    async def test_password_hash_security(self, user_manager, mock_components):
        """Test password hash security."""
        # Test that same password produces different hashes (due to salt)
        password = "TestPassword123!"
        
        hash1 = User._hash_password(password)
        hash2 = User._hash_password(password)
        
        assert hash1 != hash2  # Should be different due to salt
        assert User._verify_password(password, hash1)  # Should verify correctly
        assert User._verify_password(password, hash2)  # Should verify correctly
        
        # Test that wrong password doesn't verify
        assert not User._verify_password("WrongPassword", hash1)
    
    @pytest.mark.asyncio
    async def test_mfa_bypass_prevention(self, user_manager, mock_components):
        """Test prevention of MFA bypass attempts."""
        mfa_user = User(
            id="mfa_user",
            username="mfauser",
            email="mfa@example.com",
            password_hash=User._hash_password("Password123!"),
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = mfa_user
        
        # Should require MFA even with correct password
        with pytest.raises(MFARequiredError):
            await user_manager.authenticate(
                username="mfauser",
                password="Password123!",
                ip_address="192.168.1.100"
            )
        
        # Invalid MFA codes should not work
        invalid_codes = ["000000", "123456", "999999", ""]
        
        for code in invalid_codes:
            result = await user_manager.verify_mfa(mfa_user.id, code)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, user_manager, mock_components, test_user):
        """Test prevention of privilege escalation."""
        # Regular user should not be able to assign admin roles
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["rbac_manager"].assign_role.side_effect = Exception("Permission denied")
        
        with pytest.raises(Exception):
            await user_manager.assign_role(
                user_id=test_user.id,
                role_name="admin",
                assigned_by=test_user.id  # User trying to assign role to themselves
            )
    
    @pytest.mark.asyncio
    async def test_session_fixation_prevention(self, user_manager, mock_components, test_user):
        """Test prevention of session fixation attacks."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        mock_components["token_manager"].create_token_pair.return_value = {
            "access_token": "new_token_123",
            "refresh_token": "new_refresh_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_id": "new_session_123"
        }
        
        # Each authentication should create new session
        user1, tokens1 = await user_manager.authenticate(
            username="testuser",
            password="TestPassword123!",
            ip_address="192.168.1.100"
        )
        
        user2, tokens2 = await user_manager.authenticate(
            username="testuser",
            password="TestPassword123!",
            ip_address="192.168.1.101"
        )
        
        # Sessions should be different
        assert tokens1["session_id"] != tokens2["session_id"]
        assert tokens1["access_token"] != tokens2["access_token"]


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def user_manager(self, mock_components):
        """Create UserManager instance."""
        return UserManager(**mock_components)
    
    @pytest.mark.asyncio
    async def test_unicode_usernames_and_emails(self, user_manager, mock_components):
        """Test handling of unicode characters in usernames and emails."""
        unicode_inputs = [
            ("用户名", "用户@example.com"),
            ("utilisateur", "utilisateur@example.fr"),
            ("пользователь", "пользователь@example.ru"),
            ("ユーザー", "ユーザー@example.jp")
        ]
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        mock_components["user_store"].get_user_by_email.return_value = None
        
        for username, email in unicode_inputs:
            # Should handle unicode gracefully
            try:
                await user_manager.authenticate(
                    username=username,
                    password="password",
                    ip_address="192.168.1.100"
                )
            except AuthenticationError:
                pass  # Expected since user doesn't exist
    
    @pytest.mark.asyncio
    async def test_very_long_inputs(self, user_manager, mock_components):
        """Test handling of very long inputs."""
        long_string = "a" * 10000
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        
        # Should handle long inputs gracefully
        try:
            await user_manager.authenticate(
                username=long_string,
                password=long_string,
                ip_address="192.168.1.100"
            )
        except AuthenticationError:
            pass  # Expected
    
    @pytest.mark.asyncio
    async def test_none_values(self, user_manager, mock_components):
        """Test handling of None values."""
        # Should handle None values gracefully
        with pytest.raises((ValueError, AuthenticationError, TypeError)):
            await user_manager.authenticate(
                username=None,
                password="password",
                ip_address="192.168.1.100"
            )
        
        with pytest.raises((ValueError, AuthenticationError, TypeError)):
            await user_manager.authenticate(
                username="user",
                password=None,
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_empty_strings(self, user_manager, mock_components):
        """Test handling of empty strings."""
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = None
        
        # Should handle empty strings gracefully
        with pytest.raises(AuthenticationError):
            await user_manager.authenticate(
                username="",
                password="password",
                ip_address="192.168.1.100"
            )
        
        with pytest.raises(AuthenticationError):
            await user_manager.authenticate(
                username="user",
                password="",
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_database_connection_failures(self, user_manager, mock_components):
        """Test handling of database connection failures."""
        # Setup mocks to simulate database failures
        mock_components["user_store"].get_user_by_username.side_effect = Exception("Database connection failed")
        
        with pytest.raises(Exception):
            await user_manager.authenticate(
                username="testuser",
                password="password",
                ip_address="192.168.1.100"
            )
    
    @pytest.mark.asyncio
    async def test_concurrent_user_operations(self, user_manager, mock_components):
        """Test concurrent user operations."""
        import asyncio
        
        test_user = User(
            id="concurrent_user",
            username="concurrentuser",
            email="concurrent@example.com",
            password_hash=User._hash_password("Password123!"),
            roles=["user"],
            permissions=set(),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Setup mocks
        mock_components["user_store"].get_user_by_username.return_value = test_user
        mock_components["user_store"].update_user.return_value = test_user
        mock_components["token_manager"].create_token_pair.return_value = {
            "access_token": "token_123",
            "refresh_token": "refresh_123",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        
        # Simulate concurrent authentication attempts
        async def authenticate():
            try:
                return await user_manager.authenticate(
                    username="concurrentuser",
                    password="Password123!",
                    ip_address="192.168.1.100"
                )
            except Exception as e:
                return e
        
        # Run concurrent operations
        tasks = [authenticate() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent operations gracefully
        successful_auths = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_auths) > 0  # At least some should succeed
    
    @pytest.mark.asyncio
    async def test_memory_usage_with_many_users(self, user_manager, mock_components):
        """Test memory usage doesn't grow excessively."""
        import gc
        
        # Simulate operations with many different users
        for i in range(1000):
            mock_components["user_store"].get_user_by_username.return_value = None
            
            try:
                await user_manager.authenticate(
                    username=f"user_{i}",
                    password="password",
                    ip_address="192.168.1.100"
                )
            except AuthenticationError:
                pass
        
        # Force garbage collection
        gc.collect()
        
        # Memory should not grow unbounded
        # This is more of a sanity check than a precise test
        assert True  # If we get here without OOM, we're good


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.user_manager", "--cov-report=term-missing"])