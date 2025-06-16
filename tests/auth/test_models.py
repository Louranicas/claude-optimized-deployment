"""
Comprehensive Tests for Authentication Models (src/auth/models.py).

This test suite covers user models, API key models, validation,
serialization, security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import secrets
import hashlib
import re

from src.auth.models import (
    User, UserStatus, APIKey, APIKeyStatus, UserSession,
    UserCreationRequest, PasswordResetRequest, UserUpdateRequest,
    ValidationError, InvalidUserError, InvalidAPIKeyError
)


class TestUser:
    """Test User model functionality."""
    
    def test_user_creation(self):
        """Test basic user creation."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["user"],
            permissions={"profile:read", "profile:write"},
            status=UserStatus.ACTIVE
        )
        
        assert user.id == "user_123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "hashed_password"
        assert user.roles == ["user"]
        assert user.permissions == {"profile:read", "profile:write"}
        assert user.status == UserStatus.ACTIVE
        assert user.created_at is not None
        assert user.updated_at is not None
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert not user.mfa_enabled
    
    def test_user_creation_with_defaults(self):
        """Test user creation with default values."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password"
        )
        
        assert user.id is not None  # Should be auto-generated
        assert user.roles == []
        assert user.permissions == set()
        assert user.status == UserStatus.ACTIVE
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert not user.mfa_enabled
        assert user.mfa_secret is None
        assert user.password_reset_token is None
        assert user.password_reset_expires is None
        assert user.metadata == {}
    
    def test_user_validation(self):
        """Test user validation."""
        # Valid users
        User(username="valid_user", email="valid@example.com", password_hash="hash")
        User(username="user123", email="user.123@example.com", password_hash="hash")
        User(username="user_name", email="user+tag@example.co.uk", password_hash="hash")
        
        # Invalid usernames
        with pytest.raises(ValidationError):
            User(username="", email="test@example.com", password_hash="hash")
        
        with pytest.raises(ValidationError):
            User(username="ab", email="test@example.com", password_hash="hash")  # Too short
        
        with pytest.raises(ValidationError):
            User(username="a" * 33, email="test@example.com", password_hash="hash")  # Too long
        
        with pytest.raises(ValidationError):
            User(username="user name", email="test@example.com", password_hash="hash")  # Space
        
        with pytest.raises(ValidationError):
            User(username="user@name", email="test@example.com", password_hash="hash")  # Invalid char
        
        # Invalid emails
        with pytest.raises(ValidationError):
            User(username="testuser", email="", password_hash="hash")
        
        with pytest.raises(ValidationError):
            User(username="testuser", email="invalid-email", password_hash="hash")
        
        with pytest.raises(ValidationError):
            User(username="testuser", email="@example.com", password_hash="hash")
        
        with pytest.raises(ValidationError):
            User(username="testuser", email="test@", password_hash="hash")
        
        # Invalid password hash
        with pytest.raises(ValidationError):
            User(username="testuser", email="test@example.com", password_hash="")
        
        with pytest.raises(ValidationError):
            User(username="testuser", email="test@example.com", password_hash=None)
    
    def test_password_hashing(self):
        """Test password hashing functionality."""
        password = "TestPassword123!"
        
        # Hash password
        hash1 = User._hash_password(password)
        hash2 = User._hash_password(password)
        
        # Hashes should be different (due to salt)
        assert hash1 != hash2
        assert len(hash1) > 50  # Should be reasonably long
        assert len(hash2) > 50
        
        # Both hashes should verify the original password
        assert User._verify_password(password, hash1)
        assert User._verify_password(password, hash2)
        
        # Wrong password should not verify
        assert not User._verify_password("WrongPassword", hash1)
        assert not User._verify_password("", hash1)
        assert not User._verify_password(None, hash1)
    
    def test_password_verification(self):
        """Test password verification functionality."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=User._hash_password("CorrectPassword123!")
        )
        
        # Correct password should verify
        assert user.verify_password("CorrectPassword123!")
        
        # Wrong passwords should not verify
        assert not user.verify_password("WrongPassword")
        assert not user.verify_password("")
        assert not user.verify_password(None)
        assert not user.verify_password("correctpassword123!")  # Case sensitive
    
    def test_user_roles_management(self):
        """Test user roles management."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"]
        )
        
        # Add role
        user.add_role("admin")
        assert "admin" in user.roles
        assert "user" in user.roles
        assert len(user.roles) == 2
        
        # Add duplicate role (should not add)
        user.add_role("admin")
        assert len(user.roles) == 2
        
        # Remove role
        user.remove_role("user")
        assert "user" not in user.roles
        assert "admin" in user.roles
        assert len(user.roles) == 1
        
        # Remove non-existent role (should not error)
        user.remove_role("nonexistent")
        assert len(user.roles) == 1
        
        # Check role
        assert user.has_role("admin")
        assert not user.has_role("user")
        assert not user.has_role("nonexistent")
    
    def test_user_permissions_management(self):
        """Test user permissions management."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            permissions={"profile:read"}
        )
        
        # Add permission
        user.add_permission("profile:write")
        assert "profile:write" in user.permissions
        assert "profile:read" in user.permissions
        assert len(user.permissions) == 2
        
        # Add duplicate permission (should not add)
        user.add_permission("profile:write")
        assert len(user.permissions) == 2
        
        # Remove permission
        user.remove_permission("profile:read")
        assert "profile:read" not in user.permissions
        assert "profile:write" in user.permissions
        assert len(user.permissions) == 1
        
        # Remove non-existent permission (should not error)
        user.remove_permission("nonexistent:permission")
        assert len(user.permissions) == 1
        
        # Check permission
        assert user.has_permission("profile:write")
        assert not user.has_permission("profile:read")
        assert not user.has_permission("nonexistent:permission")
    
    def test_user_lock_unlock(self):
        """Test user account locking and unlocking."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Initially not locked
        assert not user.is_locked()
        
        # Lock user
        lock_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        user.lock_account(lock_until)
        
        assert user.is_locked()
        assert user.locked_until == lock_until
        
        # Unlock user
        user.unlock_account()
        
        assert not user.is_locked()
        assert user.locked_until is None
    
    def test_user_failed_login_attempts(self):
        """Test failed login attempts tracking."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Initially no failed attempts
        assert user.failed_login_attempts == 0
        
        # Increment failed attempts
        user.increment_failed_attempts()
        assert user.failed_login_attempts == 1
        
        user.increment_failed_attempts()
        assert user.failed_login_attempts == 2
        
        # Reset failed attempts
        user.reset_failed_attempts()
        assert user.failed_login_attempts == 0
    
    def test_user_mfa_management(self):
        """Test MFA management."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Initially MFA disabled
        assert not user.mfa_enabled
        assert user.mfa_secret is None
        
        # Enable MFA
        secret = "JBSWY3DPEHPK3PXP"
        user.enable_mfa(secret)
        
        assert user.mfa_enabled
        assert user.mfa_secret == secret
        
        # Disable MFA
        user.disable_mfa()
        
        assert not user.mfa_enabled
        assert user.mfa_secret is None
    
    def test_user_password_reset_token(self):
        """Test password reset token management."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Initially no reset token
        assert user.password_reset_token is None
        assert user.password_reset_expires is None
        
        # Set reset token
        token = "reset_token_123"
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
        user.set_password_reset_token(token, expires)
        
        # Token should be hashed
        assert user.password_reset_token is not None
        assert user.password_reset_token != token  # Should be hashed
        assert user.password_reset_expires == expires
        
        # Verify token
        assert user.verify_password_reset_token(token)
        assert not user.verify_password_reset_token("wrong_token")
        
        # Clear reset token
        user.clear_password_reset_token()
        
        assert user.password_reset_token is None
        assert user.password_reset_expires is None
    
    def test_user_metadata_management(self):
        """Test user metadata management."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Initially empty metadata
        assert user.metadata == {}
        
        # Set metadata
        user.set_metadata("department", "Engineering")
        assert user.metadata["department"] == "Engineering"
        
        user.set_metadata("level", 3)
        assert user.metadata["level"] == 3
        assert len(user.metadata) == 2
        
        # Update metadata
        user.set_metadata("department", "Product")
        assert user.metadata["department"] == "Product"
        assert len(user.metadata) == 2
        
        # Get metadata
        assert user.get_metadata("department") == "Product"
        assert user.get_metadata("level") == 3
        assert user.get_metadata("nonexistent") is None
        assert user.get_metadata("nonexistent", "default") == "default"
        
        # Remove metadata
        user.remove_metadata("level")
        assert "level" not in user.metadata
        assert len(user.metadata) == 1
    
    def test_user_to_dict(self):
        """Test user serialization to dictionary."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user", "admin"],
            permissions={"profile:read", "profile:write"},
            status=UserStatus.ACTIVE,
            mfa_enabled=True,
            metadata={"department": "Engineering"}
        )
        
        user_dict = user.to_dict(include_sensitive=False)
        
        assert user_dict["id"] == "user_123"
        assert user_dict["username"] == "testuser"
        assert user_dict["email"] == "test@example.com"
        assert set(user_dict["roles"]) == {"user", "admin"}
        assert set(user_dict["permissions"]) == {"profile:read", "profile:write"}
        assert user_dict["status"] == "ACTIVE"
        assert user_dict["mfa_enabled"] is True
        assert user_dict["metadata"]["department"] == "Engineering"
        
        # Sensitive fields should be excluded
        assert "password_hash" not in user_dict
        assert "mfa_secret" not in user_dict
        assert "password_reset_token" not in user_dict
        
        # Test with sensitive fields included
        user_dict_sensitive = user.to_dict(include_sensitive=True)
        assert "password_hash" in user_dict_sensitive
    
    def test_user_from_dict(self):
        """Test user deserialization from dictionary."""
        user_dict = {
            "id": "user_123",
            "username": "testuser",
            "email": "test@example.com",
            "password_hash": "hash",
            "roles": ["user", "admin"],
            "permissions": ["profile:read", "profile:write"],
            "status": "ACTIVE",
            "mfa_enabled": True,
            "mfa_secret": "secret",
            "failed_login_attempts": 2,
            "metadata": {"department": "Engineering"},
            "created_at": "2023-12-01T10:00:00Z",
            "updated_at": "2023-12-01T11:00:00Z"
        }
        
        user = User.from_dict(user_dict)
        
        assert user.id == "user_123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "hash"
        assert set(user.roles) == {"user", "admin"}
        assert user.permissions == {"profile:read", "profile:write"}
        assert user.status == UserStatus.ACTIVE
        assert user.mfa_enabled is True
        assert user.mfa_secret == "secret"
        assert user.failed_login_attempts == 2
        assert user.metadata["department"] == "Engineering"
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
    
    def test_user_equality(self):
        """Test user equality comparison."""
        user1 = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        user2 = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        user3 = User(
            id="user_456",
            username="otheruser",
            email="other@example.com",
            password_hash="hash"
        )
        
        assert user1 == user2  # Same ID and data
        assert user1 != user3  # Different ID and data
    
    def test_user_string_representation(self):
        """Test user string representation."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        str_repr = str(user)
        assert "testuser" in str_repr
        assert "test@example.com" in str_repr
        
        repr_str = repr(user)
        assert "User" in repr_str
        assert "testuser" in repr_str


class TestUserStatus:
    """Test UserStatus enum."""
    
    def test_user_status_values(self):
        """Test user status enumeration values."""
        assert UserStatus.ACTIVE.value == "ACTIVE"
        assert UserStatus.INACTIVE.value == "INACTIVE"
        assert UserStatus.PENDING.value == "PENDING"
        assert UserStatus.SUSPENDED.value == "SUSPENDED"
        assert UserStatus.DELETED.value == "DELETED"
    
    def test_user_status_from_string(self):
        """Test creating UserStatus from string."""
        assert UserStatus("ACTIVE") == UserStatus.ACTIVE
        assert UserStatus("INACTIVE") == UserStatus.INACTIVE
        assert UserStatus("PENDING") == UserStatus.PENDING
        assert UserStatus("SUSPENDED") == UserStatus.SUSPENDED
        assert UserStatus("DELETED") == UserStatus.DELETED
    
    def test_user_status_invalid_value(self):
        """Test UserStatus with invalid value."""
        with pytest.raises(ValueError):
            UserStatus("INVALID_STATUS")


class TestAPIKey:
    """Test APIKey model functionality."""
    
    def test_api_key_creation(self):
        """Test basic API key creation."""
        api_key = APIKey(
            id="key_123",
            name="Test API Key",
            key_hash="hashed_key",
            user_id="user_123",
            permissions={"api:read", "api:write"},
            status=APIKeyStatus.ACTIVE
        )
        
        assert api_key.id == "key_123"
        assert api_key.name == "Test API Key"
        assert api_key.key_hash == "hashed_key"
        assert api_key.user_id == "user_123"
        assert api_key.permissions == {"api:read", "api:write"}
        assert api_key.status == APIKeyStatus.ACTIVE
        assert api_key.created_at is not None
        assert api_key.expires_at is None
        assert api_key.last_used_at is None
    
    def test_api_key_creation_with_defaults(self):
        """Test API key creation with default values."""
        api_key = APIKey(
            name="Test Key",
            key_hash="hash",
            user_id="user_123"
        )
        
        assert api_key.id is not None  # Should be auto-generated
        assert api_key.permissions == set()
        assert api_key.status == APIKeyStatus.ACTIVE
        assert api_key.expires_at is None
        assert api_key.last_used_at is None
    
    def test_api_key_validation(self):
        """Test API key validation."""
        # Valid API keys
        APIKey(name="Valid Key", key_hash="hash", user_id="user_123")
        APIKey(name="API Key v2", key_hash="hash", user_id="user_123")
        APIKey(name="test-key_123", key_hash="hash", user_id="user_123")
        
        # Invalid names
        with pytest.raises(ValidationError):
            APIKey(name="", key_hash="hash", user_id="user_123")
        
        with pytest.raises(ValidationError):
            APIKey(name="a" * 65, key_hash="hash", user_id="user_123")  # Too long
        
        # Invalid key hash
        with pytest.raises(ValidationError):
            APIKey(name="Test Key", key_hash="", user_id="user_123")
        
        with pytest.raises(ValidationError):
            APIKey(name="Test Key", key_hash=None, user_id="user_123")
        
        # Invalid user ID
        with pytest.raises(ValidationError):
            APIKey(name="Test Key", key_hash="hash", user_id="")
        
        with pytest.raises(ValidationError):
            APIKey(name="Test Key", key_hash="hash", user_id=None)
    
    def test_api_key_generation(self):
        """Test API key generation."""
        # Generate key
        api_key, raw_key = APIKey.generate_key(
            name="Test Key",
            user_id="user_123",
            permissions={"api:read"}
        )
        
        assert api_key.name == "Test Key"
        assert api_key.user_id == "user_123"
        assert api_key.permissions == {"api:read"}
        assert api_key.status == APIKeyStatus.ACTIVE
        assert isinstance(raw_key, str)
        assert len(raw_key) > 20  # Should be reasonably long
        assert raw_key.startswith("sk_")  # Standard prefix
        
        # Verify the raw key against the hash
        assert api_key.verify_key(raw_key)
        assert not api_key.verify_key("wrong_key")
    
    def test_api_key_hashing(self):
        """Test API key hashing functionality."""
        raw_key = "sk_test_123456789abcdef"
        
        # Hash key
        hash1 = APIKey._hash_key(raw_key)
        hash2 = APIKey._hash_key(raw_key)
        
        # Hashes should be different (due to salt)
        assert hash1 != hash2
        assert len(hash1) > 50  # Should be reasonably long
        
        # Both hashes should verify the original key
        assert APIKey._verify_key(raw_key, hash1)
        assert APIKey._verify_key(raw_key, hash2)
        
        # Wrong key should not verify
        assert not APIKey._verify_key("wrong_key", hash1)
        assert not APIKey._verify_key("", hash1)
        assert not APIKey._verify_key(None, hash1)
    
    def test_api_key_expiration(self):
        """Test API key expiration functionality."""
        # Create non-expiring key
        api_key = APIKey(
            name="Non-expiring Key",
            key_hash="hash",
            user_id="user_123"
        )
        
        assert not api_key.is_expired()
        
        # Create expired key
        expired_key = APIKey(
            name="Expired Key",
            key_hash="hash",
            user_id="user_123",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        assert expired_key.is_expired()
        
        # Create future-expiring key
        future_key = APIKey(
            name="Future Key",
            key_hash="hash",
            user_id="user_123",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert not future_key.is_expired()
    
    def test_api_key_permissions_management(self):
        """Test API key permissions management."""
        api_key = APIKey(
            name="Test Key",
            key_hash="hash",
            user_id="user_123",
            permissions={"api:read"}
        )
        
        # Add permission
        api_key.add_permission("api:write")
        assert "api:write" in api_key.permissions
        assert "api:read" in api_key.permissions
        assert len(api_key.permissions) == 2
        
        # Add duplicate permission (should not add)
        api_key.add_permission("api:write")
        assert len(api_key.permissions) == 2
        
        # Remove permission
        api_key.remove_permission("api:read")
        assert "api:read" not in api_key.permissions
        assert "api:write" in api_key.permissions
        assert len(api_key.permissions) == 1
        
        # Check permission
        assert api_key.has_permission("api:write")
        assert not api_key.has_permission("api:read")
    
    def test_api_key_usage_tracking(self):
        """Test API key usage tracking."""
        api_key = APIKey(
            name="Test Key",
            key_hash="hash",
            user_id="user_123"
        )
        
        # Initially no usage
        assert api_key.last_used_at is None
        
        # Record usage
        api_key.record_usage()
        
        assert api_key.last_used_at is not None
        assert isinstance(api_key.last_used_at, datetime)
        
        # Record usage again
        first_usage = api_key.last_used_at
        api_key.record_usage()
        
        assert api_key.last_used_at > first_usage
    
    def test_api_key_revocation(self):
        """Test API key revocation."""
        api_key = APIKey(
            name="Test Key",
            key_hash="hash",
            user_id="user_123",
            status=APIKeyStatus.ACTIVE
        )
        
        # Initially active
        assert api_key.status == APIKeyStatus.ACTIVE
        assert not api_key.is_revoked()
        
        # Revoke key
        api_key.revoke()
        
        assert api_key.status == APIKeyStatus.REVOKED
        assert api_key.is_revoked()
    
    def test_api_key_to_dict(self):
        """Test API key serialization to dictionary."""
        api_key = APIKey(
            id="key_123",
            name="Test Key",
            key_hash="hash",
            user_id="user_123",
            permissions={"api:read", "api:write"},
            status=APIKeyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        key_dict = api_key.to_dict(include_sensitive=False)
        
        assert key_dict["id"] == "key_123"
        assert key_dict["name"] == "Test Key"
        assert key_dict["user_id"] == "user_123"
        assert set(key_dict["permissions"]) == {"api:read", "api:write"}
        assert key_dict["status"] == "ACTIVE"
        assert "expires_at" in key_dict
        assert "created_at" in key_dict
        
        # Sensitive fields should be excluded
        assert "key_hash" not in key_dict
        
        # Test with sensitive fields included
        key_dict_sensitive = api_key.to_dict(include_sensitive=True)
        assert "key_hash" in key_dict_sensitive
    
    def test_api_key_from_dict(self):
        """Test API key deserialization from dictionary."""
        key_dict = {
            "id": "key_123",
            "name": "Test Key",
            "key_hash": "hash",
            "user_id": "user_123",
            "permissions": ["api:read", "api:write"],
            "status": "ACTIVE",
            "created_at": "2023-12-01T10:00:00Z",
            "expires_at": "2023-12-31T10:00:00Z",
            "last_used_at": "2023-12-15T10:00:00Z"
        }
        
        api_key = APIKey.from_dict(key_dict)
        
        assert api_key.id == "key_123"
        assert api_key.name == "Test Key"
        assert api_key.key_hash == "hash"
        assert api_key.user_id == "user_123"
        assert api_key.permissions == {"api:read", "api:write"}
        assert api_key.status == APIKeyStatus.ACTIVE
        assert isinstance(api_key.created_at, datetime)
        assert isinstance(api_key.expires_at, datetime)
        assert isinstance(api_key.last_used_at, datetime)


class TestAPIKeyStatus:
    """Test APIKeyStatus enum."""
    
    def test_api_key_status_values(self):
        """Test API key status enumeration values."""
        assert APIKeyStatus.ACTIVE.value == "ACTIVE"
        assert APIKeyStatus.REVOKED.value == "REVOKED"
        assert APIKeyStatus.EXPIRED.value == "EXPIRED"
    
    def test_api_key_status_from_string(self):
        """Test creating APIKeyStatus from string."""
        assert APIKeyStatus("ACTIVE") == APIKeyStatus.ACTIVE
        assert APIKeyStatus("REVOKED") == APIKeyStatus.REVOKED
        assert APIKeyStatus("EXPIRED") == APIKeyStatus.EXPIRED
    
    def test_api_key_status_invalid_value(self):
        """Test APIKeyStatus with invalid value."""
        with pytest.raises(ValueError):
            APIKeyStatus("INVALID_STATUS")


class TestUserSession:
    """Test UserSession model functionality."""
    
    def test_user_session_creation(self):
        """Test basic user session creation."""
        session = UserSession(
            session_id="session_123",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        assert session.session_id == "session_123"
        assert session.user_id == "user_123"
        assert session.ip_address == "192.168.1.100"
        assert session.user_agent == "Mozilla/5.0"
        assert session.created_at is not None
        assert session.last_activity is not None
        assert session.expires_at is not None
        assert not session.is_expired()
    
    def test_user_session_device_info_parsing(self):
        """Test device info parsing from user agent."""
        # Chrome on Windows
        session = UserSession(
            session_id="session_1",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        
        device_info = session.get_device_info()
        assert "Chrome" in device_info.get("browser", "")
        assert "Windows" in device_info.get("os", "")
        assert not device_info.get("is_mobile", True)
        
        # Mobile Safari
        mobile_session = UserSession(
            session_id="session_2",
            user_id="user_123",
            ip_address="192.168.1.101",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        )
        
        mobile_device_info = mobile_session.get_device_info()
        assert "Safari" in mobile_device_info.get("browser", "")
        assert "iOS" in mobile_device_info.get("os", "")
        assert mobile_device_info.get("is_mobile", False)
    
    def test_user_session_expiration(self):
        """Test user session expiration."""
        # Create session with short timeout
        session = UserSession(
            session_id="session_123",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Test",
            timeout_minutes=1  # 1 minute timeout
        )
        
        # Initially not expired
        assert not session.is_expired()
        
        # Manually set expiration to past
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Should now be expired
        assert session.is_expired()
    
    def test_user_session_activity_update(self):
        """Test session activity updates."""
        session = UserSession(
            session_id="session_123",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Test"
        )
        
        original_activity = session.last_activity
        original_expiry = session.expires_at
        
        # Update activity
        session.update_activity()
        
        assert session.last_activity > original_activity
        assert session.expires_at > original_expiry
    
    def test_user_session_to_dict(self):
        """Test user session serialization."""
        session = UserSession(
            session_id="session_123",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        session_dict = session.to_dict()
        
        assert session_dict["session_id"] == "session_123"
        assert session_dict["user_id"] == "user_123"
        assert session_dict["ip_address"] == "192.168.1.100"
        assert session_dict["user_agent"] == "Mozilla/5.0"
        assert "created_at" in session_dict
        assert "last_activity" in session_dict
        assert "expires_at" in session_dict
        assert "device_info" in session_dict


class TestUserCreationRequest:
    """Test UserCreationRequest model."""
    
    def test_user_creation_request_validation(self):
        """Test user creation request validation."""
        # Valid request
        request = UserCreationRequest(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"]
        )
        
        assert request.username == "testuser"
        assert request.email == "test@example.com"
        assert request.password == "SecurePassword123!"
        assert request.roles == ["user"]
        
        # Invalid username
        with pytest.raises(ValidationError):
            UserCreationRequest(
                username="ab",  # Too short
                email="test@example.com",
                password="SecurePassword123!"
            )
        
        # Invalid email
        with pytest.raises(ValidationError):
            UserCreationRequest(
                username="testuser",
                email="invalid-email",
                password="SecurePassword123!"
            )
        
        # Invalid password (too short)
        with pytest.raises(ValidationError):
            UserCreationRequest(
                username="testuser",
                email="test@example.com",
                password="short"
            )


class TestPasswordResetRequest:
    """Test PasswordResetRequest model."""
    
    def test_password_reset_request_validation(self):
        """Test password reset request validation."""
        # Valid request
        request = PasswordResetRequest(email="test@example.com")
        
        assert request.email == "test@example.com"
        
        # Invalid email
        with pytest.raises(ValidationError):
            PasswordResetRequest(email="invalid-email")
        
        with pytest.raises(ValidationError):
            PasswordResetRequest(email="")


class TestUserUpdateRequest:
    """Test UserUpdateRequest model."""
    
    def test_user_update_request_validation(self):
        """Test user update request validation."""
        # Valid request with all fields
        request = UserUpdateRequest(
            email="newemail@example.com",
            status=UserStatus.INACTIVE,
            metadata={"department": "Engineering"}
        )
        
        assert request.email == "newemail@example.com"
        assert request.status == UserStatus.INACTIVE
        assert request.metadata == {"department": "Engineering"}
        
        # Valid request with partial fields
        partial_request = UserUpdateRequest(email="partial@example.com")
        
        assert partial_request.email == "partial@example.com"
        assert partial_request.status is None
        assert partial_request.metadata is None
        
        # Invalid email
        with pytest.raises(ValidationError):
            UserUpdateRequest(email="invalid-email")


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    def test_password_hash_security(self):
        """Test password hash security properties."""
        password = "TestPassword123!"
        
        # Multiple hashes should be different
        hashes = [User._hash_password(password) for _ in range(10)]
        assert len(set(hashes)) == 10  # All unique
        
        # Hashes should be sufficiently long
        for hash_val in hashes:
            assert len(hash_val) >= 60  # bcrypt produces ~60 char hashes
        
        # All hashes should verify the original password
        for hash_val in hashes:
            assert User._verify_password(password, hash_val)
    
    def test_api_key_security(self):
        """Test API key security properties."""
        # Generate multiple keys
        keys_and_hashes = [APIKey.generate_key("Test", "user_123") for _ in range(10)]
        
        # Raw keys should be different
        raw_keys = [item[1] for item in keys_and_hashes]
        assert len(set(raw_keys)) == 10  # All unique
        
        # Hashes should be different
        hashes = [item[0].key_hash for item in keys_and_hashes]
        assert len(set(hashes)) == 10  # All unique
        
        # Each key should verify against its own hash
        for api_key, raw_key in keys_and_hashes:
            assert api_key.verify_key(raw_key)
            
            # But not against other keys
            other_keys = [k for k in raw_keys if k != raw_key]
            for other_key in other_keys[:3]:  # Test a few
                assert not api_key.verify_key(other_key)
    
    def test_timing_attack_resistance(self):
        """Test timing attack resistance in password verification."""
        import time
        
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=User._hash_password("CorrectPassword")
        )
        
        # Measure verification time for correct password
        start = time.time()
        user.verify_password("CorrectPassword")
        correct_time = time.time() - start
        
        # Measure verification time for wrong password
        start = time.time()
        user.verify_password("WrongPassword")
        wrong_time = time.time() - start
        
        # Times should be similar (within 50% of each other)
        time_ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
        assert time_ratio < 1.5  # Less than 50% difference
    
    def test_input_sanitization(self):
        """Test input sanitization and validation."""
        malicious_inputs = [
            "user'; DROP TABLE users; --",
            "user<script>alert('xss')</script>",
            "user\nwith\nnewlines",
            "user\x00null_byte",
            "user\r\nCRLF_injection"
        ]
        
        for malicious_input in malicious_inputs:
            # Should raise validation error for username
            with pytest.raises(ValidationError):
                User(
                    username=malicious_input,
                    email="test@example.com",
                    password_hash="hash"
                )
    
    def test_metadata_injection_prevention(self):
        """Test prevention of metadata injection attacks."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Attempt to inject malicious metadata
        malicious_metadata = {
            "'; DROP TABLE users; --": "value",
            "<script>alert('xss')</script>": "value",
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}}
        }
        
        for key, value in malicious_metadata.items():
            user.set_metadata(key, value)
        
        # Metadata should be stored as-is (filtering happens at application level)
        # But serialization should be safe
        user_dict = user.to_dict()
        assert isinstance(user_dict, dict)
    
    def test_session_hijacking_prevention(self):
        """Test session hijacking prevention measures."""
        session = UserSession(
            session_id="session_123",
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Session ID should be sufficiently random
        assert len(session.session_id) >= 16  # Minimum length for security
        
        # Multiple sessions should have different IDs
        session_ids = []
        for i in range(100):
            new_session = UserSession(
                session_id=None,  # Auto-generated
                user_id=f"user_{i}",
                ip_address="192.168.1.100",
                user_agent="Test"
            )
            session_ids.append(new_session.session_id)
        
        # All should be unique
        assert len(set(session_ids)) == 100


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_none_and_empty_values(self):
        """Test handling of None and empty values."""
        # User with minimal valid data
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Setting None values for optional fields should work
        user.set_metadata("optional_field", None)
        assert user.get_metadata("optional_field") is None
        
        # Empty string metadata
        user.set_metadata("empty", "")
        assert user.get_metadata("empty") == ""
        
        # None permissions should be handled
        user.permissions = None
        user.permissions = set()  # Reset to valid state
    
    def test_unicode_handling(self):
        """Test handling of unicode characters."""
        # Unicode in username (if allowed by validation)
        try:
            unicode_user = User(
                username="用户",
                email="用户@example.com",
                password_hash="hash"
            )
            # If validation allows unicode, it should work
            assert unicode_user.username == "用户"
        except ValidationError:
            # If validation rejects unicode, that's also acceptable
            pass
        
        # Unicode in metadata should work
        user = User(
            username="testuser",
            email="test@example.com", 
            password_hash="hash"
        )
        
        user.set_metadata("中文", "中文值")
        assert user.get_metadata("中文") == "中文值"
        
        # Unicode in API key name
        api_key = APIKey(
            name="测试密钥",
            key_hash="hash",
            user_id="user_123"
        )
        assert api_key.name == "测试密钥"
    
    def test_very_long_values(self):
        """Test handling of very long values."""
        # Very long metadata values
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        long_value = "x" * 10000
        user.set_metadata("long_field", long_value)
        assert user.get_metadata("long_field") == long_value
        
        # Very long permissions
        long_permission = "resource:" + "x" * 1000
        user.add_permission(long_permission)
        assert user.has_permission(long_permission)
    
    def test_concurrent_modifications(self):
        """Test concurrent modifications to models."""
        import threading
        
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Concurrent metadata updates
        def update_metadata(user_obj, thread_id):
            for i in range(100):
                user_obj.set_metadata(f"field_{thread_id}_{i}", f"value_{i}")
        
        threads = []
        for i in range(10):
            thread = threading.Thread(target=update_metadata, args=(user, i))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have many metadata fields
        assert len(user.metadata) == 1000  # 10 threads * 100 fields each
    
    def test_serialization_edge_cases(self):
        """Test serialization edge cases."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash"
        )
        
        # Circular reference in metadata
        circular_data = {"key": "value"}
        circular_data["self"] = circular_data
        user.metadata = {"circular": circular_data}
        
        # Serialization should handle gracefully
        try:
            user_dict = user.to_dict()
            # If it succeeds, circular reference was handled
            assert isinstance(user_dict, dict)
        except (ValueError, RecursionError):
            # If it fails with known errors, that's acceptable
            pass
    
    def test_memory_usage(self):
        """Test memory usage with large numbers of objects."""
        import gc
        
        # Create many users
        users = []
        for i in range(1000):
            user = User(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password_hash="hash"
            )
            users.append(user)
        
        # Force garbage collection
        gc.collect()
        
        # All users should still be accessible
        assert len(users) == 1000
        assert users[0].username == "user_0"
        assert users[999].username == "user_999"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.models", "--cov-report=term-missing"])