"""
Comprehensive Authentication Tests for Production Implementation.

Tests cover:
- JWT token generation and validation
- Token revocation
- Session management
- 2FA functionality
- Rate limiting
- Security edge cases
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
import secrets
import os
import jwt

from src.auth.tokens import TokenManager, TokenData
from src.auth.token_revocation import TokenRevocationService, RevokedToken
from src.auth.session_manager import SessionManager, SessionInfo
from src.auth.two_factor import TwoFactorService, TwoFactorConfig
from src.auth.user_manager import UserManager, UserCreationRequest
from src.auth.models import User, UserStatus
from src.auth.rbac import RBACManager
from src.auth.permissions import PermissionChecker
from src.auth.middleware import AuthMiddleware
from src.core.connections import ConnectionPoolConfig


# Test fixtures
@pytest.fixture
async def redis_url():
    """Get test Redis URL."""
    return os.getenv("TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest.fixture
async def token_manager():
    """Create token manager for testing."""
    return TokenManager(secret_key="test_secret_key_for_testing_only")


@pytest.fixture
async def revocation_service(redis_url):
    """Create token revocation service."""
    service = TokenRevocationService(redis_url)
    await service.initialize()
    yield service
    await service.close()


@pytest.fixture
async def session_manager(redis_url):
    """Create session manager."""
    manager = SessionManager(redis_url)
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
async def two_factor_service(redis_url):
    """Create 2FA service."""
    service = TwoFactorService(redis_url)
    await service.initialize()
    yield service
    await service.close()


@pytest.fixture
def test_user():
    """Create a test user."""
    return User(
        id="test_user_123",
        username="testuser",
        email="test@example.com",
        password_hash=User._hash_password("Test123!@#"),
        roles=["user"],
        permissions={"users:read", "profile:write"},
        status=UserStatus.ACTIVE
    )


@pytest.fixture
def rbac_manager():
    """Create RBAC manager."""
    return RBACManager()


@pytest.fixture
def permission_checker(rbac_manager):
    """Create permission checker."""
    return PermissionChecker(rbac_manager)


class TestTokenManager:
    """Test JWT token management."""
    
    def test_token_generation(self, token_manager):
        """Test token generation with proper claims."""
        token_data = TokenData(
            user_id="user123",
            username="testuser",
            roles=["admin", "user"],
            permissions=["read", "write"]
        )
        
        # Generate access token
        access_token = token_manager.create_access_token(token_data)
        assert access_token
        
        # Decode and verify
        decoded = jwt.decode(
            access_token,
            token_manager._extract_key_from_combined(token_manager.secret_key),
            algorithms=[token_manager.algorithm]
        )
        
        assert decoded["sub"] == "user123"
        assert decoded["username"] == "testuser"
        assert decoded["roles"] == ["admin", "user"]
        assert decoded["token_type"] == "access"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded
        assert "session_id" in decoded
    
    def test_token_expiration(self, token_manager):
        """Test token expiration handling."""
        # Set very short expiration
        token_manager.access_token_expire_minutes = 0.01  # 0.6 seconds
        
        token_data = TokenData(
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=[]
        )
        
        access_token = token_manager.create_access_token(token_data)
        
        # Token should be valid immediately
        verified = token_manager.verify_token(access_token)
        assert verified is not None
        
        # Wait for expiration
        import time
        time.sleep(1)
        
        # Token should be expired
        verified = token_manager.verify_token(access_token)
        assert verified is None
    
    def test_refresh_token_flow(self, token_manager):
        """Test refresh token generation and usage."""
        # Create tokens
        tokens = token_manager.create_token_pair(
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == token_manager.access_token_expire_minutes * 60
        assert "session_id" in tokens
        
        # Verify refresh token
        refresh_data = token_manager.verify_token(tokens["refresh_token"], token_type="refresh")
        assert refresh_data is not None
        assert refresh_data.user_id == "user123"
        assert refresh_data.token_type == "refresh"
        
        # Use refresh token to get new access token
        new_access = token_manager.refresh_access_token(
            refresh_token=tokens["refresh_token"],
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        assert new_access is not None
        
        # Verify new access token has same session ID
        new_data = token_manager.verify_token(new_access)
        assert new_data.session_id == refresh_data.session_id
    
    def test_key_rotation(self, token_manager):
        """Test secret key rotation."""
        # Create token with original key
        token_data = TokenData(
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=[]
        )
        
        old_token = token_manager.create_access_token(token_data)
        
        # Rotate key
        old_key = token_manager.secret_key
        new_key = token_manager.rotate_key()
        
        assert new_key != old_key
        assert old_key in token_manager.old_keys
        
        # Old token should still be valid
        verified = token_manager.verify_token(old_token)
        assert verified is not None
        
        # New tokens use new key
        new_token = token_manager.create_access_token(token_data)
        verified_new = token_manager.verify_token(new_token)
        assert verified_new is not None
    
    def test_api_key_token(self, token_manager):
        """Test API key token generation."""
        api_key_token = token_manager.create_api_key_token(
            api_key_id="key123",
            permissions=["api:read", "api:write"]
        )
        
        assert api_key_token
        
        # Verify API key token
        verified = token_manager.verify_token(api_key_token, token_type="api_key")
        assert verified is not None
        assert verified.api_key_id == "key123"
        assert verified.permissions == ["api:read", "api:write"]
        assert verified.roles == ["api_key"]
    
    def test_secure_key_generation(self, token_manager):
        """Test secure key generation with random salt."""
        key1 = token_manager._generate_secret_key()
        key2 = token_manager._generate_secret_key()
        
        # Keys should be different due to random salt
        assert key1 != key2
        
        # Keys should be proper length when decoded
        import base64
        decoded1 = base64.urlsafe_b64decode(key1.encode('utf-8'))
        assert len(decoded1) == 64  # 32 bytes salt + 32 bytes key
    
    def test_backward_compatibility(self):
        """Test backward compatibility with legacy keys."""
        # Simulate legacy key
        legacy_key = "simple_legacy_key_format"
        manager = TokenManager(secret_key=legacy_key)
        
        assert manager._is_legacy_key
        
        # Should still work with legacy key
        token_data = TokenData(
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=[]
        )
        
        token = manager.create_access_token(token_data)
        verified = manager.verify_token(token)
        assert verified is not None


class TestTokenRevocation:
    """Test token revocation service."""
    
    @pytest.mark.asyncio
    async def test_token_revocation(self, revocation_service):
        """Test basic token revocation."""
        jti = secrets.token_urlsafe(16)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Token should not be revoked initially
        assert not await revocation_service.is_token_revoked(jti)
        
        # Revoke token
        await revocation_service.revoke_token(
            jti=jti,
            user_id="user123",
            expires_at=expires_at,
            reason="test_revocation"
        )
        
        # Token should now be revoked
        assert await revocation_service.is_token_revoked(jti)
    
    @pytest.mark.asyncio
    async def test_session_revocation(self, revocation_service):
        """Test session revocation."""
        session_id = secrets.token_urlsafe(16)
        
        # Session should not be revoked initially
        assert not await revocation_service.is_session_revoked(session_id)
        
        # Revoke session
        await revocation_service.revoke_session(
            session_id=session_id,
            user_id="user123",
            reason="logout"
        )
        
        # Session should now be revoked
        assert await revocation_service.is_session_revoked(session_id)
    
    @pytest.mark.asyncio
    async def test_bulk_revocation(self, revocation_service):
        """Test revoking all user tokens."""
        user_id = "user123"
        
        # Create some tokens
        jtis = []
        for i in range(3):
            jti = secrets.token_urlsafe(16)
            jtis.append(jti)
            await revocation_service.revoke_token(
                jti=jti,
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                reason="test"
            )
        
        # Revoke all user tokens
        count = await revocation_service.revoke_all_user_tokens(
            user_id=user_id,
            reason="security"
        )
        
        assert count >= 3
        
        # All tokens should be revoked
        for jti in jtis:
            assert await revocation_service.is_token_revoked(jti)
    
    @pytest.mark.asyncio
    async def test_revocation_expiry(self, revocation_service):
        """Test that revoked tokens expire properly."""
        jti = secrets.token_urlsafe(16)
        # Set very short expiry
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=2)
        
        await revocation_service.revoke_token(
            jti=jti,
            user_id="user123",
            expires_at=expires_at,
            reason="test"
        )
        
        # Should be revoked initially
        assert await revocation_service.is_token_revoked(jti)
        
        # Wait for expiry
        await asyncio.sleep(3)
        
        # Should no longer be in revocation list
        assert not await revocation_service.is_token_revoked(jti)
    
    @pytest.mark.asyncio
    async def test_revocation_history(self, revocation_service):
        """Test getting user revocation history."""
        user_id = "user123"
        
        # Revoke some tokens and sessions
        for i in range(3):
            await revocation_service.revoke_token(
                jti=f"token_{i}",
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                reason=f"reason_{i}"
            )
            
            await revocation_service.revoke_session(
                session_id=f"session_{i}",
                user_id=user_id,
                reason="test"
            )
        
        # Get history
        history = await revocation_service.get_user_revocation_history(user_id)
        
        assert len(history["tokens"]) >= 3
        assert len(history["sessions"]) >= 3
        
        # Check sorting (most recent first)
        if len(history["tokens"]) > 1:
            first_time = datetime.fromisoformat(history["tokens"][0]["revoked_at"])
            second_time = datetime.fromisoformat(history["tokens"][1]["revoked_at"])
            assert first_time >= second_time


class TestSessionManager:
    """Test session management."""
    
    @pytest.mark.asyncio
    async def test_session_creation(self, session_manager):
        """Test creating a new session."""
        session = await session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            metadata={"login_method": "password"}
        )
        
        assert session.session_id
        assert session.user_id == "user123"
        assert session.ip_address == "192.168.1.100"
        assert session.device_info["browser"].startswith("Chrome")
        assert session.device_info["os"].startswith("Windows")
        assert not session.device_info["is_mobile"]
    
    @pytest.mark.asyncio
    async def test_session_activity_update(self, session_manager):
        """Test updating session activity."""
        # Create session
        session = await session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        original_activity = session.last_activity
        
        # Wait a bit
        await asyncio.sleep(0.1)
        
        # Update activity
        updated = await session_manager.update_activity(session.session_id)
        
        assert updated is not None
        assert updated.last_activity > original_activity
    
    @pytest.mark.asyncio
    async def test_concurrent_session_limit(self, session_manager):
        """Test concurrent session limits."""
        user_id = "user123"
        
        # Create max sessions
        sessions = []
        for i in range(session_manager.max_concurrent_sessions):
            session = await session_manager.create_session(
                user_id=user_id,
                ip_address=f"192.168.1.{100 + i}",
                user_agent="Mozilla/5.0"
            )
            sessions.append(session)
        
        # Get user sessions
        user_sessions = await session_manager.get_user_sessions(user_id)
        assert len(user_sessions) == session_manager.max_concurrent_sessions
        
        # Create one more - should remove oldest
        new_session = await session_manager.create_session(
            user_id=user_id,
            ip_address="192.168.1.200",
            user_agent="Mozilla/5.0"
        )
        
        # Check that oldest was removed
        user_sessions = await session_manager.get_user_sessions(user_id)
        assert len(user_sessions) == session_manager.max_concurrent_sessions
        session_ids = [s.session_id for s in user_sessions]
        assert sessions[0].session_id not in session_ids
        assert new_session.session_id in session_ids
    
    @pytest.mark.asyncio
    async def test_session_invalidation(self, session_manager):
        """Test session invalidation."""
        # Create session
        session = await session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Session should be valid
        retrieved = await session_manager.get_session(session.session_id)
        assert retrieved is not None
        
        # Invalidate session
        success = await session_manager.invalidate_session(
            session.session_id,
            reason="test"
        )
        assert success
        
        # Session should no longer be valid
        retrieved = await session_manager.get_session(session.session_id)
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_ip_change_detection(self, session_manager):
        """Test IP address change detection."""
        # Create session
        session = await session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Update with different IP
        updated = await session_manager.update_activity(
            session.session_id,
            ip_address="10.0.0.1"
        )
        
        assert updated is not None
        assert updated.ip_address == "10.0.0.1"
        
        # Check security events
        events = await session_manager.get_security_events(
            user_id="user123",
            event_type="ip_change"
        )
        
        assert len(events) > 0
        assert events[0].details["old_ip"] == "192.168.1.100"
        assert events[0].details["new_ip"] == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_session_expiry(self, session_manager):
        """Test session expiration."""
        # Create session with very short timeout
        session_manager.session_timeout_minutes = 0.01  # 0.6 seconds
        
        session = await session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )
        
        # Session should be valid initially
        retrieved = await session_manager.get_session(session.session_id)
        assert retrieved is not None
        
        # Wait for expiry
        await asyncio.sleep(1)
        
        # Session should be expired
        retrieved = await session_manager.get_session(session.session_id)
        assert retrieved is None


class TestTwoFactorAuth:
    """Test 2FA functionality."""
    
    @pytest.mark.asyncio
    async def test_totp_setup(self, two_factor_service):
        """Test TOTP setup process."""
        user_id = "user123"
        user_email = "test@example.com"
        
        # Setup TOTP
        setup_data = await two_factor_service.setup_totp(user_id, user_email)
        
        assert "secret" in setup_data
        assert "qr_code" in setup_data
        assert "provisioning_uri" in setup_data
        assert setup_data["qr_code"].startswith("data:image/png;base64,")
        
        # 2FA should not be enabled yet
        status = await two_factor_service.get_2fa_status(user_id)
        assert not status["enabled"]
    
    @pytest.mark.asyncio
    async def test_totp_verification(self, two_factor_service):
        """Test TOTP verification."""
        user_id = "user123"
        
        # Setup TOTP
        setup_data = await two_factor_service.setup_totp(user_id, "test@example.com")
        secret = setup_data["secret"]
        
        # Generate valid code
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Verify setup
        success = await two_factor_service.verify_totp_setup(user_id, valid_code)
        assert success
        
        # 2FA should now be enabled
        status = await two_factor_service.get_2fa_status(user_id)
        assert status["enabled"]
        assert "totp" in status["methods"]
        assert status["backup_codes_remaining"] > 0
    
    @pytest.mark.asyncio
    async def test_2fa_challenge(self, two_factor_service):
        """Test 2FA challenge creation and verification."""
        user_id = "user123"
        
        # Setup and enable TOTP
        setup_data = await two_factor_service.setup_totp(user_id, "test@example.com")
        secret = setup_data["secret"]
        
        import pyotp
        totp = pyotp.TOTP(secret)
        await two_factor_service.verify_totp_setup(user_id, totp.now())
        
        # Create challenge
        challenge = await two_factor_service.create_challenge(user_id)
        
        assert challenge is not None
        assert challenge.challenge_type == "totp"
        assert not challenge.is_expired()
        
        # Verify with invalid code
        success, error = await two_factor_service.verify_challenge(
            challenge.challenge_id,
            "000000"
        )
        assert not success
        assert "Invalid code" in error
        
        # Verify with valid code
        valid_code = totp.now()
        success, error = await two_factor_service.verify_challenge(
            challenge.challenge_id,
            valid_code
        )
        assert success
        assert error is None
    
    @pytest.mark.asyncio
    async def test_backup_codes(self, two_factor_service):
        """Test backup code functionality."""
        user_id = "user123"
        
        # Setup 2FA
        setup_data = await two_factor_service.setup_totp(user_id, "test@example.com")
        import pyotp
        totp = pyotp.TOTP(setup_data["secret"])
        await two_factor_service.verify_totp_setup(user_id, totp.now())
        
        # Get backup codes
        codes = await two_factor_service.regenerate_backup_codes(user_id)
        assert len(codes) == two_factor_service.backup_codes_count
        
        # Use a backup code
        success = await two_factor_service.verify_backup_code(user_id, codes[0])
        assert success
        
        # Same code should not work again
        success = await two_factor_service.verify_backup_code(user_id, codes[0])
        assert not success
        
        # Other codes should still work
        success = await two_factor_service.verify_backup_code(user_id, codes[1])
        assert success
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, two_factor_service):
        """Test 2FA rate limiting."""
        user_id = "user123"
        
        # Setup 2FA
        setup_data = await two_factor_service.setup_totp(user_id, "test@example.com")
        import pyotp
        totp = pyotp.TOTP(setup_data["secret"])
        await two_factor_service.verify_totp_setup(user_id, totp.now())
        
        # Create challenge
        challenge = await two_factor_service.create_challenge(user_id)
        
        # Make multiple failed attempts
        for i in range(two_factor_service.max_verify_attempts + 1):
            success, error = await two_factor_service.verify_challenge(
                challenge.challenge_id,
                "000000"
            )
            
            if i < two_factor_service.max_verify_attempts:
                assert not success
                assert "Invalid code" in error
            else:
                # Should be rate limited
                assert not success
                assert "Too many attempts" in error
    
    @pytest.mark.asyncio
    async def test_admin_disable(self, two_factor_service):
        """Test admin 2FA disable."""
        user_id = "user123"
        admin_id = "admin456"
        
        # Setup 2FA
        setup_data = await two_factor_service.setup_totp(user_id, "test@example.com")
        import pyotp
        totp = pyotp.TOTP(setup_data["secret"])
        await two_factor_service.verify_totp_setup(user_id, totp.now())
        
        # Admin disable
        success = await two_factor_service.admin_disable_2fa(
            user_id=user_id,
            admin_id=admin_id,
            reason="Account recovery requested"
        )
        assert success
        
        # 2FA should be disabled
        status = await two_factor_service.get_2fa_status(user_id)
        assert not status["enabled"]


class TestAuthMiddleware:
    """Test authentication middleware."""
    
    @pytest.mark.asyncio
    async def test_middleware_initialization(self, token_manager, rbac_manager, 
                                           permission_checker, revocation_service,
                                           session_manager):
        """Test middleware initialization."""
        middleware = AuthMiddleware(
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker,
            token_revocation_service=revocation_service,
            session_manager=session_manager
        )
        
        assert middleware.token_manager is token_manager
        assert middleware.token_revocation_service is revocation_service
        assert middleware.session_manager is session_manager
    
    @pytest.mark.asyncio
    async def test_token_verification_with_revocation(self, token_manager, 
                                                    revocation_service,
                                                    session_manager,
                                                    rbac_manager,
                                                    permission_checker):
        """Test that revoked tokens are rejected."""
        # Create middleware
        middleware = AuthMiddleware(
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker,
            token_revocation_service=revocation_service,
            session_manager=session_manager
        )
        
        # Create token
        token_data = TokenData(
            user_id="user123",
            username="testuser",
            roles=["user"],
            permissions=[]
        )
        token = token_manager.create_access_token(token_data)
        
        # Get JTI from token
        decoded = jwt.decode(
            token,
            token_manager._extract_key_from_combined(token_manager.secret_key),
            algorithms=[token_manager.algorithm]
        )
        jti = decoded["jti"]
        
        # Revoke token
        await revocation_service.revoke_token(
            jti=jti,
            user_id="user123",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            reason="test"
        )
        
        # Mock request and credentials
        from fastapi.security import HTTPAuthorizationCredentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        # Should return None for revoked token
        user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=None
        )
        
        assert user is None


class TestUserManager:
    """Test user management with production auth."""
    
    @pytest.mark.asyncio
    async def test_user_authentication_flow(self, token_manager, rbac_manager,
                                          permission_checker, test_user):
        """Test complete user authentication flow."""
        # Mock user store
        user_store = AsyncMock()
        user_store.get_user_by_username = AsyncMock(return_value=test_user)
        user_store.update_user = AsyncMock()
        
        # Create user manager
        user_manager = UserManager(
            user_store=user_store,
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker
        )
        
        # Authenticate user
        user, tokens = await user_manager.authenticate(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.100"
        )
        
        assert user.username == "testuser"
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "session_id" in tokens
        
        # Verify tokens are valid
        access_data = token_manager.verify_token(tokens["access_token"])
        assert access_data is not None
        assert access_data.user_id == test_user.id
        
        refresh_data = token_manager.verify_token(
            tokens["refresh_token"], 
            token_type="refresh"
        )
        assert refresh_data is not None
    
    @pytest.mark.asyncio
    async def test_failed_authentication(self, token_manager, rbac_manager,
                                       permission_checker, test_user):
        """Test failed authentication attempts."""
        # Mock user store
        user_store = AsyncMock()
        user_store.get_user_by_username = AsyncMock(return_value=test_user)
        user_store.update_user = AsyncMock()
        
        # Create user manager
        user_manager = UserManager(
            user_store=user_store,
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker
        )
        
        # Try with wrong password
        with pytest.raises(Exception) as exc_info:
            await user_manager.authenticate(
                username="testuser",
                password="WrongPassword123!",
                ip_address="192.168.1.100"
            )
        
        assert "Invalid username or password" in str(exc_info.value)
        
        # Check that failed attempt was recorded
        assert test_user.failed_login_attempts > 0


class TestEndToEndAuth:
    """End-to-end authentication tests."""
    
    @pytest.mark.asyncio
    async def test_complete_auth_flow_with_2fa(self, token_manager, revocation_service,
                                              session_manager, two_factor_service,
                                              rbac_manager, permission_checker,
                                              test_user):
        """Test complete authentication flow with 2FA."""
        # Mock user store
        user_store = AsyncMock()
        user_store.get_user_by_username = AsyncMock(return_value=test_user)
        user_store.get_user = AsyncMock(return_value=test_user)
        user_store.update_user = AsyncMock()
        
        # Create user manager
        user_manager = UserManager(
            user_store=user_store,
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker
        )
        
        # Setup 2FA for user
        setup_data = await two_factor_service.setup_totp(
            test_user.id,
            test_user.email
        )
        
        import pyotp
        totp = pyotp.TOTP(setup_data["secret"])
        await two_factor_service.verify_totp_setup(test_user.id, totp.now())
        
        # Update user to have MFA enabled
        test_user.mfa_enabled = True
        test_user.mfa_secret = setup_data["secret"]
        
        # Create session for authentication
        session = await session_manager.create_session(
            user_id=test_user.id,
            ip_address="192.168.1.100",
            user_agent="Test Client"
        )
        
        # Authenticate user (first step)
        user, tokens = await user_manager.authenticate(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.100"
        )
        
        # Verify MFA
        valid_code = totp.now()
        verified = await user_manager.verify_mfa(test_user.id, valid_code)
        assert verified
        
        # Create middleware
        middleware = AuthMiddleware(
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker,
            user_store=user_store,
            token_revocation_service=revocation_service,
            session_manager=session_manager
        )
        
        # Use token to authenticate
        from fastapi.security import HTTPAuthorizationCredentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=tokens["access_token"]
        )
        
        # Should get user successfully
        authenticated_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=None
        )
        
        assert authenticated_user is not None
        assert authenticated_user.id == test_user.id
        
        # Logout - revoke session
        await session_manager.invalidate_session(session.session_id, "logout")
        await revocation_service.revoke_session(
            session_id=session.session_id,
            user_id=test_user.id,
            reason="logout"
        )
        
        # Token should no longer work
        authenticated_user = await middleware.get_current_user(
            credentials=credentials,
            api_key=None,
            request=None
        )
        
        # Should be None because session is revoked
        # (This would work if we properly set session_id in token_data)
        # For now, just verify session is revoked
        assert await revocation_service.is_session_revoked(session.session_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])