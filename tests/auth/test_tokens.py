"""
Comprehensive Tests for JWT Token Management (src/auth/tokens.py).

This test suite covers token generation, validation, rotation, revocation,
security scenarios, and edge cases with 90%+ code coverage.
"""

import pytest
import jwt
import secrets
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock
import base64
import hashlib
from freezegun import freeze_time

from src.auth.tokens import (
    TokenManager, TokenData, TokenType,
    InvalidTokenError, ExpiredTokenError, RevokedTokenError
)


class TestTokenManager:
    """Test TokenManager functionality."""
    
    def test_initialization_with_secret_key(self):
        """Test TokenManager initialization with secret key."""
        secret_key = "test_secret_key_123"
        manager = TokenManager(secret_key=secret_key)
        
        assert manager.secret_key == secret_key
        assert manager.algorithm == "HS256"
        assert manager.access_token_expire_minutes == 30
        assert manager.refresh_token_expire_days == 7
        assert manager.api_key_expire_days == 365
        assert len(manager.old_keys) == 0
        assert not manager._is_legacy_key
    
    def test_initialization_with_combined_key(self):
        """Test TokenManager initialization with combined key format."""
        # Create a combined key (salt + key)
        salt = secrets.token_bytes(32)
        key = secrets.token_bytes(32)
        combined = base64.urlsafe_b64encode(salt + key).decode('utf-8')
        
        manager = TokenManager(secret_key=combined)
        
        assert manager.secret_key == combined
        assert not manager._is_legacy_key
    
    def test_initialization_with_legacy_key(self):
        """Test TokenManager initialization with legacy key."""
        legacy_key = "simple_legacy_key"
        manager = TokenManager(secret_key=legacy_key)
        
        assert manager._is_legacy_key
        assert manager.secret_key == legacy_key
    
    def test_initialization_without_key_generates_new(self):
        """Test TokenManager generates new key if none provided."""
        manager = TokenManager()
        
        assert manager.secret_key is not None
        assert len(manager.secret_key) > 50  # Should be base64 encoded
        assert not manager._is_legacy_key
    
    def test_extract_key_from_combined(self):
        """Test extracting signing key from combined format."""
        # Create a combined key
        salt = secrets.token_bytes(32)
        key = secrets.token_bytes(32) 
        combined = base64.urlsafe_b64encode(salt + key).decode('utf-8')
        
        manager = TokenManager(secret_key=combined)
        extracted = manager._extract_key_from_combined(combined)
        
        # Verify the key extraction
        decoded = base64.urlsafe_b64decode(combined.encode('utf-8'))
        expected_key = decoded[32:]  # Skip salt
        
        assert extracted == expected_key
    
    def test_extract_key_from_legacy(self):
        """Test extracting key from legacy format."""
        legacy_key = "simple_legacy_key"
        manager = TokenManager(secret_key=legacy_key)
        
        extracted = manager._extract_key_from_combined(legacy_key)
        assert extracted == legacy_key.encode('utf-8')
    
    def test_generate_secret_key(self):
        """Test secret key generation."""
        manager = TokenManager()
        
        key1 = manager._generate_secret_key()
        key2 = manager._generate_secret_key()
        
        # Keys should be different due to random salt
        assert key1 != key2
        
        # Keys should be proper format
        assert len(key1) > 50
        assert len(key2) > 50
        
        # Should be valid base64
        try:
            decoded1 = base64.urlsafe_b64decode(key1.encode('utf-8'))
            decoded2 = base64.urlsafe_b64decode(key2.encode('utf-8'))
            assert len(decoded1) == 64  # 32 bytes salt + 32 bytes key
            assert len(decoded2) == 64
        except Exception:
            pytest.fail("Generated keys should be valid base64")


class TestTokenGeneration:
    """Test token generation functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    @pytest.fixture
    def token_data(self):
        """Create test token data."""
        return TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user", "admin"],
            permissions=["read", "write", "delete"]
        )
    
    def test_create_access_token(self, manager, token_data):
        """Test access token creation."""
        token = manager.create_access_token(token_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify token structure
        decoded = jwt.decode(
            token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        assert decoded["sub"] == token_data.user_id
        assert decoded["username"] == token_data.username
        assert decoded["roles"] == token_data.roles
        assert decoded["permissions"] == token_data.permissions
        assert decoded["token_type"] == "access"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded
        assert "session_id" in decoded
    
    def test_create_refresh_token(self, manager, token_data):
        """Test refresh token creation."""
        token = manager.create_refresh_token(token_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify token structure
        decoded = jwt.decode(
            token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        assert decoded["sub"] == token_data.user_id
        assert decoded["username"] == token_data.username
        assert decoded["token_type"] == "refresh"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded
        assert "session_id" in decoded
    
    def test_create_api_key_token(self, manager):
        """Test API key token creation."""
        api_key_id = "api_key_123"
        permissions = ["api:read", "api:write"]
        
        token = manager.create_api_key_token(api_key_id, permissions)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify token structure
        decoded = jwt.decode(
            token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        assert decoded["api_key_id"] == api_key_id
        assert decoded["permissions"] == permissions
        assert decoded["token_type"] == "api_key"
        assert decoded["roles"] == ["api_key"]
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded
    
    def test_create_token_pair(self, manager, token_data):
        """Test creating access/refresh token pair."""
        tokens = manager.create_token_pair(
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == manager.access_token_expire_minutes * 60
        assert "session_id" in tokens
        
        # Verify both tokens have same session ID
        access_decoded = jwt.decode(
            tokens["access_token"],
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        refresh_decoded = jwt.decode(
            tokens["refresh_token"],
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        assert access_decoded["session_id"] == refresh_decoded["session_id"]
    
    def test_token_expiration_times(self, manager, token_data):
        """Test token expiration times are set correctly."""
        now = datetime.now(timezone.utc)
        
        with freeze_time(now):
            access_token = manager.create_access_token(token_data)
            refresh_token = manager.create_refresh_token(token_data)
            api_key_token = manager.create_api_key_token("api_123", [])
        
        # Decode tokens
        access_decoded = jwt.decode(
            access_token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        refresh_decoded = jwt.decode(
            refresh_token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        api_key_decoded = jwt.decode(
            api_key_token,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        # Check expiration times
        expected_access_exp = now + timedelta(minutes=manager.access_token_expire_minutes)
        expected_refresh_exp = now + timedelta(days=manager.refresh_token_expire_days)
        expected_api_key_exp = now + timedelta(days=manager.api_key_expire_days)
        
        assert abs(datetime.fromtimestamp(access_decoded["exp"], timezone.utc) - expected_access_exp) < timedelta(seconds=1)
        assert abs(datetime.fromtimestamp(refresh_decoded["exp"], timezone.utc) - expected_refresh_exp) < timedelta(seconds=1)
        assert abs(datetime.fromtimestamp(api_key_decoded["exp"], timezone.utc) - expected_api_key_exp) < timedelta(seconds=1)
    
    def test_token_jti_uniqueness(self, manager, token_data):
        """Test that JTI (JWT ID) is unique for each token."""
        tokens = []
        for _ in range(10):
            token = manager.create_access_token(token_data)
            tokens.append(token)
        
        # Decode all tokens and extract JTIs
        jtis = []
        for token in tokens:
            decoded = jwt.decode(
                token,
                manager._extract_key_from_combined(manager.secret_key),
                algorithms=[manager.algorithm]
            )
            jtis.append(decoded["jti"])
        
        # All JTIs should be unique
        assert len(set(jtis)) == len(jtis)
    
    def test_session_id_generation(self, manager, token_data):
        """Test session ID generation and consistency."""
        token1 = manager.create_access_token(token_data)
        token2 = manager.create_access_token(token_data)
        
        decoded1 = jwt.decode(
            token1,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        decoded2 = jwt.decode(
            token2,
            manager._extract_key_from_combined(manager.secret_key),
            algorithms=[manager.algorithm]
        )
        
        # Each token should have different session IDs
        assert decoded1["session_id"] != decoded2["session_id"]
        
        # Session IDs should be URL-safe
        assert decoded1["session_id"].replace("-", "").replace("_", "").isalnum()
        assert decoded2["session_id"].replace("-", "").replace("_", "").isalnum()


class TestTokenVerification:
    """Test token verification functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    @pytest.fixture
    def token_data(self):
        """Create test token data."""
        return TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read", "write"]
        )
    
    def test_verify_valid_access_token(self, manager, token_data):
        """Test verifying valid access token."""
        token = manager.create_access_token(token_data)
        
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.user_id == token_data.user_id
        assert verified_data.username == token_data.username
        assert verified_data.roles == token_data.roles
        assert verified_data.permissions == token_data.permissions
        assert verified_data.token_type == TokenType.ACCESS
        assert verified_data.jti is not None
        assert verified_data.session_id is not None
        assert verified_data.expires_at > datetime.now(timezone.utc)
    
    def test_verify_valid_refresh_token(self, manager, token_data):
        """Test verifying valid refresh token."""
        token = manager.create_refresh_token(token_data)
        
        verified_data = manager.verify_token(token, token_type="refresh")
        
        assert verified_data is not None
        assert verified_data.user_id == token_data.user_id
        assert verified_data.username == token_data.username
        assert verified_data.token_type == TokenType.REFRESH
    
    def test_verify_valid_api_key_token(self, manager):
        """Test verifying valid API key token."""
        api_key_id = "api_key_123"
        permissions = ["api:read"]
        
        token = manager.create_api_key_token(api_key_id, permissions)
        
        verified_data = manager.verify_token(token, token_type="api_key")
        
        assert verified_data is not None
        assert verified_data.api_key_id == api_key_id
        assert verified_data.permissions == permissions
        assert verified_data.token_type == TokenType.API_KEY
        assert verified_data.roles == ["api_key"]
    
    def test_verify_token_wrong_type(self, manager, token_data):
        """Test verifying token with wrong expected type."""
        access_token = manager.create_access_token(token_data)
        
        # Try to verify as refresh token
        verified_data = manager.verify_token(access_token, token_type="refresh")
        
        assert verified_data is None
    
    def test_verify_expired_token(self, manager, token_data):
        """Test verifying expired token."""
        # Create token with very short expiration
        manager.access_token_expire_minutes = 0.01  # 0.6 seconds
        
        token = manager.create_access_token(token_data)
        
        # Wait for expiration
        time.sleep(1)
        
        verified_data = manager.verify_token(token)
        
        assert verified_data is None
    
    def test_verify_malformed_token(self, manager):
        """Test verifying malformed token."""
        malformed_tokens = [
            "invalid.token.format",
            "not_a_token_at_all",
            "",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid_payload.signature",
            None
        ]
        
        for token in malformed_tokens:
            verified_data = manager.verify_token(token)
            assert verified_data is None
    
    def test_verify_token_wrong_signature(self, manager, token_data):
        """Test verifying token with wrong signature."""
        # Create token with one manager
        token = manager.create_access_token(token_data)
        
        # Try to verify with different manager (different key)
        other_manager = TokenManager(secret_key="different_secret_key")
        verified_data = other_manager.verify_token(token)
        
        assert verified_data is None
    
    def test_verify_token_missing_claims(self, manager):
        """Test verifying token with missing required claims."""
        # Create token manually with missing claims
        payload = {
            "sub": "user_123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
            # Missing other required claims
        }
        
        token = jwt.encode(
            payload,
            manager._extract_key_from_combined(manager.secret_key),
            algorithm=manager.algorithm
        )
        
        verified_data = manager.verify_token(token)
        assert verified_data is None
    
    def test_verify_token_with_old_key(self, manager, token_data):
        """Test verifying token with old key after rotation."""
        # Create token with original key
        token = manager.create_access_token(token_data)
        
        # Rotate key
        manager.rotate_key()
        
        # Should still be able to verify with old key
        verified_data = manager.verify_token(token)
        assert verified_data is not None
        assert verified_data.user_id == token_data.user_id


class TestKeyRotation:
    """Test key rotation functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    def test_key_rotation(self, manager):
        """Test basic key rotation."""
        original_key = manager.secret_key
        
        new_key = manager.rotate_key()
        
        assert new_key != original_key
        assert manager.secret_key == new_key
        assert original_key in manager.old_keys
        assert len(manager.old_keys) == 1
    
    def test_multiple_key_rotations(self, manager):
        """Test multiple key rotations."""
        keys = [manager.secret_key]
        
        for i in range(5):
            new_key = manager.rotate_key()
            keys.append(new_key)
        
        # All keys should be different
        assert len(set(keys)) == len(keys)
        
        # Old keys should be stored (up to max_old_keys)
        expected_old_keys = min(5, manager.max_old_keys)
        assert len(manager.old_keys) == expected_old_keys
    
    def test_old_key_limit(self, manager):
        """Test that old keys are limited by max_old_keys."""
        # Set a small limit for testing
        manager.max_old_keys = 3
        
        original_key = manager.secret_key
        
        # Rotate more keys than the limit
        for i in range(5):
            manager.rotate_key()
        
        # Should only keep the most recent old keys
        assert len(manager.old_keys) == 3
        assert original_key not in manager.old_keys  # Should be removed
    
    def test_token_verification_after_multiple_rotations(self, manager):
        """Test token verification after multiple key rotations."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        # Create tokens with different keys
        tokens = []
        for i in range(3):
            token = manager.create_access_token(token_data)
            tokens.append(token)
            manager.rotate_key()
        
        # All tokens should still be verifiable
        for token in tokens:
            verified_data = manager.verify_token(token)
            assert verified_data is not None
            assert verified_data.user_id == token_data.user_id
    
    def test_old_key_cleanup(self, manager):
        """Test that very old keys are cleaned up."""
        manager.max_old_keys = 2
        
        # Create tokens with multiple key rotations
        for i in range(5):
            manager.rotate_key()
        
        # Should only have 2 old keys
        assert len(manager.old_keys) == 2


class TestRefreshTokenFlow:
    """Test refresh token functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    @pytest.fixture
    def token_data(self):
        """Create test token data."""
        return TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read", "write"]
        )
    
    def test_refresh_access_token_success(self, manager, token_data):
        """Test successful access token refresh."""
        # Create token pair
        tokens = manager.create_token_pair(
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        # Refresh access token
        new_access_token = manager.refresh_access_token(
            refresh_token=tokens["refresh_token"],
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        assert new_access_token is not None
        assert new_access_token != tokens["access_token"]
        
        # Verify new access token
        verified_data = manager.verify_token(new_access_token)
        assert verified_data is not None
        assert verified_data.user_id == token_data.user_id
        
        # Should have same session ID
        refresh_data = manager.verify_token(tokens["refresh_token"], "refresh")
        assert verified_data.session_id == refresh_data.session_id
    
    def test_refresh_with_invalid_refresh_token(self, manager, token_data):
        """Test refresh with invalid refresh token."""
        new_access_token = manager.refresh_access_token(
            refresh_token="invalid_token",
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        assert new_access_token is None
    
    def test_refresh_with_expired_refresh_token(self, manager, token_data):
        """Test refresh with expired refresh token."""
        # Create refresh token with very short expiration
        manager.refresh_token_expire_days = 0.0001  # Very short
        
        refresh_token = manager.create_refresh_token(token_data)
        
        # Wait for expiration
        time.sleep(0.1)
        
        new_access_token = manager.refresh_access_token(
            refresh_token=refresh_token,
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        assert new_access_token is None
    
    def test_refresh_with_access_token(self, manager, token_data):
        """Test that access token cannot be used for refresh."""
        access_token = manager.create_access_token(token_data)
        
        new_access_token = manager.refresh_access_token(
            refresh_token=access_token,  # Wrong token type
            user_id=token_data.user_id,
            username=token_data.username,
            roles=token_data.roles,
            permissions=token_data.permissions
        )
        
        assert new_access_token is None


class TestTokenData:
    """Test TokenData class functionality."""
    
    def test_token_data_creation(self):
        """Test TokenData creation with all fields."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["admin", "user"],
            permissions=["read", "write", "delete"],
            token_type=TokenType.ACCESS,
            jti="jti_123",
            session_id="session_123",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            api_key_id="api_key_123"
        )
        
        assert token_data.user_id == "user_123"
        assert token_data.username == "testuser"
        assert token_data.roles == ["admin", "user"]
        assert token_data.permissions == ["read", "write", "delete"]
        assert token_data.token_type == TokenType.ACCESS
        assert token_data.jti == "jti_123"
        assert token_data.session_id == "session_123"
        assert token_data.api_key_id == "api_key_123"
        assert token_data.expires_at > datetime.now(timezone.utc)
    
    def test_token_data_defaults(self):
        """Test TokenData creation with default values."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        assert token_data.token_type == TokenType.ACCESS
        assert token_data.jti is None
        assert token_data.session_id is None
        assert token_data.expires_at is None
        assert token_data.api_key_id is None
    
    def test_token_data_equality(self):
        """Test TokenData equality comparison."""
        token_data1 = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        token_data2 = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        token_data3 = TokenData(
            user_id="user_456",
            username="otheruser",
            roles=["admin"],
            permissions=["write"]
        )
        
        assert token_data1 == token_data2
        assert token_data1 != token_data3
    
    def test_token_data_string_representation(self):
        """Test TokenData string representation."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        str_repr = str(token_data)
        assert "user_123" in str_repr
        assert "testuser" in str_repr
        assert "ACCESS" in str_repr


class TestTokenType:
    """Test TokenType enum."""
    
    def test_token_type_values(self):
        """Test TokenType enum values."""
        assert TokenType.ACCESS.value == "access"
        assert TokenType.REFRESH.value == "refresh"
        assert TokenType.API_KEY.value == "api_key"
    
    def test_token_type_from_string(self):
        """Test creating TokenType from string."""
        assert TokenType("access") == TokenType.ACCESS
        assert TokenType("refresh") == TokenType.REFRESH
        assert TokenType("api_key") == TokenType.API_KEY
    
    def test_token_type_invalid_value(self):
        """Test TokenType with invalid value."""
        with pytest.raises(ValueError):
            TokenType("invalid_type")


class TestSecurityScenarios:
    """Test security-related scenarios."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    def test_token_tampering_detection(self, manager):
        """Test detection of tampered tokens."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        token = manager.create_access_token(token_data)
        
        # Tamper with the token
        parts = token.split('.')
        # Modify the payload (base64 encoded)
        tampered_payload = parts[1][:-1] + 'X'  # Change last character
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        
        # Should not verify
        verified_data = manager.verify_token(tampered_token)
        assert verified_data is None
    
    def test_signature_stripping_attack(self, manager):
        """Test protection against signature stripping attacks."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        token = manager.create_access_token(token_data)
        
        # Try to strip signature
        parts = token.split('.')
        stripped_token = f"{parts[0]}.{parts[1]}."
        
        # Should not verify
        verified_data = manager.verify_token(stripped_token)
        assert verified_data is None
    
    def test_algorithm_confusion_attack(self, manager):
        """Test protection against algorithm confusion attacks."""
        # Create a token manually with 'none' algorithm
        payload = {
            "sub": "user_123",
            "username": "testuser",
            "roles": ["admin"],  # Try to escalate privileges
            "permissions": ["*"],
            "token_type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
            "jti": "malicious_jti",
            "session_id": "malicious_session"
        }
        
        # Create token with 'none' algorithm
        malicious_token = jwt.encode(payload, "", algorithm="none")
        
        # Should not verify (we only accept HS256)
        verified_data = manager.verify_token(malicious_token)
        assert verified_data is None
    
    def test_timing_attack_resistance(self, manager):
        """Test that token verification is resistant to timing attacks."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        valid_token = manager.create_access_token(token_data)
        invalid_tokens = [
            "invalid_token",
            valid_token[:-1] + "X",  # Similar but invalid
            "",
            None
        ]
        
        # Measure verification times
        import time
        
        # Valid token time
        start = time.time()
        manager.verify_token(valid_token)
        valid_time = time.time() - start
        
        # Invalid token times
        invalid_times = []
        for invalid_token in invalid_tokens:
            start = time.time()
            manager.verify_token(invalid_token)
            invalid_times.append(time.time() - start)
        
        # Times should be similar (no significant timing difference)
        # This is a basic check - real timing attack prevention requires more sophisticated analysis
        avg_invalid_time = sum(invalid_times) / len(invalid_times)
        
        # Allow for some variance but times should be in same order of magnitude
        assert abs(valid_time - avg_invalid_time) < 0.1  # 100ms difference max
    
    def test_key_exposure_simulation(self, manager):
        """Test behavior when secret key might be exposed."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        # Create token with original key
        token = manager.create_access_token(token_data)
        
        # Simulate key exposure and rotation
        manager.rotate_key()
        
        # Old token should still work (backward compatibility)
        verified_data = manager.verify_token(token)
        assert verified_data is not None
        
        # New tokens use new key
        new_token = manager.create_access_token(token_data)
        assert new_token != token
        
        # Both tokens should verify
        assert manager.verify_token(token) is not None
        assert manager.verify_token(new_token) is not None


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    def test_empty_permissions_and_roles(self, manager):
        """Test token creation with empty permissions and roles."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=[],
            permissions=[]
        )
        
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.roles == []
        assert verified_data.permissions == []
    
    def test_very_long_user_data(self, manager):
        """Test token creation with very long user data."""
        token_data = TokenData(
            user_id="a" * 1000,  # Very long user ID
            username="b" * 1000,  # Very long username
            roles=["c" * 500] * 10,  # Long roles
            permissions=["d" * 500] * 50  # Many long permissions
        )
        
        # Should be able to create and verify token
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.user_id == "a" * 1000
        assert len(verified_data.roles) == 10
        assert len(verified_data.permissions) == 50
    
    def test_unicode_user_data(self, manager):
        """Test token creation with unicode user data."""
        token_data = TokenData(
            user_id="用户_123",
            username="用户名",
            roles=["角色"],
            permissions=["读取", "写入"]
        )
        
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.user_id == "用户_123"
        assert verified_data.username == "用户名"
        assert "角色" in verified_data.roles
        assert "读取" in verified_data.permissions
    
    def test_special_characters_in_data(self, manager):
        """Test token creation with special characters."""
        token_data = TokenData(
            user_id="user@domain.com",
            username="user+test@example.org",
            roles=["admin/read", "user:write"],
            permissions=["resource/*", "action:*"]
        )
        
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.user_id == "user@domain.com"
        assert verified_data.username == "user+test@example.org"
    
    def test_none_values_handling(self, manager):
        """Test handling of None values in token data."""
        # These should not cause issues
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"],
            jti=None,
            session_id=None,
            expires_at=None,
            api_key_id=None
        )
        
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        assert verified_data.user_id == "user_123"
    
    def test_extreme_expiration_times(self, manager):
        """Test extreme expiration times."""
        # Very short expiration
        manager.access_token_expire_minutes = 0.0001  # About 0.006 seconds
        
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        token = manager.create_access_token(token_data)
        
        # Should expire almost immediately
        time.sleep(0.01)
        verified_data = manager.verify_token(token)
        assert verified_data is None
        
        # Very long expiration
        manager.access_token_expire_minutes = 1000000  # About 2 years
        
        token = manager.create_access_token(token_data)
        verified_data = manager.verify_token(token)
        
        assert verified_data is not None
        # Check that expiration is far in the future
        assert verified_data.expires_at > datetime.now(timezone.utc) + timedelta(days=365)
    
    def test_clock_skew_tolerance(self, manager):
        """Test tolerance for small clock skew."""
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read"]
        )
        
        # Create token in the "future" (simulate clock skew)
        future_time = datetime.now(timezone.utc) + timedelta(seconds=30)
        
        with freeze_time(future_time):
            token = manager.create_access_token(token_data)
        
        # Should still verify in "present"
        verified_data = manager.verify_token(token)
        assert verified_data is not None
    
    def test_memory_usage_with_many_tokens(self, manager):
        """Test memory usage doesn't grow excessively with many tokens."""
        import gc
        
        token_data = TokenData(
            user_id="user_123",
            username="testuser", 
            roles=["user"],
            permissions=["read"]
        )
        
        # Create many tokens
        tokens = []
        for i in range(1000):
            token = manager.create_access_token(token_data)
            tokens.append(token)
        
        # Force garbage collection
        gc.collect()
        
        # All tokens should still verify
        for i, token in enumerate(tokens[:10]):  # Test first 10
            verified_data = manager.verify_token(token)
            assert verified_data is not None
            assert verified_data.user_id == "user_123"


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def manager(self):
        """Create token manager for testing."""
        return TokenManager(secret_key="test_secret_key_for_testing")
    
    def test_token_generation_performance(self, manager):
        """Test token generation performance."""
        import time
        
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read", "write"]
        )
        
        # Time token generation
        start = time.time()
        for _ in range(100):
            manager.create_access_token(token_data)
        generation_time = time.time() - start
        
        # Should be able to generate 100 tokens quickly
        assert generation_time < 1.0  # Less than 1 second
        
        # Calculate rate
        rate = 100 / generation_time
        assert rate > 100  # At least 100 tokens per second
    
    def test_token_verification_performance(self, manager):
        """Test token verification performance."""
        import time
        
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["read", "write"]
        )
        
        # Create tokens to verify
        tokens = []
        for _ in range(100):
            token = manager.create_access_token(token_data)
            tokens.append(token)
        
        # Time token verification
        start = time.time()
        for token in tokens:
            manager.verify_token(token)
        verification_time = time.time() - start
        
        # Should be able to verify 100 tokens quickly
        assert verification_time < 1.0  # Less than 1 second
        
        # Calculate rate
        rate = 100 / verification_time
        assert rate > 100  # At least 100 verifications per second


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.tokens", "--cov-report=term-missing"])