"""JWT Token Management.

Secure token generation and validation following OWASP guidelines.
"""

import jwt
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


@dataclass
class TokenData:
    """Token payload data."""
    
    user_id: str
    username: str
    roles: List[str]
    permissions: List[str]
    token_type: str = "access"
    session_id: Optional[str] = None
    api_key_id: Optional[str] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JWT payload."""
        return {
            "sub": self.user_id,
            "username": self.username,
            "roles": self.roles,
            "permissions": self.permissions,
            "token_type": self.token_type,
            "session_id": self.session_id,
            "api_key_id": self.api_key_id,
            "iat": int(self.issued_at.timestamp()) if self.issued_at else None,
            "exp": int(self.expires_at.timestamp()) if self.expires_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenData":
        """Create TokenData from JWT payload."""
        return cls(
            user_id=data["sub"],
            username=data.get("username", ""),
            roles=data.get("roles", []),
            permissions=data.get("permissions", []),
            token_type=data.get("token_type", "access"),
            session_id=data.get("session_id"),
            api_key_id=data.get("api_key_id"),
            issued_at=datetime.fromtimestamp(data["iat"], tz=timezone.utc) if data.get("iat") else None,
            expires_at=datetime.fromtimestamp(data["exp"], tz=timezone.utc) if data.get("exp") else None,
        )


class TokenManager:
    """Secure JWT token manager."""
    
    def __init__(self, secret_key: Optional[str] = None, 
                 algorithm: str = "HS256",
                 access_token_expire_minutes: int = 15,
                 refresh_token_expire_days: int = 30):
        """
        Initialize token manager.
        
        Args:
            secret_key: Secret key for signing tokens (generated if not provided)
            algorithm: JWT algorithm (default: HS256, OWASP recommended)
            access_token_expire_minutes: Access token expiry time
            refresh_token_expire_days: Refresh token expiry time
        """
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        
        # Generate or use provided secret key
        if secret_key:
            # Check if this is a legacy key or new format key
            # New format keys are longer due to embedded salt
            self.secret_key = secret_key
            self._is_legacy_key = self._check_legacy_key_format(secret_key)
        else:
            # Generate secure secret key with random salt
            self.secret_key = self._generate_secret_key()
            self._is_legacy_key = False
        
        # Key rotation support
        self.key_rotation_enabled = False
        self.old_keys: List[str] = []
        self.key_rotation_interval = timedelta(days=90)
        self.last_key_rotation = datetime.now(timezone.utc)
        
        # Token blacklist for revocation
        self.revoked_tokens: set = set()
        self.revoked_sessions: set = set()
    
    def _generate_secret_key(self) -> str:
        """Generate a secure secret key.
        
        Security improvement: This method now uses a random salt instead of a static one,
        following OWASP best practices for key derivation. The salt is embedded in the
        returned key string for proper storage and retrieval.
        """
        # Use environment variable if available
        env_key = os.environ.get("JWT_SECRET_KEY")
        if env_key:
            return env_key
        
        # Generate new secure key with random salt
        random_bytes = secrets.token_bytes(32)
        
        # Generate a random salt (32 bytes) for enhanced security
        # Using os.urandom for cryptographically secure random bytes
        salt = os.urandom(32)
        
        # Use PBKDF2 for key derivation (OWASP recommended)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,  # Now using random salt for each key generation
            iterations=100000,  # OWASP recommends 100,000+
            backend=default_backend()
        )
        
        key = kdf.derive(random_bytes)
        
        # Combine salt and key for storage
        # Format: base64(salt + key) - this allows us to extract the salt later if needed
        combined = salt + key
        return base64.urlsafe_b64encode(combined).decode('utf-8')
    
    def _check_legacy_key_format(self, key: str) -> bool:
        """Check if a key is in legacy format (without embedded salt).
        
        Args:
            key: The secret key to check
            
        Returns:
            True if legacy format, False if new format with salt
        """
        try:
            # Decode the key
            decoded = base64.urlsafe_b64decode(key.encode('utf-8'))
            # New format has salt (32 bytes) + key (32 bytes) = 64 bytes total
            # Legacy format would be just 32 bytes or a different length
            return len(decoded) != 64
        except Exception:
            # If we can't decode it, assume it's a legacy format
            return True
    
    def _extract_key_from_combined(self, combined_key: str) -> str:
        """Extract the actual key from a combined salt+key format.
        
        Args:
            combined_key: The base64 encoded salt+key
            
        Returns:
            The extracted key portion
        """
        if self._check_legacy_key_format(combined_key):
            # Legacy format - return as is
            return combined_key
        
        try:
            # Decode and extract the key portion (skip the 32-byte salt)
            decoded = base64.urlsafe_b64decode(combined_key.encode('utf-8'))
            key_portion = decoded[32:]  # Skip salt, get key
            return base64.urlsafe_b64encode(key_portion).decode('utf-8')
        except Exception:
            # If extraction fails, return original
            return combined_key
    
    def create_access_token(self, token_data: TokenData) -> str:
        """Create an access token."""
        # Set token timestamps
        now = datetime.now(timezone.utc)
        token_data.issued_at = now
        token_data.expires_at = now + timedelta(minutes=self.access_token_expire_minutes)
        token_data.token_type = "access"
        
        # Generate session ID if not provided
        if not token_data.session_id:
            token_data.session_id = secrets.token_urlsafe(16)
        
        # Create JWT payload
        payload = token_data.to_dict()
        
        # Additional security claims
        payload.update({
            "iss": "claude-optimized-deployment",
            "aud": "code-api",
            "jti": secrets.token_urlsafe(16),  # Unique token ID
        })
        
        # Encode token using the extracted key portion
        signing_key = self._extract_key_from_combined(self.secret_key)
        token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
        return token
    
    def create_refresh_token(self, token_data: TokenData) -> str:
        """Create a refresh token."""
        # Set token timestamps
        now = datetime.now(timezone.utc)
        token_data.issued_at = now
        token_data.expires_at = now + timedelta(days=self.refresh_token_expire_days)
        token_data.token_type = "refresh"
        
        # Use same session ID as access token
        if not token_data.session_id:
            token_data.session_id = secrets.token_urlsafe(16)
        
        # Create JWT payload (minimal claims for refresh token)
        payload = {
            "sub": token_data.user_id,
            "token_type": "refresh",
            "session_id": token_data.session_id,
            "iat": int(token_data.issued_at.timestamp()),
            "exp": int(token_data.expires_at.timestamp()),
            "iss": "claude-optimized-deployment",
            "aud": "code-api",
            "jti": secrets.token_urlsafe(16),
        }
        
        # Encode token using the extracted key portion
        signing_key = self._extract_key_from_combined(self.secret_key)
        token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
        return token
    
    def create_token_pair(self, user_id: str, username: str,
                         roles: List[str], permissions: List[str]) -> Dict[str, str]:
        """Create both access and refresh tokens."""
        # Create token data
        token_data = TokenData(
            user_id=user_id,
            username=username,
            roles=roles,
            permissions=permissions
        )
        
        # Generate tokens
        access_token = self.create_access_token(token_data)
        refresh_token = self.create_refresh_token(token_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_expire_minutes * 60,
            "session_id": token_data.session_id
        }
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[TokenData]:
        """
        Verify and decode a token.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type (access or refresh)
            
        Returns:
            TokenData if valid, None otherwise
        """
        try:
            # Try current key first (extract actual key from combined format)
            signing_key = self._extract_key_from_combined(self.secret_key)
            payload = self._decode_token(token, signing_key)
            
        except jwt.ExpiredSignatureError:
            return None
            
        except jwt.InvalidTokenError:
            # Try old keys if key rotation is enabled
            if self.key_rotation_enabled and self.old_keys:
                for old_key in self.old_keys:
                    try:
                        # Extract key from potentially combined format
                        old_signing_key = self._extract_key_from_combined(old_key)
                        payload = self._decode_token(token, old_signing_key)
                        break
                    except jwt.InvalidTokenError:
                        continue
                else:
                    return None
            else:
                return None
        
        # Verify token type
        if payload.get("token_type") != token_type:
            return None
        
        # Check if token is revoked
        jti = payload.get("jti")
        if jti and jti in self.revoked_tokens:
            return None
        
        # Check if session is revoked
        session_id = payload.get("session_id")
        if session_id and session_id in self.revoked_sessions:
            return None
        
        # Create TokenData from payload
        return TokenData.from_dict(payload)
    
    def _decode_token(self, token: str, key: str) -> Dict[str, Any]:
        """Decode a token with a specific key."""
        return jwt.decode(
            token,
            key,
            algorithms=[self.algorithm],
            issuer="claude-optimized-deployment",
            audience="code-api",
            options={"verify_exp": True}
        )
    
    def refresh_access_token(self, refresh_token: str, 
                           user_id: str, username: str,
                           roles: List[str], permissions: List[str]) -> Optional[str]:
        """Create a new access token from a refresh token."""
        # Verify refresh token
        token_data = self.verify_token(refresh_token, token_type="refresh")
        if not token_data:
            return None
        
        # Verify user ID matches
        if token_data.user_id != user_id:
            return None
        
        # Create new access token with same session ID
        new_token_data = TokenData(
            user_id=user_id,
            username=username,
            roles=roles,
            permissions=permissions,
            session_id=token_data.session_id
        )
        
        return self.create_access_token(new_token_data)
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a specific token."""
        try:
            # Decode token to get JTI (extract key from combined format)
            signing_key = self._extract_key_from_combined(self.secret_key)
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}
            )
            
            jti = payload.get("jti")
            if jti:
                self.revoked_tokens.add(jti)
                return True
                
        except jwt.InvalidTokenError:
            pass
        
        return False
    
    def revoke_session(self, session_id: str) -> None:
        """Revoke all tokens for a session."""
        self.revoked_sessions.add(session_id)
    
    def rotate_key(self) -> str:
        """Rotate the secret key for enhanced security.
        
        Uses the new secure key generation with random salt.
        """
        # Keep old key for grace period
        self.old_keys.append(self.secret_key)
        
        # Limit old keys (keep last 3)
        if len(self.old_keys) > 3:
            self.old_keys.pop(0)
        
        # Generate new key with random salt
        self.secret_key = self._generate_secret_key()
        self.last_key_rotation = datetime.now(timezone.utc)
        self.key_rotation_enabled = True
        
        return self.secret_key
    
    def should_rotate_key(self) -> bool:
        """Check if key rotation is due."""
        if not self.key_rotation_enabled:
            return False
        
        time_since_rotation = datetime.now(timezone.utc) - self.last_key_rotation
        return time_since_rotation >= self.key_rotation_interval
    
    def create_api_key_token(self, api_key_id: str, 
                           permissions: List[str]) -> str:
        """Create a token for API key authentication."""
        token_data = TokenData(
            user_id=f"apikey:{api_key_id}",
            username=f"apikey:{api_key_id}",
            roles=["api_key"],
            permissions=permissions,
            api_key_id=api_key_id
        )
        
        # API key tokens have longer expiry
        now = datetime.now(timezone.utc)
        token_data.issued_at = now
        token_data.expires_at = now + timedelta(days=365)  # 1 year
        token_data.token_type = "api_key"
        
        # Create JWT payload
        payload = token_data.to_dict()
        payload.update({
            "iss": "claude-optimized-deployment",
            "aud": "code-api",
            "jti": secrets.token_urlsafe(16),
        })
        
        # Encode token using the extracted key portion
        signing_key = self._extract_key_from_combined(self.secret_key)
        return jwt.encode(payload, signing_key, algorithm=self.algorithm)
    
    def decode_token_unsafe(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode token without verification (for debugging only).
        
        WARNING: This should never be used in production code.
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None
    
    def migrate_to_secure_key(self) -> str:
        """
        Migrate from legacy key format to new secure format with random salt.
        
        This method helps with backward compatibility by:
        1. Keeping the old key in the rotation list for grace period
        2. Generating a new key with random salt
        3. Enabling key rotation to handle tokens signed with old key
        
        Returns:
            The new secure key
            
        Usage:
            # During deployment migration
            token_manager = TokenManager(secret_key=old_key)
            new_key = token_manager.migrate_to_secure_key()
            # Save new_key to secure storage (env var, secrets manager, etc.)
        """
        # Only migrate if using legacy format
        if hasattr(self, '_is_legacy_key') and not self._is_legacy_key:
            # Already using new format
            return self.secret_key
        
        # Enable key rotation and rotate to new secure key
        self.key_rotation_enabled = True
        new_key = self.rotate_key()
        
        # Log migration for audit purposes (in production, use proper logging)
        print(f"[SECURITY] Migrated from legacy key format to secure key with random salt")
        
        return new_key