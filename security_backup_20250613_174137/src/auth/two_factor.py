"""
Two-Factor Authentication (2FA) Service.

Provides comprehensive 2FA support including:
- TOTP (Time-based One-Time Password)
- SMS OTP (placeholder for integration)
- Email OTP
- Backup codes
- Recovery options
"""

import asyncio
import secrets
import pyotp
import qrcode
import io
import base64
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
import logging
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from ..core.connections import RedisConnectionPool, ConnectionPoolConfig

logger = logging.getLogger(__name__)


@dataclass
class TwoFactorConfig:
    """2FA configuration for a user."""
    user_id: str
    totp_enabled: bool = False
    totp_secret: Optional[str] = None
    sms_enabled: bool = False
    sms_phone: Optional[str] = None
    email_enabled: bool = False
    email_address: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    backup_codes_used: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "user_id": self.user_id,
            "totp_enabled": self.totp_enabled,
            "totp_secret": self.totp_secret,
            "sms_enabled": self.sms_enabled,
            "sms_phone": self.sms_phone,
            "email_enabled": self.email_enabled,
            "email_address": self.email_address,
            "backup_codes": self.backup_codes,
            "backup_codes_used": self.backup_codes_used,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TwoFactorConfig":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            totp_enabled=data.get("totp_enabled", False),
            totp_secret=data.get("totp_secret"),
            sms_enabled=data.get("sms_enabled", False),
            sms_phone=data.get("sms_phone"),
            email_enabled=data.get("email_enabled", False),
            email_address=data.get("email_address"),
            backup_codes=data.get("backup_codes", []),
            backup_codes_used=data.get("backup_codes_used", []),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"])
        )
    
    def has_2fa_enabled(self) -> bool:
        """Check if any 2FA method is enabled."""
        return self.totp_enabled or self.sms_enabled or self.email_enabled


@dataclass
class TwoFactorChallenge:
    """Represents a 2FA challenge."""
    challenge_id: str
    user_id: str
    challenge_type: str  # totp, sms, email, backup
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    max_attempts: int = 3
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "challenge_id": self.challenge_id,
            "user_id": self.user_id,
            "challenge_type": self.challenge_type,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "verified": self.verified,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TwoFactorChallenge":
        """Create from dictionary."""
        return cls(
            challenge_id=data["challenge_id"],
            user_id=data["user_id"],
            challenge_type=data["challenge_type"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            attempts=data.get("attempts", 0),
            max_attempts=data.get("max_attempts", 3),
            verified=data.get("verified", False),
            metadata=data.get("metadata", {})
        )
    
    def is_expired(self) -> bool:
        """Check if challenge is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def can_retry(self) -> bool:
        """Check if more attempts are allowed."""
        return self.attempts < self.max_attempts


class TwoFactorService:
    """
    Two-Factor Authentication service with Redis backend.
    
    Features:
    - Multiple 2FA methods (TOTP, SMS, Email)
    - Backup codes for recovery
    - Rate limiting and brute force protection
    - Challenge-based verification
    - Admin override capabilities
    """
    
    def __init__(
        self,
        redis_url: str,
        config: Optional[ConnectionPoolConfig] = None,
        issuer_name: str = "Claude Optimized Deployment",
        totp_window: int = 1,
        challenge_timeout_minutes: int = 5,
        backup_codes_count: int = 10
    ):
        """
        Initialize 2FA service.
        
        Args:
            redis_url: Redis connection URL
            config: Connection pool configuration
            issuer_name: Name shown in authenticator apps
            totp_window: TOTP validation window
            challenge_timeout_minutes: Challenge expiration time
            backup_codes_count: Number of backup codes to generate
        """
        self.redis_url = redis_url
        self.config = config or ConnectionPoolConfig()
        self.redis_pool = RedisConnectionPool(self.config)
        
        self.issuer_name = issuer_name
        self.totp_window = totp_window
        self.challenge_timeout_minutes = challenge_timeout_minutes
        self.backup_codes_count = backup_codes_count
        
        # Key prefixes
        self.CONFIG_PREFIX = "2fa:config:"
        self.CHALLENGE_PREFIX = "2fa:challenge:"
        self.RATE_LIMIT_PREFIX = "2fa:ratelimit:"
        
        # Rate limiting
        self.max_verify_attempts = 5
        self.rate_limit_window_minutes = 15
    
    async def initialize(self):
        """Initialize the service."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        await redis.ping()
        logger.info("2FA service initialized")
    
    async def setup_totp(self, user_id: str, user_email: str) -> Dict[str, str]:
        """
        Setup TOTP authentication for a user.
        
        Args:
            user_id: User ID
            user_email: User email for display
            
        Returns:
            Dictionary with secret, QR code, and provisioning URI
        """
        # Get or create 2FA config
        config = await self._get_config(user_id) or TwoFactorConfig(user_id=user_id)
        
        # Generate new secret
        secret = pyotp.random_base32()
        config.totp_secret = secret
        
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_data = base64.b64encode(buf.getvalue()).decode()
        
        # Don't enable yet - wait for verification
        config.totp_enabled = False
        config.updated_at = datetime.now(timezone.utc)
        
        await self._save_config(config)
        
        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{qr_code_data}",
            "provisioning_uri": provisioning_uri
        }
    
    async def verify_totp_setup(self, user_id: str, code: str) -> bool:
        """
        Verify TOTP setup with initial code.
        
        Args:
            user_id: User ID
            code: TOTP code to verify
            
        Returns:
            True if verification successful
        """
        config = await self._get_config(user_id)
        if not config or not config.totp_secret:
            return False
        
        # Verify code
        totp = pyotp.TOTP(config.totp_secret)
        if totp.verify(code, valid_window=self.totp_window):
            # Enable TOTP
            config.totp_enabled = True
            config.updated_at = datetime.now(timezone.utc)
            
            # Generate backup codes if first 2FA method
            if not config.has_2fa_enabled():
                config.backup_codes = await self._generate_backup_codes()
            
            await self._save_config(config)
            
            logger.info(f"TOTP enabled for user {user_id}")
            return True
        
        return False
    
    async def disable_totp(self, user_id: str) -> bool:
        """
        Disable TOTP for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if disabled successfully
        """
        config = await self._get_config(user_id)
        if not config:
            return False
        
        config.totp_enabled = False
        config.totp_secret = None
        config.updated_at = datetime.now(timezone.utc)
        
        await self._save_config(config)
        
        logger.info(f"TOTP disabled for user {user_id}")
        return True
    
    async def create_challenge(
        self,
        user_id: str,
        preferred_method: Optional[str] = None
    ) -> Optional[TwoFactorChallenge]:
        """
        Create a 2FA challenge for authentication.
        
        Args:
            user_id: User ID
            preferred_method: Preferred 2FA method
            
        Returns:
            Challenge object if 2FA is enabled
        """
        config = await self._get_config(user_id)
        if not config or not config.has_2fa_enabled():
            return None
        
        # Determine challenge type
        if preferred_method and getattr(config, f"{preferred_method}_enabled", False):
            challenge_type = preferred_method
        elif config.totp_enabled:
            challenge_type = "totp"
        elif config.sms_enabled:
            challenge_type = "sms"
        elif config.email_enabled:
            challenge_type = "email"
        else:
            return None
        
        # Create challenge
        challenge = TwoFactorChallenge(
            challenge_id=secrets.token_urlsafe(32),
            user_id=user_id,
            challenge_type=challenge_type,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.challenge_timeout_minutes)
        )
        
        # Send OTP for non-TOTP methods
        if challenge_type == "sms":
            otp = await self._send_sms_otp(config.sms_phone)
            challenge.metadata["otp_hash"] = self._hash_otp(otp)
        elif challenge_type == "email":
            otp = await self._send_email_otp(config.email_address)
            challenge.metadata["otp_hash"] = self._hash_otp(otp)
        
        # Save challenge
        await self._save_challenge(challenge)
        
        logger.info(f"Created {challenge_type} challenge for user {user_id}")
        return challenge
    
    async def verify_challenge(
        self,
        challenge_id: str,
        code: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a 2FA challenge.
        
        Args:
            challenge_id: Challenge ID
            code: Verification code
            
        Returns:
            Tuple of (success, error_message)
        """
        # Check rate limit
        challenge = await self._get_challenge(challenge_id)
        if not challenge:
            return False, "Invalid or expired challenge"
        
        if not await self._check_rate_limit(challenge.user_id):
            return False, "Too many attempts. Please try again later."
        
        # Check expiration
        if challenge.is_expired():
            await self._delete_challenge(challenge_id)
            return False, "Challenge expired"
        
        # Check attempts
        if not challenge.can_retry():
            await self._delete_challenge(challenge_id)
            return False, "Maximum attempts exceeded"
        
        # Increment attempts
        challenge.attempts += 1
        await self._save_challenge(challenge)
        
        # Verify based on type
        success = False
        
        if challenge.challenge_type == "totp":
            config = await self._get_config(challenge.user_id)
            if config and config.totp_secret:
                totp = pyotp.TOTP(config.totp_secret)
                success = totp.verify(code, valid_window=self.totp_window)
        
        elif challenge.challenge_type in ["sms", "email"]:
            otp_hash = challenge.metadata.get("otp_hash")
            if otp_hash:
                success = self._verify_otp_hash(code, otp_hash)
        
        elif challenge.challenge_type == "backup":
            success = await self._verify_backup_code(challenge.user_id, code)
        
        if success:
            challenge.verified = True
            await self._save_challenge(challenge)
            logger.info(f"Challenge {challenge_id} verified successfully")
            return True, None
        else:
            if challenge.can_retry():
                return False, f"Invalid code. {challenge.max_attempts - challenge.attempts} attempts remaining."
            else:
                await self._delete_challenge(challenge_id)
                return False, "Invalid code. Maximum attempts exceeded."
    
    async def verify_backup_code(self, user_id: str, code: str) -> bool:
        """
        Verify and consume a backup code.
        
        Args:
            user_id: User ID
            code: Backup code
            
        Returns:
            True if valid backup code
        """
        config = await self._get_config(user_id)
        if not config:
            return False
        
        # Normalize code (remove spaces/dashes)
        code = code.replace(" ", "").replace("-", "").upper()
        
        if code in config.backup_codes and code not in config.backup_codes_used:
            # Mark as used
            config.backup_codes_used.append(code)
            config.updated_at = datetime.now(timezone.utc)
            await self._save_config(config)
            
            logger.info(f"Backup code used for user {user_id}")
            return True
        
        return False
    
    async def regenerate_backup_codes(self, user_id: str) -> List[str]:
        """
        Regenerate backup codes for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of new backup codes
        """
        config = await self._get_config(user_id)
        if not config:
            config = TwoFactorConfig(user_id=user_id)
        
        # Generate new codes
        config.backup_codes = await self._generate_backup_codes()
        config.backup_codes_used = []
        config.updated_at = datetime.now(timezone.utc)
        
        await self._save_config(config)
        
        logger.info(f"Regenerated backup codes for user {user_id}")
        return config.backup_codes
    
    async def get_2fa_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get 2FA status for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with 2FA status
        """
        config = await self._get_config(user_id)
        if not config:
            return {
                "enabled": False,
                "methods": []
            }
        
        methods = []
        if config.totp_enabled:
            methods.append("totp")
        if config.sms_enabled:
            methods.append("sms")
        if config.email_enabled:
            methods.append("email")
        
        return {
            "enabled": config.has_2fa_enabled(),
            "methods": methods,
            "backup_codes_remaining": len(config.backup_codes) - len(config.backup_codes_used),
            "created_at": config.created_at.isoformat(),
            "updated_at": config.updated_at.isoformat()
        }
    
    async def admin_disable_2fa(
        self,
        user_id: str,
        admin_id: str,
        reason: str
    ) -> bool:
        """
        Admin override to disable 2FA for a user.
        
        Args:
            user_id: User ID to disable 2FA for
            admin_id: Admin user ID
            reason: Reason for disabling
            
        Returns:
            True if disabled successfully
        """
        config = await self._get_config(user_id)
        if not config:
            return False
        
        # Disable all methods
        config.totp_enabled = False
        config.totp_secret = None
        config.sms_enabled = False
        config.sms_phone = None
        config.email_enabled = False
        config.email_address = None
        config.backup_codes = []
        config.backup_codes_used = []
        config.updated_at = datetime.now(timezone.utc)
        
        # Add admin action to metadata
        if "admin_actions" not in config.__dict__:
            config.__dict__["admin_actions"] = []
        
        config.__dict__["admin_actions"].append({
            "action": "disabled_2fa",
            "admin_id": admin_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        await self._save_config(config)
        
        logger.warning(f"Admin {admin_id} disabled 2FA for user {user_id}, reason: {reason}")
        return True
    
    async def _get_config(self, user_id: str) -> Optional[TwoFactorConfig]:
        """Get 2FA configuration for a user."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        data = await redis.get(f"{self.CONFIG_PREFIX}{user_id}")
        if not data:
            return None
        
        return TwoFactorConfig.from_dict(eval(data))
    
    async def _save_config(self, config: TwoFactorConfig):
        """Save 2FA configuration."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Store indefinitely
        await redis.set(
            f"{self.CONFIG_PREFIX}{config.user_id}",
            str(config.to_dict())
        )
    
    async def _get_challenge(self, challenge_id: str) -> Optional[TwoFactorChallenge]:
        """Get a challenge by ID."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        data = await redis.get(f"{self.CHALLENGE_PREFIX}{challenge_id}")
        if not data:
            return None
        
        return TwoFactorChallenge.from_dict(eval(data))
    
    async def _save_challenge(self, challenge: TwoFactorChallenge):
        """Save a challenge."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        ttl = int((challenge.expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl > 0:
            await redis.setex(
                f"{self.CHALLENGE_PREFIX}{challenge.challenge_id}",
                ttl,
                str(challenge.to_dict())
            )
    
    async def _delete_challenge(self, challenge_id: str):
        """Delete a challenge."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        await redis.delete(f"{self.CHALLENGE_PREFIX}{challenge_id}")
    
    async def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user is rate limited."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        key = f"{self.RATE_LIMIT_PREFIX}{user_id}"
        attempts = await redis.incr(key)
        
        if attempts == 1:
            await redis.expire(key, self.rate_limit_window_minutes * 60)
        
        return attempts <= self.max_verify_attempts
    
    async def _generate_backup_codes(self) -> List[str]:
        """Generate backup codes."""
        codes = []
        for _ in range(self.backup_codes_count):
            # Generate 8-character codes in format XXXX-XXXX
            code = secrets.token_hex(4).upper()
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    def _hash_otp(self, otp: str) -> str:
        """Hash an OTP for storage."""
        # Use PBKDF2 for OTP hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"otp_salt",  # In production, use unique salt
            iterations=100000,
            backend=default_backend()
        )
        return base64.b64encode(kdf.derive(otp.encode())).decode()
    
    def _verify_otp_hash(self, otp: str, otp_hash: str) -> bool:
        """Verify an OTP against its hash."""
        return self._hash_otp(otp) == otp_hash
    
    async def _send_sms_otp(self, phone: str) -> str:
        """Send SMS OTP (placeholder)."""
        # Generate 6-digit OTP
        otp = str(secrets.randbelow(1000000)).zfill(6)
        
        # In production, integrate with SMS service
        logger.info(f"SMS OTP for {phone}: {otp} (not actually sent)")
        
        return otp
    
    async def _send_email_otp(self, email: str) -> str:
        """Send email OTP (placeholder)."""
        # Generate 6-digit OTP
        otp = str(secrets.randbelow(1000000)).zfill(6)
        
        # In production, integrate with email service
        logger.info(f"Email OTP for {email}: {otp} (not actually sent)")
        
        return otp
    
    async def _verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify backup code (internal method)."""
        return await self.verify_backup_code(user_id, code)
    
    async def close(self):
        """Close the service."""
        await self.redis_pool.close()
        logger.info("2FA service closed")