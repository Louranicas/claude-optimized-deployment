"""
Cache security features including encryption, access control, and audit logging.

This module provides comprehensive security features for the distributed cache:
- Data encryption at rest and in transit
- Access control with role-based permissions
- Audit logging for all cache operations
- Key validation and sanitization
- Rate limiting and abuse prevention
"""

import hashlib
import hmac
import time
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Callable, Pattern, Tuple
from enum import Enum
import structlog

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets

__all__ = [
    "SecurityLevel",
    "Permission",
    "Role",
    "SecurityConfig",
    "CacheSecurityManager",
    "AccessControlManager",
    "AuditLogger",
    "KeyValidator",
    "RateLimiter",
    "EncryptionManager"
]

logger = structlog.get_logger(__name__)


class SecurityLevel(Enum):
    """Security levels for cache operations."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Permission(Enum):
    """Cache operation permissions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    MONITOR = "monitor"


@dataclass
class Role:
    """User role with permissions."""
    name: str
    permissions: Set[Permission]
    key_patterns: List[str] = field(default_factory=list)  # Allowed key patterns
    rate_limit: Optional[int] = None  # Operations per minute
    security_level: SecurityLevel = SecurityLevel.INTERNAL
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if role has specific permission."""
        return permission in self.permissions or Permission.ADMIN in self.permissions
    
    def can_access_key(self, key: str) -> bool:
        """Check if role can access specific key."""
        if not self.key_patterns:
            return True  # No restrictions
        
        for pattern in self.key_patterns:
            if re.match(pattern, key):
                return True
        return False


@dataclass
class SecurityConfig:
    """Security configuration for cache."""
    # Encryption settings
    enable_encryption: bool = True
    encryption_algorithm: str = "AES256"
    key_rotation_interval: int = 86400  # 24 hours
    
    # Access control settings
    enable_access_control: bool = True
    default_role: str = "user"
    session_timeout: int = 3600  # 1 hour
    
    # Audit settings
    enable_audit_logging: bool = True
    audit_log_level: str = "INFO"
    audit_retention_days: int = 30
    
    # Rate limiting
    enable_rate_limiting: bool = True
    default_rate_limit: int = 1000  # Operations per minute
    burst_allowance: int = 100
    
    # Key validation
    enable_key_validation: bool = True
    max_key_length: int = 250
    allowed_key_characters: str = r"[a-zA-Z0-9:._-]+"
    blocked_key_patterns: List[str] = field(default_factory=list)
    
    # Security monitoring
    enable_security_monitoring: bool = True
    failed_auth_threshold: int = 5
    suspicious_pattern_threshold: int = 10


class EncryptionManager:
    """Manages encryption keys and operations."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._keys: Dict[str, Fernet] = {}
        self._current_key_id = None
        self._key_rotation_time = time.time()
        
        if config.enable_encryption:
            self._generate_initial_key()
    
    def _generate_initial_key(self) -> None:
        """Generate initial encryption key."""
        key = Fernet.generate_key()
        key_id = hashlib.sha256(key).hexdigest()[:16]
        
        self._keys[key_id] = Fernet(key)
        self._current_key_id = key_id
        self._key_rotation_time = time.time()
        
        logger.info("Initial encryption key generated", key_id=key_id)
    
    def _should_rotate_key(self) -> bool:
        """Check if key should be rotated."""
        return (time.time() - self._key_rotation_time) > self.config.key_rotation_interval
    
    def rotate_key(self) -> str:
        """Rotate encryption key."""
        if not self.config.enable_encryption:
            return None
        
        # Generate new key
        new_key = Fernet.generate_key()
        new_key_id = hashlib.sha256(new_key).hexdigest()[:16]
        
        self._keys[new_key_id] = Fernet(new_key)
        old_key_id = self._current_key_id
        self._current_key_id = new_key_id
        self._key_rotation_time = time.time()
        
        logger.info("Encryption key rotated", old_key_id=old_key_id, new_key_id=new_key_id)
        return new_key_id
    
    def encrypt(self, data: bytes) -> Tuple[str, bytes]:
        """Encrypt data with current key."""
        if not self.config.enable_encryption:
            return None, data
        
        if self._should_rotate_key():
            self.rotate_key()
        
        encrypted_data = self._keys[self._current_key_id].encrypt(data)
        return self._current_key_id, encrypted_data
    
    def decrypt(self, key_id: str, encrypted_data: bytes) -> bytes:
        """Decrypt data with specified key."""
        if not self.config.enable_encryption or key_id is None:
            return encrypted_data
        
        if key_id not in self._keys:
            raise ValueError(f"Encryption key not found: {key_id}")
        
        return self._keys[key_id].decrypt(encrypted_data)
    
    def get_current_key_id(self) -> str:
        """Get current encryption key ID."""
        return self._current_key_id


class KeyValidator:
    """Validates and sanitizes cache keys."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._key_pattern = re.compile(config.allowed_key_characters) if config.enable_key_validation else None
        self._blocked_patterns = [re.compile(pattern) for pattern in config.blocked_key_patterns]
    
    def validate_key(self, key: str) -> bool:
        """Validate cache key according to security rules."""
        if not self.config.enable_key_validation:
            return True
        
        # Check key length
        if len(key) > self.config.max_key_length:
            logger.warning("Key too long", key=key[:50] + "...", length=len(key))
            return False
        
        # Check allowed characters
        if self._key_pattern and not self._key_pattern.fullmatch(key):
            logger.warning("Key contains invalid characters", key=key)
            return False
        
        # Check blocked patterns
        for pattern in self._blocked_patterns:
            if pattern.search(key):
                logger.warning("Key matches blocked pattern", key=key)
                return False
        
        return True
    
    def sanitize_key(self, key: str) -> str:
        """Sanitize key by removing invalid characters."""
        if not self.config.enable_key_validation:
            return key
        
        # Remove invalid characters
        sanitized = re.sub(r'[^a-zA-Z0-9:._-]', '_', key)
        
        # Truncate if too long
        if len(sanitized) > self.config.max_key_length:
            sanitized = sanitized[:self.config.max_key_length]
        
        return sanitized


class RateLimiter:
    """Rate limiting for cache operations."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._user_limits: Dict[str, Dict[str, Any]] = {}
        self._global_limits: Dict[str, Any] = {
            'count': 0,
            'window_start': time.time()
        }
    
    def is_allowed(self, user_id: str, operation: str, role: Role = None) -> bool:
        """Check if operation is allowed for user."""
        if not self.config.enable_rate_limiting:
            return True
        
        current_time = time.time()
        window_duration = 60  # 1 minute window
        
        # Get user rate limit
        rate_limit = role.rate_limit if role and role.rate_limit else self.config.default_rate_limit
        
        # Initialize user tracking if not exists
        if user_id not in self._user_limits:
            self._user_limits[user_id] = {
                'count': 0,
                'window_start': current_time,
                'burst_tokens': self.config.burst_allowance
            }
        
        user_data = self._user_limits[user_id]
        
        # Reset window if expired
        if current_time - user_data['window_start'] >= window_duration:
            user_data['count'] = 0
            user_data['window_start'] = current_time
            user_data['burst_tokens'] = self.config.burst_allowance
        
        # Check burst allowance first
        if user_data['burst_tokens'] > 0:
            user_data['burst_tokens'] -= 1
            user_data['count'] += 1
            return True
        
        # Check rate limit
        if user_data['count'] >= rate_limit:
            logger.warning(
                "Rate limit exceeded",
                user_id=user_id,
                operation=operation,
                count=user_data['count'],
                limit=rate_limit
            )
            return False
        
        user_data['count'] += 1
        return True
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get rate limiting stats for user."""
        if user_id not in self._user_limits:
            return {'count': 0, 'remaining': self.config.default_rate_limit}
        
        user_data = self._user_limits[user_id]
        remaining = max(0, self.config.default_rate_limit - user_data['count'])
        
        return {
            'count': user_data['count'],
            'remaining': remaining,
            'burst_tokens': user_data['burst_tokens'],
            'window_start': user_data['window_start']
        }


class AuditLogger:
    """Audit logging for cache operations."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.audit_logger = structlog.get_logger("cache.audit")
    
    async def log_operation(
        self,
        user_id: str,
        operation: str,
        key: str,
        success: bool,
        metadata: Dict[str, Any] = None
    ) -> None:
        """Log cache operation for audit purposes."""
        if not self.config.enable_audit_logging:
            return
        
        audit_entry = {
            "timestamp": time.time(),
            "user_id": user_id,
            "operation": operation,
            "key": key,
            "success": success,
            "metadata": metadata or {}
        }
        
        if success:
            self.audit_logger.info("Cache operation", **audit_entry)
        else:
            self.audit_logger.warning("Failed cache operation", **audit_entry)
    
    async def log_security_event(
        self,
        event_type: str,
        user_id: str,
        details: Dict[str, Any]
    ) -> None:
        """Log security-related events."""
        security_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details
        }
        
        self.audit_logger.warning("Security event", **security_entry)


class AccessControlManager:
    """Manages user access control and permissions."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._roles: Dict[str, Role] = {}
        self._users: Dict[str, str] = {}  # user_id -> role_name
        self._sessions: Dict[str, Dict[str, Any]] = {}
        
        self._setup_default_roles()
    
    def _setup_default_roles(self) -> None:
        """Setup default roles."""
        # Public role - read-only access to public data
        self._roles["public"] = Role(
            name="public",
            permissions={Permission.READ},
            key_patterns=["public:*"],
            rate_limit=100,
            security_level=SecurityLevel.PUBLIC
        )
        
        # User role - standard user access
        self._roles["user"] = Role(
            name="user",
            permissions={Permission.READ, Permission.WRITE},
            rate_limit=1000,
            security_level=SecurityLevel.INTERNAL
        )
        
        # Admin role - full access
        self._roles["admin"] = Role(
            name="admin",
            permissions={Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN, Permission.MONITOR},
            security_level=SecurityLevel.RESTRICTED
        )
    
    def add_role(self, role: Role) -> None:
        """Add custom role."""
        self._roles[role.name] = role
        logger.info("Role added", role_name=role.name)
    
    def assign_role(self, user_id: str, role_name: str) -> bool:
        """Assign role to user."""
        if role_name not in self._roles:
            logger.error("Role not found", role_name=role_name)
            return False
        
        self._users[user_id] = role_name
        logger.info("Role assigned", user_id=user_id, role_name=role_name)
        return True
    
    def get_user_role(self, user_id: str) -> Optional[Role]:
        """Get user's role."""
        role_name = self._users.get(user_id, self.config.default_role)
        return self._roles.get(role_name)
    
    def create_session(self, user_id: str, metadata: Dict[str, Any] = None) -> str:
        """Create user session."""
        session_id = secrets.token_urlsafe(32)
        session_data = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "metadata": metadata or {}
        }
        
        self._sessions[session_id] = session_data
        logger.info("Session created", user_id=user_id, session_id=session_id)
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """Validate session and return user_id."""
        if session_id not in self._sessions:
            return None
        
        session_data = self._sessions[session_id]
        current_time = time.time()
        
        # Check session timeout
        if current_time - session_data["last_activity"] > self.config.session_timeout:
            del self._sessions[session_id]
            logger.info("Session expired", session_id=session_id)
            return None
        
        # Update last activity
        session_data["last_activity"] = current_time
        return session_data["user_id"]
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke user session."""
        if session_id in self._sessions:
            user_id = self._sessions[session_id]["user_id"]
            del self._sessions[session_id]
            logger.info("Session revoked", user_id=user_id, session_id=session_id)
            return True
        return False
    
    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        key: str = None
    ) -> bool:
        """Check if user has permission for operation."""
        if not self.config.enable_access_control:
            return True
        
        role = self.get_user_role(user_id)
        if not role:
            return False
        
        # Check permission
        if not role.has_permission(permission):
            return False
        
        # Check key access if specified
        if key and not role.can_access_key(key):
            return False
        
        return True


class CacheSecurityManager:
    """Main security manager coordinating all security features."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.encryption_manager = EncryptionManager(config)
        self.key_validator = KeyValidator(config)
        self.rate_limiter = RateLimiter(config)
        self.audit_logger = AuditLogger(config)
        self.access_control = AccessControlManager(config)
        
        # Security monitoring
        self._failed_auth_attempts: Dict[str, List[float]] = {}
        self._suspicious_patterns: Dict[str, int] = {}
    
    async def authorize_operation(
        self,
        session_id: str,
        operation: str,
        key: str,
        metadata: Dict[str, Any] = None
    ) -> Tuple[bool, Optional[str], Optional[Role]]:
        """Authorize cache operation."""
        # Validate session
        user_id = self.access_control.validate_session(session_id)
        if not user_id:
            await self.audit_logger.log_security_event(
                "invalid_session",
                session_id,
                {"operation": operation, "key": key}
            )
            return False, None, None
        
        # Get user role
        role = self.access_control.get_user_role(user_id)
        if not role:
            await self.audit_logger.log_security_event(
                "no_role",
                user_id,
                {"operation": operation, "key": key}
            )
            return False, user_id, None
        
        # Check permissions
        permission_map = {
            "get": Permission.READ,
            "set": Permission.WRITE,
            "delete": Permission.DELETE,
            "clear": Permission.ADMIN,
            "info": Permission.MONITOR
        }
        
        required_permission = permission_map.get(operation, Permission.READ)
        if not self.access_control.check_permission(user_id, required_permission, key):
            await self.audit_logger.log_security_event(
                "permission_denied",
                user_id,
                {"operation": operation, "key": key, "permission": required_permission.value}
            )
            return False, user_id, role
        
        # Validate key
        if not self.key_validator.validate_key(key):
            await self.audit_logger.log_security_event(
                "invalid_key",
                user_id,
                {"operation": operation, "key": key}
            )
            return False, user_id, role
        
        # Check rate limits
        if not self.rate_limiter.is_allowed(user_id, operation, role):
            await self.audit_logger.log_security_event(
                "rate_limit_exceeded",
                user_id,
                {"operation": operation, "key": key}
            )
            return False, user_id, role
        
        return True, user_id, role
    
    async def secure_value(self, value: bytes) -> Tuple[Optional[str], bytes]:
        """Encrypt value if encryption is enabled."""
        return self.encryption_manager.encrypt(value)
    
    async def unsecure_value(self, key_id: Optional[str], encrypted_value: bytes) -> bytes:
        """Decrypt value if it was encrypted."""
        return self.encryption_manager.decrypt(key_id, encrypted_value)
    
    async def log_operation(
        self,
        user_id: str,
        operation: str,
        key: str,
        success: bool,
        metadata: Dict[str, Any] = None
    ) -> None:
        """Log operation for audit purposes."""
        await self.audit_logger.log_operation(user_id, operation, key, success, metadata)
    
    def sanitize_key(self, key: str) -> str:
        """Sanitize cache key."""
        return self.key_validator.sanitize_key(key)
    
    def create_user_session(self, user_id: str, metadata: Dict[str, Any] = None) -> str:
        """Create user session."""
        return self.access_control.create_session(user_id, metadata)
    
    def assign_user_role(self, user_id: str, role_name: str) -> bool:
        """Assign role to user."""
        return self.access_control.assign_role(user_id, role_name)
    
    def add_custom_role(self, role: Role) -> None:
        """Add custom role."""
        self.access_control.add_role(role)
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get user statistics."""
        return {
            "rate_limit": self.rate_limiter.get_user_stats(user_id),
            "role": self.access_control.get_user_role(user_id).name if self.access_control.get_user_role(user_id) else None,
            "current_key_id": self.encryption_manager.get_current_key_id()
        }
    
    async def rotate_encryption_key(self) -> str:
        """Manually rotate encryption key."""
        return self.encryption_manager.rotate_key()
    
    def monitor_security_events(self) -> Dict[str, Any]:
        """Get security monitoring statistics."""
        return {
            "failed_auth_attempts": len(self._failed_auth_attempts),
            "suspicious_patterns": self._suspicious_patterns,
            "active_sessions": len(self.access_control._sessions),
            "encryption_enabled": self.config.enable_encryption,
            "access_control_enabled": self.config.enable_access_control
        }