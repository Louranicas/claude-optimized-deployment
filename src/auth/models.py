"""Authentication and Authorization Models.

Following OWASP guidelines for secure user and permission modeling.
"""

from datetime import datetime, timezone
from typing import Optional, List, Set, Dict, Any
from enum import Enum
import secrets
import hashlib
from dataclasses import dataclass, field
import bcrypt


class UserStatus(Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"


class APIKeyStatus(Enum):
    """API key status."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class User:
    """User model with secure password handling."""
    
    id: str
    username: str
    email: str
    password_hash: str
    roles: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    email_verified: bool = False
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    refresh_tokens: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create(cls, username: str, email: str, password: str) -> "User":
        """Create a new user with hashed password."""
        # Generate secure user ID
        user_id = f"user_{secrets.token_urlsafe(16)}"
        
        # Hash password using bcrypt (OWASP recommended)
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)  # OWASP recommends 10+ rounds
        ).decode('utf-8')
        
        return cls(
            id=user_id,
            username=username,
            email=email.lower(),
            password_hash=password_hash
        )
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    def update_password(self, new_password: str) -> None:
        """Update user password."""
        self.password_hash = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
        self.updated_at = datetime.now(timezone.utc)
        self.password_reset_token = None
        self.password_reset_expires = None
    
    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if self.status == UserStatus.LOCKED:
            return True
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return True
        return False
    
    def record_failed_login(self, max_attempts: int = 5) -> None:
        """Record failed login attempt."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.status = UserStatus.LOCKED
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def record_successful_login(self) -> None:
        """Record successful login."""
        self.failed_login_attempts = 0
        self.last_login = datetime.now(timezone.utc)
        if self.locked_until:
            self.locked_until = None
        if self.status == UserStatus.LOCKED:
            self.status = UserStatus.ACTIVE
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def add_role(self, role: str) -> None:
        """Add a role to user."""
        if role not in self.roles:
            self.roles.append(role)
            self.updated_at = datetime.now(timezone.utc)
    
    def remove_role(self, role: str) -> None:
        """Remove a role from user."""
        if role in self.roles:
            self.roles.remove(role)
            self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "roles": self.roles,
            "permissions": list(self.permissions),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "email_verified": self.email_verified,
            "mfa_enabled": self.mfa_enabled,
            "metadata": self.metadata
        }
        
        if include_sensitive:
            data.update({
                "failed_login_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            })
        
        return data


@dataclass
class UserRole:
    """User role assignment with expiration support."""
    
    user_id: str
    role_name: str
    granted_by: str
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if role assignment has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if role assignment is valid."""
        return not self.is_expired()


@dataclass
class APIKey:
    """API Key model for service authentication."""
    
    id: str
    key_hash: str
    name: str
    user_id: Optional[str]
    service_name: Optional[str]
    permissions: Set[str] = field(default_factory=set)
    rate_limit: Optional[int] = None
    expires_at: Optional[datetime] = None
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: Optional[datetime] = None
    usage_count: int = 0
    allowed_ips: List[str] = field(default_factory=list)
    allowed_endpoints: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create(cls, name: str, user_id: Optional[str] = None, 
               service_name: Optional[str] = None) -> tuple["APIKey", str]:
        """Create a new API key and return the key and its model."""
        # Generate secure API key
        key_id = f"apikey_{secrets.token_urlsafe(8)}"
        raw_key = secrets.token_urlsafe(32)
        
        # Hash the key for storage (never store raw keys)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        api_key = cls(
            id=key_id,
            key_hash=key_hash,
            name=name,
            user_id=user_id,
            service_name=service_name
        )
        
        # Return both the model and the raw key (only shown once)
        return api_key, f"{key_id}.{raw_key}"
    
    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Hash an API key for comparison."""
        return hashlib.sha256(raw_key.encode()).hexdigest()
    
    def verify_key(self, raw_key: str) -> bool:
        """Verify an API key against the hash."""
        return self.key_hash == self.hash_key(raw_key)
    
    def is_valid(self) -> bool:
        """Check if API key is valid."""
        if self.status != APIKeyStatus.ACTIVE:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            self.status = APIKeyStatus.EXPIRED
            return False
        return True
    
    def record_usage(self) -> None:
        """Record API key usage."""
        self.usage_count += 1
        self.last_used = datetime.now(timezone.utc)
    
    def check_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP address is allowed."""
        if not self.allowed_ips:
            return True  # No IP restrictions
        return ip_address in self.allowed_ips
    
    def check_endpoint_allowed(self, endpoint: str) -> bool:
        """Check if endpoint is allowed."""
        if not self.allowed_endpoints:
            return True  # No endpoint restrictions
        
        # Check exact match or wildcard patterns
        for allowed in self.allowed_endpoints:
            if allowed.endswith("*"):
                if endpoint.startswith(allowed[:-1]):
                    return True
            elif endpoint == allowed:
                return True
        
        return False
    
    def revoke(self) -> None:
        """Revoke the API key."""
        self.status = APIKeyStatus.REVOKED
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "service_name": self.service_name,
            "permissions": list(self.permissions),
            "rate_limit": self.rate_limit,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "usage_count": self.usage_count,
            "metadata": self.metadata
        }
        
        if include_sensitive:
            data.update({
                "allowed_ips": self.allowed_ips,
                "allowed_endpoints": self.allowed_endpoints,
            })
        
        return data


# Import timedelta after using it
from datetime import timedelta