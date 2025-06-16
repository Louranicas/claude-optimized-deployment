"""User Management Service.

Provides comprehensive user management functionality including
creation, authentication, role assignment, and account management.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import secrets
import re
from email_validator import validate_email, EmailNotValidError
import pyotp
import qrcode
import io
import base64

from .models import User, UserStatus, APIKey, APIKeyStatus, UserRole
from .tokens import TokenManager
from .rbac import RBACManager
from .permissions import PermissionChecker
from ..core.exceptions import ValidationError, ConflictError, NotFoundError

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    AuthenticationError,\n    AuthorizationError,\n    ValidationError,\n    ResourceNotFoundError,\n    RateLimitError,\n    log_error
)

__all__ = [
    "UserCreationRequest",
    "PasswordResetRequest",
    "UserManager"
]



@dataclass
class UserCreationRequest:
    """Request for creating a new user."""
    username: str
    email: str
    password: str
    roles: List[str] = None
    metadata: Dict[str, Any] = None
    
    @handle_errors()
    def validate(self) -> None:
        """Validate user creation request."""
        # Username validation
        if not re.match(r"^[a-zA-Z0-9_-]{3,32}$", self.username):
            raise ValidationError(
                "Username must be 3-32 characters, alphanumeric, dash, or underscore"
            )
        
        # Email validation
        try:
            validate_email(self.email)
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email: {str(e)}")
        
        # Password validation
        if len(self.password) < 8:
            raise ValidationError("Password must be at least 8 characters")
        
        # Check password complexity
        has_upper = any(c.isupper() for c in self.password)
        has_lower = any(c.islower() for c in self.password)
        has_digit = any(c.isdigit() for c in self.password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in self.password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            raise ValidationError(
                "Password must contain uppercase, lowercase, digit, and special character"
            )


@dataclass
class PasswordResetRequest:
    """Request for password reset."""
    email: str
    
    @handle_errors()
    def validate(self) -> None:
        """Validate password reset request."""
        try:
            validate_email(self.email)
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email: {str(e)}")


class UserManager:
    """Comprehensive user management service."""
    
    def __init__(self, user_store: Any, token_manager: TokenManager,
                 rbac_manager: RBACManager, permission_checker: PermissionChecker):
        """
        Initialize user manager.
        
        Args:
            user_store: User storage backend
            token_manager: JWT token manager
            rbac_manager: RBAC manager
            permission_checker: Permission checker
        """
        self.user_store = user_store
        self.token_manager = token_manager
        self.rbac_manager = rbac_manager
        self.permission_checker = permission_checker
        
        # Password policy
        self.min_password_length = 8
        self.max_password_length = 128
        self.password_history_size = 5
        self.password_expiry_days = 90
        
        # Account lockout policy
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        
        # Session policy
        self.max_concurrent_sessions = 5
        self.session_timeout_minutes = 30
        
        # API key policy
        self.max_api_keys_per_user = 10
        self.api_key_expiry_days = 365
    
    async def create_user(self, request: UserCreationRequest, 
                         created_by: Optional[str] = None) -> User:
        """Create a new user."""
        # Validate request
        request.validate()
        
        # Check for existing user
        existing = await self.user_store.get_user_by_username(request.username)
        if existing:
            raise ConflictError(f"Username already exists: {request.username}")
        
        existing = await self.user_store.get_user_by_email(request.email)
        if existing:
            raise ConflictError(f"Email already exists: {request.email}")
        
        # Validate roles
        if request.roles:
            for role in request.roles:
                if not self.rbac_manager.get_role(role):
                    raise ValidationError(f"Invalid role: {role}")
        else:
            # Default role
            request.roles = ["viewer"]
        
        # Create user
        user = User.create(
            username=request.username,
            email=request.email,
            password=request.password
        )
        
        user.roles = request.roles
        user.metadata = request.metadata or {}
        
        # Set creator
        if created_by:
            user.metadata["created_by"] = created_by
        
        # Calculate initial permissions
        self._update_user_permissions(user)
        
        # Save user
        await self.user_store.create_user(user)
        
        # Audit user creation
        await self._audit_user_action(
            user_id=user.id,
            action="user_created",
            actor_id=created_by,
            details={"username": user.username, "roles": user.roles}
        )
        
        return user
    
    async def authenticate(self, username: str, password: str,
                          ip_address: Optional[str] = None) -> Tuple[User, Dict[str, str]]:
        """
        Authenticate user and return tokens.
        
        Returns:
            Tuple of (User, tokens) where tokens contains access and refresh tokens
        """
        # Get user by username or email
        user = await self.user_store.get_user_by_username(username)
        if not user:
            user = await self.user_store.get_user_by_email(username)
        
        if not user:
            # Don't reveal whether username exists
            raise ValidationError("Invalid username or password")
        
        # Check if account is locked
        if user.is_locked():
            raise ValidationError("Account is locked. Please try again later.")
        
        # Verify password
        if not user.verify_password(password):
            # Record failed attempt
            user.record_failed_login(self.max_failed_attempts)
            await self.user_store.update_user(user)
            
            # Audit failed login
            await self._audit_user_action(
                user_id=user.id,
                action="login_failed",
                details={"ip_address": ip_address}
            )
            
            raise ValidationError("Invalid username or password")
        
        # Check if account is active
        if user.status != UserStatus.ACTIVE:
            raise ValidationError(f"Account is {user.status.value}")
        
        # Record successful login
        user.record_successful_login()
        
        # Update permissions
        self._update_user_permissions(user)
        
        await self.user_store.update_user(user)
        
        # Generate tokens
        tokens = self.token_manager.create_token_pair(
            user_id=user.id,
            username=user.username,
            roles=user.roles,
            permissions=list(user.permissions)
        )
        
        # Audit successful login
        await self._audit_user_action(
            user_id=user.id,
            action="login_success",
            details={
                "ip_address": ip_address,
                "session_id": tokens["session_id"]
            }
        )
        
        return user, tokens
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, str]:
        """Refresh access token using refresh token."""
        # Verify refresh token
        token_data = self.token_manager.verify_token(refresh_token, token_type="refresh")
        if not token_data:
            raise ValidationError("Invalid refresh token")
        
        # Get user
        user = await self.user_store.get_user(token_data.user_id)
        if not user or user.status != UserStatus.ACTIVE:
            raise ValidationError("User not found or inactive")
        
        # Update permissions
        self._update_user_permissions(user)
        
        # Create new access token
        access_token = self.token_manager.refresh_access_token(
            refresh_token=refresh_token,
            user_id=user.id,
            username=user.username,
            roles=user.roles,
            permissions=list(user.permissions)
        )
        
        if not access_token:
            raise ValidationError("Failed to refresh token")
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.token_manager.access_token_expire_minutes * 60
        }
    
    async def logout(self, user_id: str, session_id: str) -> None:
        """Logout user and revoke session."""
        # Revoke session
        self.token_manager.revoke_session(session_id)
        
        # Audit logout
        await self._audit_user_action(
            user_id=user_id,
            action="logout",
            details={"session_id": session_id}
        )
    
    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        user = await self.user_store.get_user(user_id)
        if user:
            self._update_user_permissions(user)
        return user
    
    async def update_user(self, user_id: str, updates: Dict[str, Any],
                         updated_by: str) -> User:
        """Update user information."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Update allowed fields
        allowed_fields = {"email", "status", "metadata"}
        for field, value in updates.items():
            if field in allowed_fields:
                setattr(user, field, value)
        
        user.updated_at = datetime.now(timezone.utc)
        
        # Save changes
        await self.user_store.update_user(user)
        
        # Audit update
        await self._audit_user_action(
            user_id=user_id,
            action="user_updated",
            actor_id=updated_by,
            details={"fields": list(updates.keys())}
        )
        
        return user
    
    async def delete_user(self, user_id: str, deleted_by: str) -> None:
        """Delete (deactivate) a user."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Don't actually delete, just deactivate
        user.status = UserStatus.INACTIVE
        user.updated_at = datetime.now(timezone.utc)
        user.metadata["deleted_by"] = deleted_by
        user.metadata["deleted_at"] = datetime.now(timezone.utc).isoformat()
        
        await self.user_store.update_user(user)
        
        # Revoke all sessions
        for refresh_token in user.refresh_tokens:
            self.token_manager.revoke_token(refresh_token)
        
        # Audit deletion
        await self._audit_user_action(
            user_id=user_id,
            action="user_deleted",
            actor_id=deleted_by
        )
    
    async def change_password(self, user_id: str, old_password: str,
                            new_password: str) -> None:
        """Change user password."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Verify old password
        if not user.verify_password(old_password):
            raise ValidationError("Invalid current password")
        
        # Validate new password
        request = UserCreationRequest(
            username=user.username,
            email=user.email,
            password=new_password
        )
        try:
            request.validate()
        except ValidationError as e:
            if "Password" in str(e):
                raise
            # Ignore other validation errors for password change
        
        # Update password
        user.update_password(new_password)
        
        # Revoke all sessions (force re-login)
        for refresh_token in user.refresh_tokens:
            self.token_manager.revoke_token(refresh_token)
        user.refresh_tokens = []
        
        await self.user_store.update_user(user)
        
        # Audit password change
        await self._audit_user_action(
            user_id=user_id,
            action="password_changed"
        )
    
    async def reset_password_request(self, request: PasswordResetRequest) -> str:
        """Request password reset token."""
        request.validate()
        
        user = await self.user_store.get_user_by_email(request.email)
        if not user:
            # Don't reveal if email exists
            return "If the email exists, a reset link has been sent"
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        
        await self.user_store.update_user(user)
        
        # Audit reset request
        await self._audit_user_action(
            user_id=user.id,
            action="password_reset_requested"
        )
        
        # In production, send email with reset link
        # For now, return the token (DO NOT do this in production!)
        return reset_token
    
    async def reset_password(self, token: str, new_password: str) -> None:
        """Reset password using reset token."""
        # Find user with token
        user = await self.user_store.get_user_by_reset_token(token)
        if not user:
            raise ValidationError("Invalid or expired reset token")
        
        # Check token expiry
        if user.password_reset_expires < datetime.now(timezone.utc):
            raise ValidationError("Reset token has expired")
        
        # Validate new password
        request = UserCreationRequest(
            username=user.username,
            email=user.email,
            password=new_password
        )
        try:
            request.validate()
        except ValidationError as e:
            if "Password" in str(e):
                raise
        
        # Update password
        user.update_password(new_password)
        
        # Revoke all sessions
        for refresh_token in user.refresh_tokens:
            self.token_manager.revoke_token(refresh_token)
        user.refresh_tokens = []
        
        await self.user_store.update_user(user)
        
        # Audit password reset
        await self._audit_user_action(
            user_id=user.id,
            action="password_reset_completed"
        )
    
    async def enable_mfa(self, user_id: str) -> Dict[str, str]:
        """Enable MFA for user and return QR code."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        if user.mfa_enabled:
            raise ValidationError("MFA is already enabled")
        
        # Generate secret
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        
        # Generate provisioning URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="Claude Optimized Deployment"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        
        # Convert to base64
        qr_code = base64.b64encode(buf.getvalue()).decode()
        
        await self.user_store.update_user(user)
        
        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{qr_code}",
            "uri": totp_uri
        }
    
    async def verify_mfa(self, user_id: str, code: str) -> bool:
        """Verify MFA code."""
        user = await self.user_store.get_user(user_id)
        if not user or not user.mfa_secret:
            return False
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(code, valid_window=1)
    
    async def disable_mfa(self, user_id: str, password: str) -> None:
        """Disable MFA for user."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Verify password
        if not user.verify_password(password):
            raise ValidationError("Invalid password")
        
        user.mfa_enabled = False
        user.mfa_secret = None
        
        await self.user_store.update_user(user)
        
        # Audit MFA disabled
        await self._audit_user_action(
            user_id=user_id,
            action="mfa_disabled"
        )
    
    async def assign_role(self, user_id: str, role_name: str,
                         assigned_by: str, expires_at: Optional[datetime] = None) -> None:
        """Assign a role to user."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Validate role
        role = self.rbac_manager.get_role(role_name)
        if not role:
            raise ValidationError(f"Invalid role: {role_name}")
        
        # Add role
        user.add_role(role_name)
        
        # Create role assignment record
        user_role = UserRole(
            user_id=user_id,
            role_name=role_name,
            granted_by=assigned_by,
            expires_at=expires_at
        )
        
        # Update permissions
        self._update_user_permissions(user)
        
        await self.user_store.update_user(user)
        await self.user_store.create_user_role(user_role)
        
        # Audit role assignment
        await self._audit_user_action(
            user_id=user_id,
            action="role_assigned",
            actor_id=assigned_by,
            details={"role": role_name}
        )
    
    async def remove_role(self, user_id: str, role_name: str,
                         removed_by: str) -> None:
        """Remove a role from user."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Remove role
        user.remove_role(role_name)
        
        # Update permissions
        self._update_user_permissions(user)
        
        await self.user_store.update_user(user)
        await self.user_store.delete_user_role(user_id, role_name)
        
        # Audit role removal
        await self._audit_user_action(
            user_id=user_id,
            action="role_removed",
            actor_id=removed_by,
            details={"role": role_name}
        )
    
    async def create_api_key(self, user_id: str, name: str,
                           permissions: Optional[List[str]] = None,
                           expires_at: Optional[datetime] = None) -> Tuple[APIKey, str]:
        """Create an API key for user."""
        user = await self.user_store.get_user(user_id)
        if not user:
            raise NotFoundError(f"User not found: {user_id}")
        
        # Check API key limit
        user_keys = await self.user_store.get_user_api_keys(user_id)
        if len(user_keys) >= self.max_api_keys_per_user:
            raise ValidationError(f"Maximum API keys limit reached: {self.max_api_keys_per_user}")
        
        # Create API key
        api_key, raw_key = APIKey.create(
            name=name,
            user_id=user_id
        )
        
        # Set permissions (default to user's permissions)
        if permissions:
            # Validate permissions
            for perm in permissions:
                if perm not in user.permissions:
                    raise ValidationError(f"User does not have permission: {perm}")
            api_key.permissions = set(permissions)
        else:
            api_key.permissions = user.permissions.copy()
        
        # Set expiry
        if not expires_at:
            expires_at = datetime.now(timezone.utc) + timedelta(days=self.api_key_expiry_days)
        api_key.expires_at = expires_at
        
        # Save API key
        await self.user_store.create_api_key(api_key)
        
        # Audit API key creation
        await self._audit_user_action(
            user_id=user_id,
            action="api_key_created",
            details={"key_id": api_key.id, "name": name}
        )
        
        return api_key, raw_key
    
    async def revoke_api_key(self, user_id: str, key_id: str) -> None:
        """Revoke an API key."""
        api_key = await self.user_store.get_api_key(key_id)
        if not api_key or api_key.user_id != user_id:
            raise NotFoundError(f"API key not found: {key_id}")
        
        api_key.revoke()
        await self.user_store.update_api_key(api_key)
        
        # Audit API key revocation
        await self._audit_user_action(
            user_id=user_id,
            action="api_key_revoked",
            details={"key_id": key_id}
        )
    
    async def list_users(self, offset: int = 0, limit: int = 100,
                        status: Optional[UserStatus] = None) -> List[User]:
        """List users with pagination."""
        users = await self.user_store.list_users(offset, limit, status)
        
        # Update permissions for each user
        for user in users:
            self._update_user_permissions(user)
        
        return users
    
    async def search_users(self, query: str) -> List[User]:
        """Search users by username or email."""
        users = await self.user_store.search_users(query)
        
        # Update permissions for each user
        for user in users:
            self._update_user_permissions(user)
        
        return users
    
    def _update_user_permissions(self, user: User) -> None:
        """Update user's effective permissions based on roles."""
        all_permissions = set()
        
        for role_name in user.roles:
            role = self.rbac_manager.get_role(role_name)
            if role:
                role_perms = role.get_all_permissions(self.rbac_manager)
                for perm in role_perms:
                    all_permissions.add(str(perm))
        
        user.permissions = all_permissions
    
    async def _audit_user_action(self, user_id: str, action: str,
                               actor_id: Optional[str] = None,
                               details: Optional[Dict[str, Any]] = None) -> None:
        """Audit user-related actions."""
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "action": action,
            "actor_id": actor_id or user_id,
            "details": details or {}
        }
        
        # In production, this would go to an audit log service
        print(f"USER_AUDIT: {audit_entry}")