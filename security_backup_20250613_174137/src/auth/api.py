"""Authentication API Endpoints.

FastAPI endpoints for user authentication, authorization, and management.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta
import asyncio
import os
import logging

from .user_manager import UserManager, UserCreationRequest, PasswordResetRequest
from .models import User, APIKey, UserStatus
from .tokens import TokenManager, TokenData
from .rbac import RBACManager
from .permissions import PermissionChecker
from .middleware import AuthMiddleware, get_current_user_dependency
from .audit import AuditLogger, AuditEventType, AuditSeverity
from .audit_config import get_audit_logger
from .token_revocation import TokenRevocationService
from .session_manager import SessionManager
from .two_factor import TwoFactorService
from ..core.connections import ConnectionPoolConfig
from ..database.connection import get_db_connection
from ..database.repositories.user_repository import UserRepository

from ..core.rate_limit_middleware import rate_limit_dependency

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    DatabaseError,
    ResourceNotFoundError,
    RateLimitError,
    log_error
)

logger = logging.getLogger(__name__)

__all__ = [
    "LoginRequest",
    "LoginResponse",
    "RefreshTokenRequest",
    "ChangePasswordRequest",
    "ResetPasswordRequest",
    "CreateUserRequest",
    "UpdateUserRequest",
    "AssignRoleRequest",
    "CreateAPIKeyRequest",
    "APIKeyResponse",
    "get_auth_dependencies",
    "require_permission"
]



# Request/Response models
class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=6)


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: Dict[str, Any]


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    """Change password request model."""
    old_password: str
    new_password: str = Field(..., min_length=8)


class ResetPasswordRequest(BaseModel):
    """Reset password request model."""
    token: str
    new_password: str = Field(..., min_length=8)


class CreateUserRequest(BaseModel):
    """Create user request model."""
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=8)
    roles: Optional[List[str]] = None


class UpdateUserRequest(BaseModel):
    """Update user request model."""
    email: Optional[EmailStr] = None
    status: Optional[UserStatus] = None
    metadata: Optional[Dict[str, Any]] = None


class AssignRoleRequest(BaseModel):
    """Assign role request model."""
    role_name: str
    expires_at: Optional[datetime] = None


class CreateAPIKeyRequest(BaseModel):
    """Create API key request model."""
    name: str = Field(..., min_length=1, max_length=64)
    permissions: Optional[List[str]] = None
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    """API key response model."""
    id: str
    name: str
    key: str  # Only shown once during creation
    permissions: List[str]
    expires_at: Optional[datetime]


# Initialize components with production configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")  # Must be set in production

# Initialize services
token_manager = TokenManager(secret_key=JWT_SECRET_KEY)
rbac_manager = RBACManager()
permission_checker = PermissionChecker(rbac_manager)
audit_logger = get_audit_logger()

# Initialize Redis-backed services
token_revocation_service = TokenRevocationService(REDIS_URL)
session_manager = SessionManager(REDIS_URL)
two_factor_service = TwoFactorService(REDIS_URL)

# These will be initialized on startup
user_manager: Optional[UserManager] = None
auth_middleware: Optional[AuthMiddleware] = None
user_repository: Optional[UserRepository] = None

# Flag to track initialization
_initialized = False

# Security scheme
security = HTTPBearer()

# Router
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


async def initialize_auth_services():
    """Initialize authentication services on startup."""
    global user_manager, auth_middleware, user_repository, _initialized
    
    if _initialized:
        return
    
    # Initialize Redis services
    await token_revocation_service.initialize()
    await session_manager.initialize()
    await two_factor_service.initialize()
    
    # Get database connection
    db = await get_db_connection()
    user_repository = UserRepository(db)
    
    # Initialize user manager with real storage
    user_manager = UserManager(
        user_store=user_repository,
        token_manager=token_manager,
        rbac_manager=rbac_manager,
        permission_checker=permission_checker
    )
    
    # Initialize auth middleware
    auth_middleware = AuthMiddleware(
        token_manager=token_manager,
        rbac_manager=rbac_manager,
        permission_checker=permission_checker,
        token_revocation_service=token_revocation_service,
        session_manager=session_manager
    )
    
    _initialized = True
    logger.info("Authentication services initialized")


def get_auth_dependencies():
    """Get authentication dependencies."""
    if not _initialized:
        raise RuntimeError("Authentication services not initialized. Call initialize_auth_services() first.")
    
    return user_manager, auth_middleware


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> User:
    """Get current authenticated user."""
    _, middleware = get_auth_dependencies()
    
    # Extract token from credentials
    token = credentials.credentials
    
    # Verify token and check revocation
    token_data = token_manager.verify_token(token)
    if not token_data:
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            ip_address=request.client.host if request and request.client else None,
            result="failure",
            details={"reason": "Invalid token"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if token is revoked
    if await token_revocation_service.is_token_revoked(token_data.jti):
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            user_id=token_data.user_id,
            ip_address=request.client.host if request and request.client else None,
            result="failure",
            details={"reason": "Token revoked"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if session is revoked
    if token_data.session_id and await token_revocation_service.is_session_revoked(token_data.session_id):
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            user_id=token_data.user_id,
            ip_address=request.client.host if request and request.client else None,
            result="failure",
            details={"reason": "Session revoked"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update session activity
    if token_data.session_id:
        await session_manager.update_activity(
            session_id=token_data.session_id,
            ip_address=request.client.host if request and request.client else None
        )
    
    # Get user from repository
    user = await user_repository.get_user(token_data.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


def require_permission(resource: str, action: str):
    """Decorator for requiring specific permissions."""
    @handle_errors()
    def dependency(current_user: User = Depends(get_current_user)):
        if not permission_checker.check_permission(
            current_user.id, current_user.roles, resource, action
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {resource}:{action}"
            )
        return current_user
    return dependency


@auth_router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest, 
    http_request: Request,
    _: None = Depends(rate_limit_dependency())
):
    """Authenticate user and return tokens."""
    mgr, _ = get_auth_dependencies()
    
    try:
        # Get client IP
        client_ip = http_request.client.host if http_request.client else None
        
        # Authenticate user
        user, tokens = await mgr.authenticate(
            username=request.username,
            password=request.password,
            ip_address=client_ip
        )
        
        # Check 2FA if enabled
        two_fa_status = await two_factor_service.get_2fa_status(user.id)
        if two_fa_status["enabled"]:
            if not request.mfa_code:
                # Create 2FA challenge
                challenge = await two_factor_service.create_challenge(user.id)
                if challenge:
                    return JSONResponse(
                        status_code=status.HTTP_200_OK,
                        content={
                            "requires_2fa": True,
                            "challenge_id": challenge.challenge_id,
                            "challenge_type": challenge.challenge_type,
                            "expires_at": challenge.expires_at.isoformat()
                        }
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to create 2FA challenge"
                    )
            
            # Verify 2FA code
            is_valid_2fa = False
            
            # Check if it's a backup code
            if request.mfa_code and len(request.mfa_code) == 9 and "-" in request.mfa_code:
                is_valid_2fa = await two_factor_service.verify_backup_code(user.id, request.mfa_code)
            else:
                # Regular TOTP verification
                is_valid_2fa = await mgr.verify_mfa(user.id, request.mfa_code)
            
            if not is_valid_2fa:
                await audit_logger.log_event(
                    event_type=AuditEventType.LOGIN_FAILED,
                    severity=AuditSeverity.WARNING,
                    user_id=user.id,
                    ip_address=client_ip,
                    result="failure",
                    details={"reason": "Invalid 2FA code"}
                )
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid 2FA code"
                )
        
        # Create session
        session = await session_manager.create_session(
            user_id=user.id,
            ip_address=client_ip,
            user_agent=http_request.headers.get("User-Agent", "Unknown"),
            metadata={
                "login_method": "password",
                "2fa_used": two_fa_status["enabled"]
            }
        )
        
        # Update tokens with session info
        tokens["session_id"] = session.session_id
        
        # Log successful login
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user.id,
            ip_address=client_ip,
            session_id=session.session_id
        )
        
        return LoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
            user=user.to_dict()
        )
        
    except Exception as e:
        # Log failed login attempt
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            ip_address=client_ip,
            result="failure",
            details={"error": str(e), "username": request.username}
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@auth_router.post("/refresh")
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token."""
    mgr, _ = get_auth_dependencies()
    
    try:
        tokens = await mgr.refresh_token(request.refresh_token)
        
        # Log token refresh
        await audit_logger.log_event(
            event_type=AuditEventType.TOKEN_REFRESH,
            result="success"
        )
        
        return tokens
        
    except Exception as e:
        await audit_logger.log_event(
            event_type=AuditEventType.TOKEN_REFRESH,
            severity=AuditSeverity.WARNING,
            result="failure",
            details={"error": str(e)}
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@auth_router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user)
):
    """Logout user and revoke session."""
    mgr, _ = get_auth_dependencies()
    
    # Extract token data
    token = credentials.credentials
    token_data = token_manager.verify_token(token)
    
    if token_data:
        # Revoke the token
        if token_data.jti and token_data.expires_at:
            await token_revocation_service.revoke_token(
                jti=token_data.jti,
                user_id=current_user.id,
                expires_at=token_data.expires_at,
                reason="logout"
            )
        
        # Invalidate the session
        if token_data.session_id:
            await session_manager.invalidate_session(
                session_id=token_data.session_id,
                reason="logout"
            )
            
            await mgr.logout(current_user.id, token_data.session_id)
            
            await audit_logger.log_event(
                event_type=AuditEventType.LOGOUT,
                user_id=current_user.id,
                session_id=token_data.session_id,
                ip_address=request.client.host if request.client else None
            )
    
    return {"message": "Logged out successfully"}


@auth_router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return current_user.to_dict()


@auth_router.put("/me/password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user)
):
    """Change current user's password."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.change_password(
        user_id=current_user.id,
        old_password=request.old_password,
        new_password=request.new_password
    )
    
    return {"message": "Password changed successfully"}


@auth_router.post("/password-reset-request")
async def request_password_reset(
    request: PasswordResetRequest,
    _: None = Depends(rate_limit_dependency())
):
    """Request password reset."""
    mgr, _ = get_auth_dependencies()
    
    reset_request = PasswordResetRequest(email=request.email)
    result = await mgr.reset_password_request(reset_request)
    
    return {"message": result}


@auth_router.post("/password-reset")
async def reset_password(request: ResetPasswordRequest):
    """Reset password using reset token."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.reset_password(request.token, request.new_password)
    
    return {"message": "Password reset successfully"}


@auth_router.post("/mfa/enable")
async def enable_mfa(current_user: User = Depends(get_current_user)):
    """Enable MFA for current user."""
    mgr, _ = get_auth_dependencies()
    
    mfa_data = await mgr.enable_mfa(current_user.id)
    
    return {
        "message": "MFA setup initiated",
        "secret": mfa_data["secret"],
        "qr_code": mfa_data["qr_code"],
        "instructions": "Scan the QR code with your authenticator app"
    }


@auth_router.post("/mfa/verify")
async def verify_mfa_setup(
    code: str,
    current_user: User = Depends(get_current_user)
):
    """Verify MFA setup and enable it."""
    mgr, _ = get_auth_dependencies()
    
    if await mgr.verify_mfa(current_user.id, code):
        # Enable MFA for user
        user = await mgr.get_user(current_user.id)
        user.mfa_enabled = True
        await mgr.user_store.update_user(user)
        
        await audit_logger.log_event(
            event_type=AuditEventType.MFA_ENABLED,
            user_id=current_user.id
        )
        
        return {"message": "MFA enabled successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )


@auth_router.delete("/mfa/disable")
async def disable_mfa(
    password: str,
    current_user: User = Depends(get_current_user)
):
    """Disable MFA for current user."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.disable_mfa(current_user.id, password)
    
    return {"message": "MFA disabled successfully"}


# User Management Endpoints (Admin only)

@auth_router.post("/users", response_model=Dict[str, Any])
async def create_user(
    request: CreateUserRequest,
    current_user: User = Depends(require_permission("users", "write"))
):
    """Create a new user."""
    mgr, _ = get_auth_dependencies()
    
    user_request = UserCreationRequest(
        username=request.username,
        email=request.email,
        password=request.password,
        roles=request.roles
    )
    
    user = await mgr.create_user(user_request, created_by=current_user.id)
    
    return user.to_dict()


@auth_router.get("/users")
async def list_users(
    offset: int = 0,
    limit: int = 100,
    status: Optional[UserStatus] = None,
    current_user: User = Depends(require_permission("users", "read"))
):
    """List users with pagination."""
    mgr, _ = get_auth_dependencies()
    
    users = await mgr.list_users(offset, limit, status)
    
    return {
        "users": [user.to_dict() for user in users],
        "offset": offset,
        "limit": limit,
        "total": len(users)
    }


@auth_router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    current_user: User = Depends(require_permission("users", "read"))
):
    """Get user by ID."""
    mgr, _ = get_auth_dependencies()
    
    user = await mgr.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user.to_dict()


@auth_router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    request: UpdateUserRequest,
    current_user: User = Depends(require_permission("users", "write"))
):
    """Update user information."""
    mgr, _ = get_auth_dependencies()
    
    updates = request.dict(exclude_unset=True)
    user = await mgr.update_user(user_id, updates, current_user.id)
    
    return user.to_dict()


@auth_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_permission("users", "delete"))
):
    """Delete (deactivate) a user."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.delete_user(user_id, current_user.id)
    
    return {"message": "User deleted successfully"}


@auth_router.post("/users/{user_id}/roles")
async def assign_role(
    user_id: str,
    request: AssignRoleRequest,
    current_user: User = Depends(require_permission("rbac", "write"))
):
    """Assign role to user."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.assign_role(
        user_id=user_id,
        role_name=request.role_name,
        assigned_by=current_user.id,
        expires_at=request.expires_at
    )
    
    return {"message": f"Role {request.role_name} assigned successfully"}


@auth_router.delete("/users/{user_id}/roles/{role_name}")
async def remove_role(
    user_id: str,
    role_name: str,
    current_user: User = Depends(require_permission("rbac", "write"))
):
    """Remove role from user."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.remove_role(user_id, role_name, current_user.id)
    
    return {"message": f"Role {role_name} removed successfully"}


# API Key Management

@auth_router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user: User = Depends(get_current_user)
):
    """Create an API key for current user."""
    mgr, _ = get_auth_dependencies()
    
    api_key, raw_key = await mgr.create_api_key(
        user_id=current_user.id,
        name=request.name,
        permissions=request.permissions,
        expires_at=request.expires_at
    )
    
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        permissions=list(api_key.permissions),
        expires_at=api_key.expires_at
    )


@auth_router.get("/api-keys")
async def list_api_keys(current_user: User = Depends(get_current_user)):
    """List API keys for current user."""
    mgr, _ = get_auth_dependencies()
    
    # Get API keys from repository
    api_keys = await user_repository.get_user_api_keys(current_user.id)
    
    # Filter out sensitive data
    sanitized_keys = []
    for key in api_keys:
        sanitized_keys.append({
            "id": key.id,
            "name": key.name,
            "created_at": key.created_at.isoformat(),
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            "permissions": list(key.permissions),
            "status": key.status.value
        })
    
    return {"api_keys": sanitized_keys}


@auth_router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Revoke an API key."""
    mgr, _ = get_auth_dependencies()
    
    await mgr.revoke_api_key(current_user.id, key_id)
    
    return {"message": "API key revoked successfully"}


# RBAC Endpoints

@auth_router.get("/roles")
async def list_roles(current_user: User = Depends(require_permission("rbac", "read"))):
    """List all available roles."""
    return {"roles": rbac_manager.export_roles()}


@auth_router.get("/roles/{role_name}")
async def get_role(
    role_name: str,
    current_user: User = Depends(require_permission("rbac", "read"))
):
    """Get role hierarchy and permissions."""
    hierarchy = rbac_manager.get_role_hierarchy(role_name)
    if not hierarchy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    return hierarchy


@auth_router.get("/permissions")
async def get_user_permissions(current_user: User = Depends(get_current_user)):
    """Get current user's effective permissions."""
    permissions = permission_checker.get_user_permissions(
        current_user.id, current_user.roles
    )
    
    return {"permissions": permissions}


# Audit Endpoints

@auth_router.get("/audit/events")
async def get_audit_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
    current_user: User = Depends(require_permission("audit", "read"))
):
    """Get audit events."""
    if not start_time:
        start_time = datetime.utcnow() - timedelta(days=7)
    
    events = await audit_logger.query_events(
        filters={},
        start_time=start_time,
        end_time=end_time,
        limit=limit
    )
    
    return {
        "events": [event.to_dict() for event in events],
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat() if end_time else None,
        "count": len(events)
    }


@auth_router.get("/audit/user/{user_id}")
async def get_user_audit_events(
    user_id: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    current_user: User = Depends(require_permission("audit", "read"))
):
    """Get audit events for specific user."""
    events = await audit_logger.get_user_activity(
        user_id, start_time, end_time
    )
    
    return {
        "events": [event.to_dict() for event in events],
        "user_id": user_id,
        "count": len(events)
    }


@auth_router.get("/audit/security")
async def get_security_events(
    severity: AuditSeverity = AuditSeverity.WARNING,
    current_user: User = Depends(require_permission("audit", "read"))
):
    """Get recent security events."""
    events = await audit_logger.get_security_events(severity)
    
    return {
        "events": [event.to_dict() for event in events],
        "severity": severity.value,
        "count": len(events)
    }


@auth_router.get("/audit/statistics")
async def get_audit_statistics(
    current_user: User = Depends(require_permission("audit", "read"))
):
    """Get audit statistics."""
    return audit_logger.get_statistics()


# 2FA Endpoints

@auth_router.post("/2fa/setup/totp")
async def setup_totp(
    current_user: User = Depends(get_current_user)
):
    """Setup TOTP 2FA for current user."""
    setup_data = await two_factor_service.setup_totp(
        user_id=current_user.id,
        user_email=current_user.email
    )
    
    await audit_logger.log_event(
        event_type=AuditEventType.MFA_SETUP_INITIATED,
        user_id=current_user.id,
        details={"method": "totp"}
    )
    
    return {
        "qr_code": setup_data["qr_code"],
        "secret": setup_data["secret"],
        "message": "Scan the QR code with your authenticator app and verify with a code"
    }


@auth_router.post("/2fa/verify/totp")
async def verify_totp_setup(
    code: str,
    current_user: User = Depends(get_current_user)
):
    """Verify TOTP setup and enable it."""
    success = await two_factor_service.verify_totp_setup(
        user_id=current_user.id,
        code=code
    )
    
    if success:
        # Get backup codes
        two_fa_status = await two_factor_service.get_2fa_status(current_user.id)
        
        await audit_logger.log_event(
            event_type=AuditEventType.MFA_ENABLED,
            user_id=current_user.id,
            details={"method": "totp"}
        )
        
        # Get the config to return backup codes
        backup_codes = await two_factor_service.regenerate_backup_codes(current_user.id)
        
        return {
            "message": "2FA enabled successfully",
            "backup_codes": backup_codes,
            "warning": "Save these backup codes in a secure place. They can be used to access your account if you lose your authenticator."
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )


@auth_router.post("/2fa/verify")
async def verify_2fa_challenge(
    challenge_id: str,
    code: str,
    _: None = Depends(rate_limit_dependency())
):
    """Verify a 2FA challenge during login."""
    success, error_message = await two_factor_service.verify_challenge(
        challenge_id=challenge_id,
        code=code
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message or "Invalid 2FA code"
        )
    
    # Get the challenge to retrieve user info
    # In production, this would return continuation of login flow
    return {
        "message": "2FA verification successful",
        "continue_login": True
    }


@auth_router.get("/2fa/status")
async def get_2fa_status(
    current_user: User = Depends(get_current_user)
):
    """Get 2FA status for current user."""
    status = await two_factor_service.get_2fa_status(current_user.id)
    return status


@auth_router.post("/2fa/backup-codes/regenerate")
async def regenerate_backup_codes(
    password: str,
    current_user: User = Depends(get_current_user)
):
    """Regenerate backup codes (requires password verification)."""
    mgr, _ = get_auth_dependencies()
    
    # Verify password
    user = await mgr.get_user(current_user.id)
    if not user or not user.verify_password(password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    
    # Check if 2FA is enabled
    status = await two_factor_service.get_2fa_status(current_user.id)
    if not status["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled"
        )
    
    # Regenerate codes
    backup_codes = await two_factor_service.regenerate_backup_codes(current_user.id)
    
    await audit_logger.log_event(
        event_type=AuditEventType.BACKUP_CODES_REGENERATED,
        user_id=current_user.id
    )
    
    return {
        "backup_codes": backup_codes,
        "warning": "Your old backup codes are now invalid. Save these new codes in a secure place."
    }


@auth_router.delete("/2fa/disable")
async def disable_2fa(
    password: str,
    method: str,  # totp, sms, email, or all
    current_user: User = Depends(get_current_user)
):
    """Disable 2FA method (requires password verification)."""
    mgr, _ = get_auth_dependencies()
    
    # Verify password
    user = await mgr.get_user(current_user.id)
    if not user or not user.verify_password(password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    
    # Disable specific method or all
    if method == "totp":
        success = await two_factor_service.disable_totp(current_user.id)
    elif method == "all":
        success = await two_factor_service.admin_disable_2fa(
            user_id=current_user.id,
            admin_id=current_user.id,  # Self-disable
            reason="User requested"
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported 2FA method: {method}"
        )
    
    if success:
        await audit_logger.log_event(
            event_type=AuditEventType.MFA_DISABLED,
            user_id=current_user.id,
            details={"method": method}
        )
        
        return {"message": f"2FA {method} disabled successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to disable 2FA"
        )


# Session Management Endpoints

@auth_router.get("/sessions")
async def list_sessions(
    current_user: User = Depends(get_current_user)
):
    """List all active sessions for current user."""
    sessions = await session_manager.get_user_sessions(current_user.id)
    
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "created_at": s.created_at.isoformat(),
                "last_activity": s.last_activity.isoformat(),
                "ip_address": s.ip_address,
                "device_info": s.device_info,
                "expires_at": s.expires_at.isoformat()
            }
            for s in sessions
        ],
        "count": len(sessions)
    }


@auth_router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user)
):
    """Revoke a specific session."""
    # Verify session belongs to user
    session = await session_manager.get_session(session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Invalidate session
    success = await session_manager.invalidate_session(
        session_id=session_id,
        reason="user_revoked"
    )
    
    if success:
        await audit_logger.log_event(
            event_type=AuditEventType.SESSION_REVOKED,
            user_id=current_user.id,
            details={"session_id": session_id}
        )
        
        return {"message": "Session revoked successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to revoke session"
        )


@auth_router.delete("/sessions")
async def revoke_all_sessions(
    keep_current: bool = True,
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user)
):
    """Revoke all sessions for current user."""
    # Get current session ID if keeping it
    current_session_id = None
    if keep_current:
        token = credentials.credentials
        token_data = token_manager.verify_token(token)
        if token_data:
            current_session_id = token_data.session_id
    
    # Get all sessions
    sessions = await session_manager.get_user_sessions(current_user.id)
    
    # Revoke all except current
    revoked_count = 0
    for session in sessions:
        if session.session_id != current_session_id:
            if await session_manager.invalidate_session(session.session_id, "bulk_revoke"):
                revoked_count += 1
    
    await audit_logger.log_event(
        event_type=AuditEventType.ALL_SESSIONS_REVOKED,
        user_id=current_user.id,
        details={
            "revoked_count": revoked_count,
            "kept_current": keep_current
        }
    )
    
    return {
        "message": f"Revoked {revoked_count} sessions",
        "kept_current": keep_current
    }


# Admin 2FA Override

@auth_router.post("/admin/2fa/disable/{user_id}")
async def admin_disable_2fa(
    user_id: str,
    reason: str,
    current_user: User = Depends(require_permission("users", "admin"))
):
    """Admin override to disable 2FA for a user."""
    success = await two_factor_service.admin_disable_2fa(
        user_id=user_id,
        admin_id=current_user.id,
        reason=reason
    )
    
    if success:
        await audit_logger.log_event(
            event_type=AuditEventType.ADMIN_2FA_OVERRIDE,
            user_id=user_id,
            actor_id=current_user.id,
            severity=AuditSeverity.HIGH,
            details={"action": "disabled_2fa", "reason": reason}
        )
        
        return {"message": f"2FA disabled for user {user_id}"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to disable 2FA"
        )


# Health check
@auth_router.get("/health")
async def health_check():
    """Authentication service health check."""
    components = {
        "token_manager": "ok",
        "rbac_manager": "ok",
        "permission_checker": "ok",
        "audit_logger": "ok",
        "redis_services": "checking"
    }
    
    # Check Redis services
    try:
        stats = await token_revocation_service.get_revoked_tokens_count()
        session_count = await session_manager.get_session_count()
        components["redis_services"] = "ok"
        components["revoked_tokens"] = stats["revoked_tokens"]
        components["active_sessions"] = session_count
    except Exception as e:
        components["redis_services"] = f"error: {str(e)}"
    
    return {
        "status": "healthy" if all(v == "ok" or isinstance(v, int) for v in components.values()) else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "components": components
    }