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

from .user_manager import UserManager, UserCreationRequest, PasswordResetRequest
from .models import User, APIKey, UserStatus
from .tokens import TokenManager, TokenData
from .rbac import RBACManager
from .permissions import PermissionChecker
from .middleware import AuthMiddleware, get_current_user_dependency
from .audit import AuditLogger, AuditEventType, AuditSeverity
from .audit_config import get_audit_logger


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


# Initialize components (in production, use dependency injection)
token_manager = TokenManager()
rbac_manager = RBACManager()
permission_checker = PermissionChecker(rbac_manager)
audit_logger = get_audit_logger()

# This would be injected in production
user_manager: Optional[UserManager] = None
auth_middleware: Optional[AuthMiddleware] = None

# Security scheme
security = HTTPBearer()

# Router
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_dependencies():
    """Get authentication dependencies (mock for demo)."""
    global user_manager, auth_middleware
    
    if not user_manager:
        # Mock initialization - in production, use proper DI
        user_manager = UserManager(
            user_store=None,  # Would be real storage
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker
        )
    
    if not auth_middleware:
        auth_middleware = AuthMiddleware(
            token_manager=token_manager,
            rbac_manager=rbac_manager,
            permission_checker=permission_checker
        )
    
    return user_manager, auth_middleware


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> User:
    """Get current authenticated user."""
    _, middleware = get_auth_dependencies()
    
    user = await middleware.get_current_user(credentials, None, request)
    if not user:
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
    
    return user


def require_permission(resource: str, action: str):
    """Decorator for requiring specific permissions."""
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
async def login(request: LoginRequest, http_request: Request):
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
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not request.mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="MFA code required"
                )
            
            if not await mgr.verify_mfa(user.id, request.mfa_code):
                await audit_logger.log_event(
                    event_type=AuditEventType.LOGIN_FAILED,
                    severity=AuditSeverity.WARNING,
                    user_id=user.id,
                    ip_address=client_ip,
                    result="failure",
                    details={"reason": "Invalid MFA code"}
                )
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid MFA code"
                )
        
        # Log successful login
        await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user.id,
            ip_address=client_ip,
            session_id=tokens["session_id"]
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
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user and revoke session."""
    mgr, _ = get_auth_dependencies()
    
    # Extract session ID from token (simplified)
    session_id = "current_session"  # Would extract from token
    
    await mgr.logout(current_user.id, session_id)
    
    await audit_logger.log_event(
        event_type=AuditEventType.LOGOUT,
        user_id=current_user.id,
        session_id=session_id
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
async def request_password_reset(request: PasswordResetRequest):
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
    
    # Mock implementation
    return {"api_keys": []}


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


# Health check
@auth_router.get("/health")
async def health_check():
    """Authentication service health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "token_manager": "ok",
            "rbac_manager": "ok",
            "permission_checker": "ok",
            "audit_logger": "ok"
        }
    }