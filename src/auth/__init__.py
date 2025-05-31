"""Authentication and Authorization Module.

This module provides production-grade RBAC (Role-Based Access Control)
implementation following OWASP security guidelines.
"""

from .models import User, UserStatus, APIKey, APIKeyStatus, UserRole
from .tokens import TokenManager, TokenData
from .rbac import RBACManager, Role, Permission
from .permissions import PermissionChecker, require_permission, ResourceType, ResourcePermission
from .middleware import AuthMiddleware, get_current_user_dependency, require_auth
from .user_manager import UserManager, UserCreationRequest, PasswordResetRequest
from .audit import AuditLogger, AuditEventType, AuditSeverity, AuditEvent
from .mcp_integration import AuthenticatedMCPManager, AuthenticatedMCPContext
from .experts_integration import AuthenticatedExpertManager, AuthenticatedExpertContext
from .api import auth_router

__all__ = [
    # Core models
    "User",
    "UserStatus", 
    "APIKey",
    "APIKeyStatus",
    "UserRole",
    
    # Token management
    "TokenManager",
    "TokenData",
    
    # RBAC
    "RBACManager", 
    "Role",
    "Permission",
    
    # Permissions
    "PermissionChecker",
    "require_permission",
    "ResourceType",
    "ResourcePermission",
    
    # Middleware
    "AuthMiddleware",
    "get_current_user_dependency",
    "require_auth",
    
    # User management
    "UserManager",
    "UserCreationRequest",
    "PasswordResetRequest",
    
    # Audit logging
    "AuditLogger",
    "AuditEventType",
    "AuditSeverity", 
    "AuditEvent",
    
    # Integrations
    "AuthenticatedMCPManager",
    "AuthenticatedMCPContext",
    "AuthenticatedExpertManager",
    "AuthenticatedExpertContext",
    
    # API
    "auth_router"
]


def create_auth_system(
    user_store=None,
    api_key_store=None,
    secret_key: str = None,
    mcp_manager=None,
    expert_manager=None
):
    """
    Create a complete authentication system with all components.
    
    Args:
        user_store: User storage backend
        api_key_store: API key storage backend
        secret_key: JWT secret key
        mcp_manager: MCP manager instance for integration
        expert_manager: Expert manager instance for integration
        
    Returns:
        Dictionary containing all auth system components
    """
    # Initialize core components
    token_manager = TokenManager(secret_key=secret_key)
    rbac_manager = RBACManager()
    permission_checker = PermissionChecker(rbac_manager)
    audit_logger = AuditLogger()
    
    # Initialize user manager
    user_manager = UserManager(
        user_store=user_store,
        token_manager=token_manager,
        rbac_manager=rbac_manager,
        permission_checker=permission_checker
    )
    
    # Initialize middleware
    auth_middleware = AuthMiddleware(
        token_manager=token_manager,
        rbac_manager=rbac_manager,
        permission_checker=permission_checker,
        user_store=user_store,
        api_key_store=api_key_store
    )
    
    # Initialize integrations
    authenticated_mcp_manager = None
    if mcp_manager:
        authenticated_mcp_manager = AuthenticatedMCPManager(
            mcp_manager=mcp_manager,
            permission_checker=permission_checker
        )
        authenticated_mcp_manager.register_mcp_permissions()
    
    authenticated_expert_manager = None
    if expert_manager:
        authenticated_expert_manager = AuthenticatedExpertManager(
            expert_manager=expert_manager,
            permission_checker=permission_checker
        )
    
    return {
        "token_manager": token_manager,
        "rbac_manager": rbac_manager,
        "permission_checker": permission_checker,
        "audit_logger": audit_logger,
        "user_manager": user_manager,
        "auth_middleware": auth_middleware,
        "authenticated_mcp_manager": authenticated_mcp_manager,
        "authenticated_expert_manager": authenticated_expert_manager
    }