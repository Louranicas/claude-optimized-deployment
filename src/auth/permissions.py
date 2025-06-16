"""Permission Checking and Resource-Based Access Control.

Implements fine-grained permission checking with resource ownership
and contextual permissions.
"""

from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import re
from functools import wraps
import asyncio
import inspect

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error
)

__all__ = [
    "ResourceType",
    "ResourcePermission",
    "PermissionChecker",
    "require_permission"
]



class ResourceType(Enum):
    """Types of resources in the system."""
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    AI_MODEL = "ai_model"
    DEPLOYMENT = "deployment"
    INFRASTRUCTURE = "infrastructure"
    USER = "user"
    API_KEY = "api_key"
    ROLE = "role"
    AUDIT_LOG = "audit_log"
    CONFIG = "config"


@dataclass
class ResourcePermission:
    """Resource-specific permission with context."""
    
    resource_type: ResourceType
    resource_id: str
    owner_id: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def check_permission(self, user_id: str, action: str, 
                        user_roles: List[str], context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if user has permission for action on this resource."""
        # Owner always has full access
        if self.owner_id and self.owner_id == user_id:
            return True
        
        # Check explicit user permissions
        user_perms = self.permissions.get(f"user:{user_id}", {})
        if action in user_perms or "*" in user_perms:
            return self._check_contextual_permission(user_perms, action, context)
        
        # Check role-based permissions
        for role in user_roles:
            role_perms = self.permissions.get(f"role:{role}", {})
            if action in role_perms or "*" in role_perms:
                return self._check_contextual_permission(role_perms, action, context)
        
        # Check wildcard permissions
        wildcard_perms = self.permissions.get("*", {})
        if action in wildcard_perms or "*" in wildcard_perms:
            return self._check_contextual_permission(wildcard_perms, action, context)
        
        return False
    
    def _check_contextual_permission(self, perms: Dict[str, Any], 
                                   action: str, context: Optional[Dict[str, Any]]) -> bool:
        """Check contextual conditions for permission."""
        perm_config = perms.get(action, perms.get("*", {}))
        
        # Simple boolean permission
        if isinstance(perm_config, bool):
            return perm_config
        
        # Permission with conditions
        if isinstance(perm_config, dict):
            conditions = perm_config.get("conditions", {})
            
            # Time-based conditions
            if "time_window" in conditions:
                # Implementation would check current time against window
                pass
            
            # IP-based conditions
            if "allowed_ips" in conditions and context:
                client_ip = context.get("client_ip")
                if client_ip and client_ip not in conditions["allowed_ips"]:
                    return False
            
            # Environment conditions
            if "environments" in conditions and context:
                env = context.get("environment")
                if env and env not in conditions["environments"]:
                    return False
            
            return perm_config.get("allowed", True)
        
        return True
    
    def grant_permission(self, principal: str, action: str, 
                        conditions: Optional[Dict[str, Any]] = None) -> None:
        """Grant permission to a principal (user or role)."""
        if principal not in self.permissions:
            self.permissions[principal] = {}
        
        if conditions:
            self.permissions[principal][action] = {
                "allowed": True,
                "conditions": conditions
            }
        else:
            self.permissions[principal][action] = True
    
    def revoke_permission(self, principal: str, action: Optional[str] = None) -> None:
        """Revoke permission from a principal."""
        if principal in self.permissions:
            if action:
                self.permissions[principal].pop(action, None)
                if not self.permissions[principal]:
                    del self.permissions[principal]
            else:
                del self.permissions[principal]


class PermissionChecker:
    """Central permission checking service."""
    
    def __init__(self, rbac_manager: Optional[Any] = None):
        """Initialize permission checker."""
        self.rbac_manager = rbac_manager
        self.resource_permissions: Dict[str, ResourcePermission] = {}
        self.permission_cache: Dict[str, bool] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Permission evaluation callbacks
        self.custom_evaluators: Dict[str, Callable] = {}
        
        # Audit callback
        self.audit_callback: Optional[Callable] = None
    
    def check_permission(self, user_id: str, user_roles: List[str],
                        resource: str, action: str,
                        context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if user has permission to perform action on resource.
        
        Args:
            user_id: User identifier
            user_roles: List of user's roles
            resource: Resource identifier (e.g., "mcp.docker", "deployment:123")
            action: Action to perform (e.g., "execute", "read")
            context: Additional context for permission evaluation
            
        Returns:
            True if permission granted, False otherwise
        """
        # Build cache key
        cache_key = f"{user_id}:{','.join(sorted(user_roles))}:{resource}:{action}"
        
        # Check cache
        if cache_key in self.permission_cache:
            result = self.permission_cache[cache_key]
            self._audit_permission_check(user_id, resource, action, result, "cached")
            return result
        
        # Check RBAC permissions first
        if self.rbac_manager:
            rbac_result = self.rbac_manager.check_permission(user_roles, resource, action)
            if rbac_result:
                self.permission_cache[cache_key] = True
                self._audit_permission_check(user_id, resource, action, True, "rbac")
                return True
        
        # Parse resource identifier
        resource_type, resource_id = self._parse_resource(resource)
        
        # Check resource-specific permissions
        resource_key = f"{resource_type}:{resource_id}" if resource_id else resource_type
        if resource_key in self.resource_permissions:
            resource_perm = self.resource_permissions[resource_key]
            result = resource_perm.check_permission(user_id, action, user_roles, context)
            if result:
                self.permission_cache[cache_key] = True
                self._audit_permission_check(user_id, resource, action, True, "resource")
                return True
        
        # Check custom evaluators
        if resource_type in self.custom_evaluators:
            evaluator = self.custom_evaluators[resource_type]
            result = evaluator(user_id, user_roles, resource_id, action, context)
            if result:
                self.permission_cache[cache_key] = True
                self._audit_permission_check(user_id, resource, action, True, "custom")
                return True
        
        # Permission denied
        self.permission_cache[cache_key] = False
        self._audit_permission_check(user_id, resource, action, False, "denied")
        return False
    
    def _parse_resource(self, resource: str) -> tuple[str, Optional[str]]:
        """Parse resource identifier into type and ID."""
        # Handle resource with ID (e.g., "deployment:123")
        if ":" in resource and not resource.endswith(":*"):
            parts = resource.split(":", 1)
            return parts[0], parts[1]
        
        # Handle hierarchical resources (e.g., "mcp.docker")
        return resource, None
    
    def register_resource_permission(self, resource_type: ResourceType,
                                   resource_id: str,
                                   owner_id: Optional[str] = None,
                                   initial_permissions: Optional[Dict[str, Any]] = None) -> ResourcePermission:
        """Register resource-specific permissions."""
        resource_key = f"{resource_type.value}:{resource_id}"
        
        resource_perm = ResourcePermission(
            resource_type=resource_type,
            resource_id=resource_id,
            owner_id=owner_id,
            permissions=initial_permissions or {}
        )
        
        self.resource_permissions[resource_key] = resource_perm
        return resource_perm
    
    def get_resource_permission(self, resource_type: ResourceType,
                              resource_id: str) -> Optional[ResourcePermission]:
        """Get resource permission object."""
        resource_key = f"{resource_type.value}:{resource_id}"
        return self.resource_permissions.get(resource_key)
    
    def register_custom_evaluator(self, resource_type: str,
                                evaluator: Callable) -> None:
        """Register custom permission evaluator for resource type."""
        self.custom_evaluators[resource_type] = evaluator
    
    def set_audit_callback(self, callback: Callable) -> None:
        """Set callback for permission check auditing."""
        self.audit_callback = callback
    
    @handle_errors()
    def _audit_permission_check(self, user_id: str, resource: str,
                              action: str, result: bool, source: str) -> None:
        """Audit permission check."""
        if self.audit_callback:
            try:
                if asyncio.iscoroutinefunction(self.audit_callback):
                    asyncio.create_task(self.audit_callback(
                        user_id, resource, action, result, source
                    ))
                else:
                    self.audit_callback(user_id, resource, action, result, source)
            except Exception:
                # Don't let audit failures affect permission checks
                pass
    
    def clear_cache(self, user_id: Optional[str] = None) -> None:
        """Clear permission cache."""
        if user_id:
            # Clear specific user's cache entries
            keys_to_remove = [k for k in self.permission_cache.keys() 
                            if k.startswith(f"{user_id}:")]
            for key in keys_to_remove:
                del self.permission_cache[key]
        else:
            # Clear entire cache
            self.permission_cache.clear()
    
    def get_user_permissions(self, user_id: str, user_roles: List[str]) -> Dict[str, List[str]]:
        """Get all permissions for a user."""
        permissions: Dict[str, Set[str]] = {}
        
        # Get RBAC permissions
        if self.rbac_manager:
            for role_name in user_roles:
                role = self.rbac_manager.get_role(role_name)
                if role:
                    all_perms = role.get_all_permissions(self.rbac_manager)
                    for perm in all_perms:
                        resource = perm.resource
                        if resource not in permissions:
                            permissions[resource] = set()
                        permissions[resource].add(perm.action)
        
        # Get resource-specific permissions
        for resource_key, resource_perm in self.resource_permissions.items():
            # Check if user is owner
            if resource_perm.owner_id == user_id:
                if resource_key not in permissions:
                    permissions[resource_key] = set()
                permissions[resource_key].add("*")
                continue
            
            # Check explicit permissions
            user_key = f"user:{user_id}"
            if user_key in resource_perm.permissions:
                if resource_key not in permissions:
                    permissions[resource_key] = set()
                permissions[resource_key].update(resource_perm.permissions[user_key].keys())
            
            # Check role permissions
            for role in user_roles:
                role_key = f"role:{role}"
                if role_key in resource_perm.permissions:
                    if resource_key not in permissions:
                        permissions[resource_key] = set()
                    permissions[resource_key].update(resource_perm.permissions[role_key].keys())
        
        # Convert sets to lists
        return {k: sorted(list(v)) for k, v in permissions.items()}


def require_permission(resource: str, action: str):
    """
    Decorator for requiring permissions on functions.
    
    Usage:
        @require_permission("mcp.docker", "execute")
        async def deploy_container(user: User, ...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract user from arguments
            user = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'roles'):
                    user = arg
                    break
            
            if not user:
                user = kwargs.get('user') or kwargs.get('current_user')
            
            if not user:
                raise PermissionError("No user context provided")
            
            # Get permission checker from somewhere (e.g., dependency injection)
            # This is a simplified example
            from .permissions import PermissionChecker
            checker = PermissionChecker()
            
            # Check permission
            if not checker.check_permission(user.id, user.roles, resource, action):
                raise PermissionError(f"Permission denied: {resource}:{action}")
            
            # Call original function
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Similar logic for sync functions
            user = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'roles'):
                    user = arg
                    break
            
            if not user:
                user = kwargs.get('user') or kwargs.get('current_user')
            
            if not user:
                raise PermissionError("No user context provided")
            
            from .permissions import PermissionChecker
            checker = PermissionChecker()
            
            if not checker.check_permission(user.id, user.roles, resource, action):
                raise PermissionError(f"Permission denied: {resource}:{action}")
            
            return func(*args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator