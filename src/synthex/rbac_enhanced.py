
"""
Role-Based Access Control (RBAC) Implementation
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

class Permission(Enum):
    """System permissions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    EXECUTE = "execute"

class Resource(Enum):
    """System resources"""
    SEARCH = "search"
    AGENTS = "agents"
    CONFIG = "config"
    USERS = "users"
    LOGS = "logs"
    METRICS = "metrics"

@dataclass
class Role:
    """Role definition"""
    name: str
    permissions: Dict[Resource, List[Permission]]
    description: str = ""
    
class RBACManager:
    """RBAC manager"""
    
    def __init__(self):
        self.roles = self._initialize_roles()
        self.user_roles = {}
        
    def _initialize_roles(self) -> Dict[str, Role]:
        """Initialize default roles"""
        return {
            "admin": Role(
                name="admin",
                permissions={
                    Resource.SEARCH: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.AGENTS: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.CONFIG: [Permission.READ, Permission.WRITE, Permission.ADMIN],
                    Resource.USERS: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.LOGS: [Permission.READ, Permission.ADMIN],
                    Resource.METRICS: [Permission.READ, Permission.ADMIN]
                },
                description="Full system access"
            ),
            "operator": Role(
                name="operator",
                permissions={
                    Resource.SEARCH: [Permission.READ, Permission.WRITE, Permission.EXECUTE],
                    Resource.AGENTS: [Permission.READ, Permission.EXECUTE],
                    Resource.CONFIG: [Permission.READ],
                    Resource.LOGS: [Permission.READ],
                    Resource.METRICS: [Permission.READ]
                },
                description="System operator access"
            ),
            "viewer": Role(
                name="viewer",
                permissions={
                    Resource.SEARCH: [Permission.READ],
                    Resource.AGENTS: [Permission.READ],
                    Resource.METRICS: [Permission.READ]
                },
                description="Read-only access"
            )
        }
        
    def assign_role(self, user_id: str, role_name: str):
        """Assign role to user"""
        if role_name not in self.roles:
            raise ValueError(f"Unknown role: {role_name}")
        self.user_roles[user_id] = role_name
        
    def check_permission(self, user_id: str, resource: Resource, permission: Permission) -> bool:
        """Check if user has permission"""
        if user_id not in self.user_roles:
            return False
            
        role_name = self.user_roles[user_id]
        role = self.roles[role_name]
        
        if resource not in role.permissions:
            return False
            
        return permission in role.permissions[resource]
        
    def requires_permission(self, resource: Resource, permission: Permission):
        """Decorator for permission checking"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_id = kwargs.get("user_id")
                if not user_id:
                    raise PermissionError("No user ID provided")
                    
                if not self.check_permission(user_id, resource, permission):
                    raise PermissionError(f"User {user_id} lacks {permission.value} permission for {resource.value}")
                    
                return await func(*args, **kwargs)
            return wrapper
        return decorator

# Global RBAC manager
rbac_manager = RBACManager()
