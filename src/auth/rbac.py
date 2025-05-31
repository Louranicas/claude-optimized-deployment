"""Role-Based Access Control (RBAC) Implementation.

Implements a hierarchical RBAC system with inheritance and
fine-grained permissions following OWASP guidelines.
"""

from typing import Dict, Set, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import re


class PermissionType(Enum):
    """Types of permissions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


@dataclass(frozen=True)
class Permission:
    """Permission definition with resource and action."""
    
    resource: str
    action: str
    conditions: Dict[str, Any] = field(default_factory=dict, compare=False, hash=False)
    
    def __str__(self) -> str:
        """String representation of permission."""
        return f"{self.resource}:{self.action}"
    
    def __hash__(self) -> int:
        """Make Permission hashable for use in sets."""
        return hash((self.resource, self.action))
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if not isinstance(other, Permission):
            return False
        return self.resource == other.resource and self.action == other.action
    
    def matches(self, resource: str, action: str) -> bool:
        """Check if this permission matches the given resource and action."""
        # Handle wildcards
        if self.resource == "*" or resource == self.resource:
            if self.action == "*" or action == self.action:
                return True
        
        # Handle resource patterns (e.g., "mcp.docker.*")
        if self.resource.endswith("*"):
            pattern = self.resource[:-1]
            if resource.startswith(pattern):
                if self.action == "*" or action == self.action:
                    return True
        
        return False
    
    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Create permission from string format 'resource:action'."""
        parts = permission_str.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid permission format: {permission_str}")
        return cls(resource=parts[0], action=parts[1])


@dataclass
class Role:
    """Role definition with permissions and hierarchy."""
    
    name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    parent_roles: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_permission(self, permission: Permission) -> None:
        """Add a permission to the role."""
        self.permissions.add(permission)
    
    def remove_permission(self, permission: Permission) -> None:
        """Remove a permission from the role."""
        self.permissions.discard(permission)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has a specific permission."""
        for perm in self.permissions:
            if perm.matches(resource, action):
                return True
        return False
    
    def get_all_permissions(self, rbac_manager: "RBACManager") -> Set[Permission]:
        """Get all permissions including inherited ones."""
        all_perms = self.permissions.copy()
        
        # Add permissions from parent roles
        for parent_name in self.parent_roles:
            parent_role = rbac_manager.get_role(parent_name)
            if parent_role:
                all_perms.update(parent_role.get_all_permissions(rbac_manager))
        
        return all_perms


class RBACManager:
    """RBAC Manager for role and permission management."""
    
    def __init__(self):
        """Initialize RBAC manager with default roles."""
        self.roles: Dict[str, Role] = {}
        self.resource_permissions: Dict[str, Set[str]] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self) -> None:
        """Initialize default system roles."""
        # Viewer role - read-only access
        viewer = Role(
            name="viewer",
            description="Read-only access to resources",
            permissions={
                Permission("*", "read"),
                Permission("auth", "read"),
                Permission("mcp.*", "read"),
                Permission("circle_of_experts", "read"),
            }
        )
        
        # Operator role - can execute operations
        operator = Role(
            name="operator",
            description="Can execute operations and deployments",
            parent_roles=["viewer"],
            permissions={
                Permission("mcp.docker", "execute"),
                Permission("mcp.kubernetes", "execute"),
                Permission("mcp.desktop", "execute"),
                Permission("circle_of_experts", "execute"),
                Permission("deployment", "write"),
                Permission("deployment", "execute"),
            }
        )
        
        # Admin role - full access
        admin = Role(
            name="admin",
            description="Full administrative access",
            parent_roles=["operator"],
            permissions={
                Permission("*", "*"),
                Permission("auth", "*"),
                Permission("rbac", "*"),
                Permission("audit", "*"),
            }
        )
        
        # Service account roles
        mcp_service = Role(
            name="mcp_service",
            description="MCP service account role",
            permissions={
                Permission("mcp.*", "*"),
                Permission("infrastructure", "execute"),
                Permission("monitoring", "write"),
            }
        )
        
        ci_cd_service = Role(
            name="ci_cd_service",
            description="CI/CD service account role",
            permissions={
                Permission("deployment", "*"),
                Permission("mcp.docker", "*"),
                Permission("mcp.kubernetes", "*"),
                Permission("mcp.azure_devops", "*"),
                Permission("security.scan", "execute"),
            }
        )
        
        monitoring_service = Role(
            name="monitoring_service",
            description="Monitoring service account role",
            permissions={
                Permission("monitoring", "*"),
                Permission("mcp.prometheus", "*"),
                Permission("mcp.slack", "execute"),
                Permission("logs", "read"),
            }
        )
        
        # Add roles to manager
        self.add_role(viewer)
        self.add_role(operator)
        self.add_role(admin)
        self.add_role(mcp_service)
        self.add_role(ci_cd_service)
        self.add_role(monitoring_service)
        
        # Define resource-specific permissions
        self._define_resource_permissions()
    
    def _define_resource_permissions(self) -> None:
        """Define available permissions for each resource type."""
        self.resource_permissions = {
            # MCP resources
            "mcp.docker": {"read", "execute", "admin"},
            "mcp.kubernetes": {"read", "execute", "admin"},
            "mcp.desktop": {"read", "execute", "admin"},
            "mcp.azure_devops": {"read", "write", "execute", "admin"},
            "mcp.windows": {"read", "execute", "admin"},
            "mcp.prometheus": {"read", "execute", "admin"},
            "mcp.security_scanner": {"read", "execute", "admin"},
            "mcp.slack": {"read", "execute", "admin"},
            "mcp.s3": {"read", "write", "delete", "admin"},
            "mcp.brave_search": {"read", "execute"},
            
            # Circle of Experts resources
            "circle_of_experts": {"read", "execute", "admin"},
            "circle_of_experts.claude": {"read", "execute"},
            "circle_of_experts.openai": {"read", "execute"},
            "circle_of_experts.gemini": {"read", "execute"},
            "circle_of_experts.deepseek": {"read", "execute"},
            
            # Infrastructure resources
            "infrastructure": {"read", "write", "execute", "admin"},
            "deployment": {"read", "write", "execute", "delete", "admin"},
            "security": {"read", "execute", "admin"},
            "monitoring": {"read", "write", "admin"},
            
            # Auth resources
            "auth": {"read", "write", "admin"},
            "rbac": {"read", "write", "admin"},
            "users": {"read", "write", "delete", "admin"},
            "api_keys": {"read", "write", "delete", "admin"},
            
            # System resources
            "audit": {"read", "write", "admin"},
            "logs": {"read", "write", "delete", "admin"},
            "config": {"read", "write", "admin"},
        }
    
    def add_role(self, role: Role) -> None:
        """Add a role to the manager."""
        self.roles[role.name] = role
    
    def remove_role(self, role_name: str) -> bool:
        """Remove a role from the manager."""
        if role_name in self.roles:
            # Check if role is referenced by other roles
            for role in self.roles.values():
                if role_name in role.parent_roles:
                    raise ValueError(f"Cannot remove role {role_name}: referenced by {role.name}")
            
            del self.roles[role_name]
            return True
        return False
    
    def get_role(self, role_name: str) -> Optional[Role]:
        """Get a role by name."""
        return self.roles.get(role_name)
    
    def check_permission(self, role_names: List[str], resource: str, action: str) -> bool:
        """Check if any of the roles has the required permission."""
        for role_name in role_names:
            role = self.get_role(role_name)
            if role:
                # Check direct permissions
                if role.has_permission(resource, action):
                    return True
                
                # Check inherited permissions
                all_perms = role.get_all_permissions(self)
                for perm in all_perms:
                    if perm.matches(resource, action):
                        return True
        
        return False
    
    def get_resource_permissions(self, resource: str) -> Set[str]:
        """Get available permissions for a resource."""
        # Direct match
        if resource in self.resource_permissions:
            return self.resource_permissions[resource]
        
        # Pattern match (e.g., "mcp.*")
        for pattern, perms in self.resource_permissions.items():
            if pattern.endswith("*"):
                if resource.startswith(pattern[:-1]):
                    return perms
        
        # Default permissions
        return {"read", "write", "execute", "delete", "admin"}
    
    def validate_permission(self, resource: str, action: str) -> bool:
        """Validate if a permission is valid for a resource."""
        available_actions = self.get_resource_permissions(resource)
        return action in available_actions or action == "*"
    
    def create_custom_role(self, name: str, description: str,
                          permissions: List[str],
                          parent_roles: Optional[List[str]] = None) -> Role:
        """Create a custom role with specified permissions."""
        if name in self.roles:
            raise ValueError(f"Role {name} already exists")
        
        # Validate role name
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,30}$", name):
            raise ValueError("Invalid role name format")
        
        # Parse and validate permissions
        role_permissions = set()
        for perm_str in permissions:
            perm = Permission.from_string(perm_str)
            if not self.validate_permission(perm.resource, perm.action):
                raise ValueError(f"Invalid permission: {perm_str}")
            role_permissions.add(perm)
        
        # Validate parent roles
        if parent_roles:
            for parent in parent_roles:
                if parent not in self.roles:
                    raise ValueError(f"Parent role {parent} does not exist")
        
        # Create and add role
        role = Role(
            name=name,
            description=description,
            permissions=role_permissions,
            parent_roles=parent_roles or []
        )
        
        self.add_role(role)
        return role
    
    def get_role_hierarchy(self, role_name: str) -> Dict[str, Any]:
        """Get the complete role hierarchy for a role."""
        role = self.get_role(role_name)
        if not role:
            return {}
        
        hierarchy = {
            "name": role.name,
            "description": role.description,
            "direct_permissions": [str(p) for p in role.permissions],
            "parent_roles": role.parent_roles,
            "inherited_permissions": [],
            "children": []
        }
        
        # Get inherited permissions
        all_perms = role.get_all_permissions(self)
        inherited = all_perms - role.permissions
        hierarchy["inherited_permissions"] = [str(p) for p in inherited]
        
        # Find child roles
        for r in self.roles.values():
            if role_name in r.parent_roles:
                hierarchy["children"].append(r.name)
        
        return hierarchy
    
    def export_roles(self) -> Dict[str, Any]:
        """Export all roles and their configurations."""
        return {
            role_name: {
                "description": role.description,
                "permissions": [str(p) for p in role.permissions],
                "parent_roles": role.parent_roles,
                "metadata": role.metadata
            }
            for role_name, role in self.roles.items()
        }
    
    def import_roles(self, roles_data: Dict[str, Any]) -> None:
        """Import roles from exported data."""
        # Clear existing non-default roles
        default_roles = {"viewer", "operator", "admin", "mcp_service",
                        "ci_cd_service", "monitoring_service"}
        
        for role_name in list(self.roles.keys()):
            if role_name not in default_roles:
                del self.roles[role_name]
        
        # Import new roles
        for role_name, role_data in roles_data.items():
            if role_name not in default_roles:
                permissions = set()
                for perm_str in role_data.get("permissions", []):
                    permissions.add(Permission.from_string(perm_str))
                
                role = Role(
                    name=role_name,
                    description=role_data.get("description", ""),
                    permissions=permissions,
                    parent_roles=role_data.get("parent_roles", []),
                    metadata=role_data.get("metadata", {})
                )
                
                self.add_role(role)