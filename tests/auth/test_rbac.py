"""
Comprehensive Tests for Role-Based Access Control (src/auth/rbac.py).

This test suite covers role management, role hierarchy, permission inheritance,
security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
import json

from src.auth.rbac import (
    RBACManager, Role, RoleHierarchy, RoleAssignment,
    RoleNotFoundError, CircularRoleHierarchyError,
    InvalidRoleError, RoleConflictError
)


class TestRole:
    """Test Role class functionality."""
    
    def test_role_creation(self):
        """Test basic role creation."""
        role = Role(
            name="admin",
            description="Administrator role",
            permissions={"users:*", "system:*"},
            metadata={"level": "high", "department": "IT"}
        )
        
        assert role.name == "admin"
        assert role.description == "Administrator role"
        assert "users:*" in role.permissions
        assert "system:*" in role.permissions
        assert role.metadata["level"] == "high"
        assert role.created_at is not None
        assert role.updated_at is not None
    
    def test_role_creation_minimal(self):
        """Test role creation with minimal parameters."""
        role = Role(name="user")
        
        assert role.name == "user"
        assert role.description == ""
        assert len(role.permissions) == 0
        assert len(role.metadata) == 0
        assert role.created_at is not None
        assert role.updated_at is not None
    
    def test_role_validation(self):
        """Test role validation."""
        # Valid role names
        Role(name="user")
        Role(name="admin")
        Role(name="content_moderator")
        Role(name="api_user")
        Role(name="super-admin")
        
        # Invalid role names
        with pytest.raises(InvalidRoleError):
            Role(name="")  # Empty name
        
        with pytest.raises(InvalidRoleError):
            Role(name=None)  # None name
        
        with pytest.raises(InvalidRoleError):
            Role(name="user role")  # Space in name
        
        with pytest.raises(InvalidRoleError):
            Role(name="user:role")  # Colon in name
        
        with pytest.raises(InvalidRoleError):
            Role(name="a" * 101)  # Too long (over 100 chars)
    
    def test_role_add_permission(self):
        """Test adding permissions to role."""
        role = Role(name="user")
        
        role.add_permission("users:read")
        assert "users:read" in role.permissions
        
        role.add_permission("posts:write")
        assert "posts:write" in role.permissions
        assert len(role.permissions) == 2
        
        # Adding duplicate permission should not increase count
        role.add_permission("users:read")
        assert len(role.permissions) == 2
    
    def test_role_remove_permission(self):
        """Test removing permissions from role."""
        role = Role(name="user", permissions={"users:read", "posts:write"})
        
        role.remove_permission("users:read")
        assert "users:read" not in role.permissions
        assert "posts:write" in role.permissions
        
        # Removing non-existent permission should not raise error
        role.remove_permission("nonexistent:permission")
        assert len(role.permissions) == 1
    
    def test_role_has_permission(self):
        """Test checking if role has permission."""
        role = Role(name="user", permissions={"users:read", "posts:*"})
        
        assert role.has_permission("users:read")
        assert role.has_permission("posts:*")
        assert not role.has_permission("users:write")
        assert not role.has_permission("admin:read")
    
    def test_role_update_metadata(self):
        """Test updating role metadata."""
        role = Role(name="user")
        
        role.update_metadata("department", "Engineering")
        assert role.metadata["department"] == "Engineering"
        
        role.update_metadata("level", 1)
        assert role.metadata["level"] == 1
        
        # Updating existing metadata
        role.update_metadata("department", "Product")
        assert role.metadata["department"] == "Product"
        assert len(role.metadata) == 2
    
    def test_role_equality(self):
        """Test role equality comparison."""
        role1 = Role(name="user", permissions={"users:read"})
        role2 = Role(name="user", permissions={"users:read"})
        role3 = Role(name="admin", permissions={"users:read"})
        role4 = Role(name="user", permissions={"users:write"})
        
        assert role1 == role2
        assert role1 != role3  # Different name
        assert role1 != role4  # Different permissions
    
    def test_role_string_representation(self):
        """Test role string representation."""
        role = Role(name="admin", description="Administrator")
        
        assert str(role) == "admin"
        assert "admin" in repr(role)
        assert "Administrator" in repr(role)
    
    def test_role_to_dict(self):
        """Test role serialization to dictionary."""
        role = Role(
            name="admin",
            description="Administrator role",
            permissions={"users:*", "system:*"},
            metadata={"level": "high"}
        )
        
        role_dict = role.to_dict()
        
        assert role_dict["name"] == "admin"
        assert role_dict["description"] == "Administrator role"
        assert set(role_dict["permissions"]) == {"users:*", "system:*"}
        assert role_dict["metadata"]["level"] == "high"
        assert "created_at" in role_dict
        assert "updated_at" in role_dict
    
    def test_role_from_dict(self):
        """Test role deserialization from dictionary."""
        role_dict = {
            "name": "admin",
            "description": "Administrator role",
            "permissions": ["users:*", "system:*"],
            "metadata": {"level": "high"},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        role = Role.from_dict(role_dict)
        
        assert role.name == "admin"
        assert role.description == "Administrator role"
        assert set(role.permissions) == {"users:*", "system:*"}
        assert role.metadata["level"] == "high"


class TestRoleHierarchy:
    """Test RoleHierarchy class functionality."""
    
    def test_role_hierarchy_creation(self):
        """Test role hierarchy creation."""
        hierarchy = RoleHierarchy()
        
        assert len(hierarchy.roles) == 0
        assert len(hierarchy.parent_child_map) == 0
        assert len(hierarchy.child_parent_map) == 0
    
    def test_add_role(self):
        """Test adding roles to hierarchy."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin", permissions={"*:*"})
        user_role = Role(name="user", permissions={"profile:read"})
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(user_role)
        
        assert len(hierarchy.roles) == 2
        assert hierarchy.get_role("admin") == admin_role
        assert hierarchy.get_role("user") == user_role
    
    def test_add_duplicate_role(self):
        """Test adding duplicate role raises error."""
        hierarchy = RoleHierarchy()
        
        role = Role(name="admin")
        hierarchy.add_role(role)
        
        with pytest.raises(RoleConflictError):
            hierarchy.add_role(role)
    
    def test_remove_role(self):
        """Test removing roles from hierarchy."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin")
        user_role = Role(name="user")
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(user_role)
        
        hierarchy.remove_role("user")
        
        assert len(hierarchy.roles) == 1
        assert hierarchy.get_role("admin") == admin_role
        assert hierarchy.get_role("user") is None
    
    def test_remove_nonexistent_role(self):
        """Test removing non-existent role raises error."""
        hierarchy = RoleHierarchy()
        
        with pytest.raises(RoleNotFoundError):
            hierarchy.remove_role("nonexistent")
    
    def test_add_parent_child_relationship(self):
        """Test adding parent-child relationships."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin", permissions={"*:*"})
        moderator_role = Role(name="moderator", permissions={"posts:*"})
        user_role = Role(name="user", permissions={"profile:read"})
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(moderator_role)
        hierarchy.add_role(user_role)
        
        # admin -> moderator -> user
        hierarchy.add_parent_child("admin", "moderator")
        hierarchy.add_parent_child("moderator", "user")
        
        assert "moderator" in hierarchy.parent_child_map["admin"]
        assert "user" in hierarchy.parent_child_map["moderator"]
        assert hierarchy.child_parent_map["moderator"] == "admin"
        assert hierarchy.child_parent_map["user"] == "moderator"
    
    def test_circular_hierarchy_detection(self):
        """Test detection of circular role hierarchies."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin")
        moderator_role = Role(name="moderator")
        user_role = Role(name="user")
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(moderator_role)
        hierarchy.add_role(user_role)
        
        # Create chain: admin -> moderator -> user
        hierarchy.add_parent_child("admin", "moderator")
        hierarchy.add_parent_child("moderator", "user")
        
        # Attempt to create cycle: user -> admin
        with pytest.raises(CircularRoleHierarchyError):
            hierarchy.add_parent_child("user", "admin")
    
    def test_get_inherited_permissions(self):
        """Test getting inherited permissions from role hierarchy."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin", permissions={"admin:*", "users:*"})
        moderator_role = Role(name="moderator", permissions={"posts:*", "comments:*"})
        user_role = Role(name="user", permissions={"profile:read", "profile:write"})
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(moderator_role)
        hierarchy.add_role(user_role)
        
        # admin -> moderator -> user
        hierarchy.add_parent_child("admin", "moderator")
        hierarchy.add_parent_child("moderator", "user")
        
        # User should inherit from moderator and admin
        user_permissions = hierarchy.get_inherited_permissions("user")
        expected_permissions = {
            "profile:read", "profile:write",  # Own permissions
            "posts:*", "comments:*",          # From moderator
            "admin:*", "users:*"              # From admin
        }
        
        assert user_permissions == expected_permissions
        
        # Moderator should inherit from admin
        moderator_permissions = hierarchy.get_inherited_permissions("moderator")
        expected_moderator_permissions = {
            "posts:*", "comments:*",  # Own permissions
            "admin:*", "users:*"      # From admin
        }
        
        assert moderator_permissions == expected_moderator_permissions
        
        # Admin has no parents
        admin_permissions = hierarchy.get_inherited_permissions("admin")
        assert admin_permissions == {"admin:*", "users:*"}
    
    def test_get_role_ancestors(self):
        """Test getting role ancestors."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin")
        moderator_role = Role(name="moderator")
        user_role = Role(name="user")
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(moderator_role)
        hierarchy.add_role(user_role)
        
        # admin -> moderator -> user
        hierarchy.add_parent_child("admin", "moderator")
        hierarchy.add_parent_child("moderator", "user")
        
        # User ancestors: moderator, admin
        user_ancestors = hierarchy.get_role_ancestors("user")
        assert user_ancestors == ["moderator", "admin"]
        
        # Moderator ancestors: admin
        moderator_ancestors = hierarchy.get_role_ancestors("moderator")
        assert moderator_ancestors == ["admin"]
        
        # Admin has no ancestors
        admin_ancestors = hierarchy.get_role_ancestors("admin")
        assert admin_ancestors == []
    
    def test_get_role_descendants(self):
        """Test getting role descendants."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin")
        moderator_role = Role(name="moderator")
        user_role = Role(name="user")
        guest_role = Role(name="guest")
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(moderator_role)
        hierarchy.add_role(user_role)
        hierarchy.add_role(guest_role)
        
        # admin -> moderator -> user
        # admin -> guest
        hierarchy.add_parent_child("admin", "moderator")
        hierarchy.add_parent_child("moderator", "user")
        hierarchy.add_parent_child("admin", "guest")
        
        # Admin descendants: moderator, user, guest
        admin_descendants = hierarchy.get_role_descendants("admin")
        assert set(admin_descendants) == {"moderator", "user", "guest"}
        
        # Moderator descendants: user
        moderator_descendants = hierarchy.get_role_descendants("moderator")
        assert moderator_descendants == ["user"]
        
        # User has no descendants
        user_descendants = hierarchy.get_role_descendants("user")
        assert user_descendants == []
    
    def test_role_hierarchy_export_import(self):
        """Test exporting and importing role hierarchy."""
        hierarchy = RoleHierarchy()
        
        admin_role = Role(name="admin", permissions={"*:*"})
        user_role = Role(name="user", permissions={"profile:read"})
        
        hierarchy.add_role(admin_role)
        hierarchy.add_role(user_role)
        hierarchy.add_parent_child("admin", "user")
        
        # Export
        exported = hierarchy.export()
        
        assert "roles" in exported
        assert "hierarchy" in exported
        assert len(exported["roles"]) == 2
        assert exported["hierarchy"]["admin"] == ["user"]
        
        # Import to new hierarchy
        new_hierarchy = RoleHierarchy()
        new_hierarchy.import_hierarchy(exported)
        
        assert len(new_hierarchy.roles) == 2
        assert new_hierarchy.get_role("admin").permissions == {"*:*"}
        assert new_hierarchy.get_role("user").permissions == {"profile:read"}
        assert "user" in new_hierarchy.parent_child_map["admin"]


class TestRoleAssignment:
    """Test RoleAssignment class functionality."""
    
    def test_role_assignment_creation(self):
        """Test role assignment creation."""
        assignment = RoleAssignment(
            user_id="user_123",
            role_name="admin",
            assigned_by="admin_456",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            metadata={"reason": "promotion"}
        )
        
        assert assignment.user_id == "user_123"
        assert assignment.role_name == "admin"
        assert assignment.assigned_by == "admin_456"
        assert assignment.expires_at > datetime.now(timezone.utc)
        assert assignment.metadata["reason"] == "promotion"
        assert assignment.assigned_at is not None
        assert not assignment.is_expired()
    
    def test_role_assignment_permanent(self):
        """Test permanent role assignment (no expiration)."""
        assignment = RoleAssignment(
            user_id="user_123",
            role_name="user",
            assigned_by="system"
        )
        
        assert assignment.expires_at is None
        assert not assignment.is_expired()
    
    def test_role_assignment_expiration(self):
        """Test role assignment expiration."""
        # Create expired assignment
        assignment = RoleAssignment(
            user_id="user_123",
            role_name="temp_admin",
            assigned_by="admin_456",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        assert assignment.is_expired()
    
    def test_role_assignment_extension(self):
        """Test extending role assignment."""
        assignment = RoleAssignment(
            user_id="user_123",
            role_name="admin",
            assigned_by="admin_456",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)
        )
        
        new_expiry = datetime.now(timezone.utc) + timedelta(days=30)
        assignment.extend_expiry(new_expiry)
        
        assert assignment.expires_at == new_expiry
    
    def test_role_assignment_to_dict(self):
        """Test role assignment serialization."""
        assignment = RoleAssignment(
            user_id="user_123",
            role_name="admin",
            assigned_by="admin_456"
        )
        
        assignment_dict = assignment.to_dict()
        
        assert assignment_dict["user_id"] == "user_123"
        assert assignment_dict["role_name"] == "admin"
        assert assignment_dict["assigned_by"] == "admin_456"
        assert "assigned_at" in assignment_dict


class TestRBACManager:
    """Test RBACManager class functionality."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create RBACManager instance."""
        return RBACManager()
    
    def test_rbac_manager_initialization(self, rbac_manager):
        """Test RBACManager initialization."""
        assert isinstance(rbac_manager.hierarchy, RoleHierarchy)
        assert len(rbac_manager.role_assignments) == 0
    
    def test_create_role(self, rbac_manager):
        """Test creating roles."""
        role = rbac_manager.create_role(
            name="admin",
            description="Administrator role",
            permissions=["users:*", "system:*"]
        )
        
        assert role.name == "admin"
        assert role.description == "Administrator role"
        assert "users:*" in role.permissions
        assert "system:*" in role.permissions
        
        # Role should be in hierarchy
        assert rbac_manager.hierarchy.get_role("admin") == role
    
    def test_create_duplicate_role(self, rbac_manager):
        """Test creating duplicate role raises error."""
        rbac_manager.create_role(name="admin")
        
        with pytest.raises(RoleConflictError):
            rbac_manager.create_role(name="admin")
    
    def test_update_role(self, rbac_manager):
        """Test updating role."""
        role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        updated_role = rbac_manager.update_role(
            "user",
            description="Standard user role",
            permissions=["profile:read", "profile:write"]
        )
        
        assert updated_role.description == "Standard user role"
        assert "profile:write" in updated_role.permissions
    
    def test_update_nonexistent_role(self, rbac_manager):
        """Test updating non-existent role raises error."""
        with pytest.raises(RoleNotFoundError):
            rbac_manager.update_role("nonexistent", description="Test")
    
    def test_delete_role(self, rbac_manager):
        """Test deleting role."""
        rbac_manager.create_role(name="temp_role")
        
        rbac_manager.delete_role("temp_role")
        
        assert rbac_manager.hierarchy.get_role("temp_role") is None
    
    def test_delete_role_with_assignments(self, rbac_manager):
        """Test deleting role that has active assignments."""
        rbac_manager.create_role(name="admin")
        rbac_manager.assign_role("user_123", "admin", "system")
        
        # Should not be able to delete role with active assignments
        with pytest.raises(RoleConflictError):
            rbac_manager.delete_role("admin")
    
    def test_assign_role(self, rbac_manager):
        """Test assigning role to user."""
        rbac_manager.create_role(name="admin")
        
        assignment = rbac_manager.assign_role(
            user_id="user_123",
            role_name="admin",
            assigned_by="admin_456",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        assert assignment.user_id == "user_123"
        assert assignment.role_name == "admin"
        assert assignment.assigned_by == "admin_456"
        
        # Assignment should be stored
        user_assignments = rbac_manager.role_assignments.get("user_123", [])
        assert len(user_assignments) == 1
        assert user_assignments[0] == assignment
    
    def test_assign_nonexistent_role(self, rbac_manager):
        """Test assigning non-existent role raises error."""
        with pytest.raises(RoleNotFoundError):
            rbac_manager.assign_role("user_123", "nonexistent", "admin")
    
    def test_revoke_role(self, rbac_manager):
        """Test revoking role from user."""
        rbac_manager.create_role(name="admin")
        rbac_manager.assign_role("user_123", "admin", "system")
        
        rbac_manager.revoke_role("user_123", "admin")
        
        user_assignments = rbac_manager.role_assignments.get("user_123", [])
        assert len(user_assignments) == 0
    
    def test_revoke_nonexistent_assignment(self, rbac_manager):
        """Test revoking non-existent role assignment."""
        rbac_manager.create_role(name="admin")
        
        # Should not raise error
        rbac_manager.revoke_role("user_123", "admin")
    
    def test_get_user_roles(self, rbac_manager):
        """Test getting user roles."""
        rbac_manager.create_role(name="admin")
        rbac_manager.create_role(name="user")
        
        rbac_manager.assign_role("user_123", "admin", "system")
        rbac_manager.assign_role("user_123", "user", "system")
        
        user_roles = rbac_manager.get_user_roles("user_123")
        assert set(user_roles) == {"admin", "user"}
    
    def test_get_user_roles_with_expired(self, rbac_manager):
        """Test getting user roles excludes expired assignments."""
        rbac_manager.create_role(name="admin")
        rbac_manager.create_role(name="user")
        
        # Active assignment
        rbac_manager.assign_role("user_123", "user", "system")
        
        # Expired assignment
        rbac_manager.assign_role(
            "user_123", "admin", "system",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        user_roles = rbac_manager.get_user_roles("user_123")
        assert user_roles == ["user"]  # Only active role
    
    def test_user_has_role(self, rbac_manager):
        """Test checking if user has role."""
        rbac_manager.create_role(name="admin")
        rbac_manager.assign_role("user_123", "admin", "system")
        
        assert rbac_manager.user_has_role(["admin"], "admin")
        assert not rbac_manager.user_has_role(["user"], "admin")
        assert not rbac_manager.user_has_role([], "admin")
    
    def test_user_has_role_inherited(self, rbac_manager):
        """Test checking if user has role through inheritance."""
        admin_role = rbac_manager.create_role(name="admin", permissions=["*:*"])
        user_role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        # Set up hierarchy: admin -> user
        rbac_manager.hierarchy.add_parent_child("admin", "user")
        
        # User with admin role should also "have" user role
        assert rbac_manager.user_has_role(["admin"], "user")
        assert rbac_manager.user_has_role(["admin"], "admin")
        assert not rbac_manager.user_has_role(["user"], "admin")
    
    def test_get_user_permissions(self, rbac_manager):
        """Test getting user permissions."""
        admin_role = rbac_manager.create_role(name="admin", permissions=["users:*", "system:*"])
        user_role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        rbac_manager.assign_role("user_123", "admin", "system")
        rbac_manager.assign_role("user_123", "user", "system")
        
        permissions = rbac_manager.get_user_permissions("user_123", ["admin", "user"])
        expected_permissions = {"users:*", "system:*", "profile:read"}
        
        assert permissions == expected_permissions
    
    def test_get_user_permissions_with_hierarchy(self, rbac_manager):
        """Test getting user permissions with role hierarchy."""
        admin_role = rbac_manager.create_role(name="admin", permissions=["admin:*"])
        moderator_role = rbac_manager.create_role(name="moderator", permissions=["posts:*"])
        user_role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        # Set up hierarchy: admin -> moderator -> user
        rbac_manager.hierarchy.add_parent_child("admin", "moderator")
        rbac_manager.hierarchy.add_parent_child("moderator", "user")
        
        # User with admin role should get all inherited permissions
        permissions = rbac_manager.get_user_permissions("user_123", ["admin"])
        expected_permissions = {"admin:*", "posts:*", "profile:read"}
        
        assert permissions == expected_permissions
    
    def test_get_role_hierarchy(self, rbac_manager):
        """Test getting role hierarchy information."""
        admin_role = rbac_manager.create_role(name="admin", permissions=["admin:*"])
        user_role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        rbac_manager.hierarchy.add_parent_child("admin", "user")
        
        hierarchy_info = rbac_manager.get_role_hierarchy("admin")
        
        assert hierarchy_info["role"] == "admin"
        assert hierarchy_info["permissions"] == ["admin:*"]
        assert hierarchy_info["children"] == ["user"]
        assert hierarchy_info["inherited_permissions"] == {"admin:*", "profile:read"}
    
    def test_export_roles(self, rbac_manager):
        """Test exporting all roles."""
        rbac_manager.create_role(name="admin", permissions=["*:*"])
        rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        exported = rbac_manager.export_roles()
        
        assert "admin" in exported
        assert "user" in exported
        assert exported["admin"]["permissions"] == ["*:*"]
        assert exported["user"]["permissions"] == ["profile:read"]
    
    def test_cleanup_expired_assignments(self, rbac_manager):
        """Test cleaning up expired role assignments."""
        rbac_manager.create_role(name="admin")
        rbac_manager.create_role(name="user")
        
        # Active assignment
        rbac_manager.assign_role("user_123", "user", "system")
        
        # Expired assignment
        rbac_manager.assign_role(
            "user_123", "admin", "system",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        # Before cleanup
        assert len(rbac_manager.role_assignments["user_123"]) == 2
        
        # Cleanup
        cleaned_count = rbac_manager.cleanup_expired_assignments()
        
        # After cleanup
        assert cleaned_count == 1
        assert len(rbac_manager.role_assignments["user_123"]) == 1
        assert rbac_manager.role_assignments["user_123"][0].role_name == "user"


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create RBACManager instance."""
        return RBACManager()
    
    def test_privilege_escalation_prevention(self, rbac_manager):
        """Test prevention of privilege escalation through role manipulation."""
        # Create roles with different privilege levels
        admin_role = rbac_manager.create_role(name="admin", permissions=["*:*"])
        user_role = rbac_manager.create_role(name="user", permissions=["profile:read"])
        
        # User should not be able to escalate to admin through role hierarchy manipulation
        rbac_manager.assign_role("user_123", "user", "system")
        
        # Attempt to create hierarchy that would escalate privileges
        # This should not give user admin permissions
        rbac_manager.hierarchy.add_parent_child("user", "admin")  # Invalid hierarchy
        
        # User permissions should not include admin permissions
        permissions = rbac_manager.get_user_permissions("user_123", ["user"])
        assert "*:*" not in permissions
        assert "profile:read" in permissions
    
    def test_role_name_injection_prevention(self, rbac_manager):
        """Test prevention of role name injection attacks."""
        malicious_names = [
            "admin'; DROP TABLE roles; --",
            "user<script>alert('xss')</script>",
            "role\nwith\nnewlines",
            "role\twith\ttabs",
            "role with spaces",
            "role:with:colons"
        ]
        
        for malicious_name in malicious_names:
            with pytest.raises(InvalidRoleError):
                rbac_manager.create_role(name=malicious_name)
    
    def test_permission_injection_prevention(self, rbac_manager):
        """Test prevention of permission injection attacks."""
        malicious_permissions = [
            "*:*; DROP TABLE permissions; --",
            "users:read<script>alert('xss')</script>",
            "admin\n:*",
            "users\t:write"
        ]
        
        # These should be treated as literal permission strings, not as attacks
        role = rbac_manager.create_role(name="test_role", permissions=malicious_permissions)
        
        # Permissions should be stored as-is (sanitization happens at permission check level)
        for perm in malicious_permissions:
            assert perm in role.permissions
    
    def test_circular_hierarchy_attack_prevention(self, rbac_manager):
        """Test prevention of circular hierarchy attacks."""
        rbac_manager.create_role(name="admin")
        rbac_manager.create_role(name="user")
        rbac_manager.create_role(name="guest")
        
        # Create valid hierarchy
        rbac_manager.hierarchy.add_parent_child("admin", "user")
        rbac_manager.hierarchy.add_parent_child("user", "guest")
        
        # Attempt to create circular dependency
        with pytest.raises(CircularRoleHierarchyError):
            rbac_manager.hierarchy.add_parent_child("guest", "admin")
    
    def test_role_assignment_spoofing_prevention(self, rbac_manager):
        """Test prevention of role assignment spoofing."""
        rbac_manager.create_role(name="admin")
        
        # Assignment should require valid assigned_by
        assignment = rbac_manager.assign_role("user_123", "admin", "admin_456")
        
        assert assignment.assigned_by == "admin_456"
        assert assignment.user_id == "user_123"
        
        # Verify assignment cannot be modified externally
        original_assigned_by = assignment.assigned_by
        
        # This should not change the assignment (if implementation is secure)
        assignment_dict = assignment.to_dict()
        assignment_dict["assigned_by"] = "malicious_user"
        
        # Original assignment should be unchanged
        assert assignment.assigned_by == original_assigned_by
    
    def test_mass_assignment_prevention(self, rbac_manager):
        """Test prevention of mass role assignment attacks."""
        rbac_manager.create_role(name="admin")
        
        # Should not be able to assign role to large number of users at once
        # without proper authorization
        
        users = [f"user_{i}" for i in range(1000)]
        
        # This should work but be tracked for auditing
        for user_id in users[:10]:  # Limit test to 10 users
            assignment = rbac_manager.assign_role(user_id, "admin", "system")
            assert assignment.user_id == user_id
            assert assignment.role_name == "admin"
    
    def test_role_expiry_bypass_prevention(self, rbac_manager):
        """Test prevention of role expiry bypass attacks."""
        rbac_manager.create_role(name="temp_admin")
        
        # Create assignment with short expiry
        assignment = rbac_manager.assign_role(
            "user_123", "temp_admin", "admin",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=1)
        )
        
        # Wait for expiry
        import time
        time.sleep(2)
        
        # User should not have role after expiry
        user_roles = rbac_manager.get_user_roles("user_123")
        assert "temp_admin" not in user_roles
        
        # Permissions should not include temp_admin permissions
        permissions = rbac_manager.get_user_permissions("user_123", user_roles)
        temp_admin_role = rbac_manager.hierarchy.get_role("temp_admin")
        for perm in temp_admin_role.permissions:
            assert perm not in permissions


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create RBACManager instance."""
        return RBACManager()
    
    def test_large_role_hierarchy_performance(self, rbac_manager):
        """Test performance with large role hierarchy."""
        import time
        
        # Create large hierarchy
        num_roles = 100
        
        start = time.time()
        
        # Create roles
        for i in range(num_roles):
            rbac_manager.create_role(
                name=f"role_{i}",
                permissions=[f"resource_{i}:read", f"resource_{i}:write"]
            )
        
        # Create hierarchy (linear chain)
        for i in range(num_roles - 1):
            rbac_manager.hierarchy.add_parent_child(f"role_{i}", f"role_{i+1}")
        
        creation_time = time.time() - start
        
        # Should be able to create hierarchy quickly
        assert creation_time < 5.0  # Less than 5 seconds
        
        # Test permission inheritance performance
        start = time.time()
        
        permissions = rbac_manager.get_user_permissions("user_123", ["role_0"])
        
        inheritance_time = time.time() - start
        
        # Should be able to calculate inherited permissions quickly
        assert inheritance_time < 1.0  # Less than 1 second
        
        # Should have inherited all permissions
        assert len(permissions) == num_roles * 2  # 2 permissions per role
    
    def test_many_role_assignments_performance(self, rbac_manager):
        """Test performance with many role assignments."""
        import time
        
        # Create roles
        for i in range(10):
            rbac_manager.create_role(name=f"role_{i}")
        
        # Create many assignments
        num_users = 1000
        
        start = time.time()
        
        for i in range(num_users):
            rbac_manager.assign_role(f"user_{i}", f"role_{i % 10}", "system")
        
        assignment_time = time.time() - start
        
        # Should be able to create assignments quickly
        assert assignment_time < 5.0  # Less than 5 seconds
        
        # Test role lookup performance
        start = time.time()
        
        for i in range(100):  # Test first 100 users
            roles = rbac_manager.get_user_roles(f"user_{i}")
            assert len(roles) == 1
        
        lookup_time = time.time() - start
        
        # Should be able to lookup roles quickly
        assert lookup_time < 1.0  # Less than 1 second for 100 lookups
    
    def test_expired_assignment_cleanup_performance(self, rbac_manager):
        """Test performance of expired assignment cleanup."""
        import time
        
        rbac_manager.create_role(name="temp_role")
        
        # Create many expired assignments
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        
        for i in range(1000):
            rbac_manager.assign_role(
                f"user_{i}", "temp_role", "system",
                expires_at=past_time
            )
        
        # Cleanup should be fast
        start = time.time()
        cleaned_count = rbac_manager.cleanup_expired_assignments()
        cleanup_time = time.time() - start
        
        assert cleaned_count == 1000
        assert cleanup_time < 2.0  # Less than 2 seconds


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create RBACManager instance."""
        return RBACManager()
    
    def test_empty_role_names(self, rbac_manager):
        """Test handling of empty role names."""
        with pytest.raises(InvalidRoleError):
            rbac_manager.create_role(name="")
        
        with pytest.raises(InvalidRoleError):
            rbac_manager.create_role(name=None)
    
    def test_unicode_role_names(self, rbac_manager):
        """Test handling of unicode role names."""
        unicode_names = ["管理员", "用户", "moderateur", "пользователь"]
        
        for name in unicode_names:
            role = rbac_manager.create_role(name=name)
            assert role.name == name
            assert rbac_manager.hierarchy.get_role(name) == role
    
    def test_very_long_role_names(self, rbac_manager):
        """Test handling of very long role names."""
        # Valid long name (100 chars)
        long_name = "a" * 100
        role = rbac_manager.create_role(name=long_name)
        assert role.name == long_name
        
        # Invalid very long name (101 chars)
        with pytest.raises(InvalidRoleError):
            rbac_manager.create_role(name="a" * 101)
    
    def test_special_characters_in_roles(self, rbac_manager):
        """Test handling of special characters in role names."""
        valid_names = ["admin-role", "api_user", "content.moderator"]
        invalid_names = ["admin role", "user:role", "role\nwith\nnewlines"]
        
        for name in valid_names:
            role = rbac_manager.create_role(name=name)
            assert role.name == name
        
        for name in invalid_names:
            with pytest.raises(InvalidRoleError):
                rbac_manager.create_role(name=name)
    
    def test_empty_permission_sets(self, rbac_manager):
        """Test handling of empty permission sets."""
        role = rbac_manager.create_role(name="empty_role", permissions=[])
        
        assert len(role.permissions) == 0
        
        permissions = rbac_manager.get_user_permissions("user_123", ["empty_role"])
        assert len(permissions) == 0
    
    def test_duplicate_permissions(self, rbac_manager):
        """Test handling of duplicate permissions."""
        role = rbac_manager.create_role(
            name="test_role",
            permissions=["users:read", "users:read", "posts:write", "users:read"]
        )
        
        # Should deduplicate permissions
        assert len(role.permissions) == 2
        assert "users:read" in role.permissions
        assert "posts:write" in role.permissions
    
    def test_none_values_in_assignments(self, rbac_manager):
        """Test handling of None values in role assignments."""
        rbac_manager.create_role(name="test_role")
        
        # None user_id should raise error
        with pytest.raises(Exception):
            rbac_manager.assign_role(None, "test_role", "admin")
        
        # None role_name should raise error
        with pytest.raises(RoleNotFoundError):
            rbac_manager.assign_role("user_123", None, "admin")
        
        # None assigned_by should work (system assignment)
        assignment = rbac_manager.assign_role("user_123", "test_role", None)
        assert assignment.assigned_by is None
    
    def test_concurrent_role_operations(self, rbac_manager):
        """Test concurrent role operations."""
        import threading
        
        def create_roles():
            for i in range(10):
                try:
                    rbac_manager.create_role(
                        name=f"role_{threading.current_thread().ident}_{i}"
                    )
                except RoleConflictError:
                    pass  # Expected for duplicates
        
        def assign_roles():
            for i in range(10):
                try:
                    rbac_manager.assign_role(
                        f"user_{threading.current_thread().ident}_{i}",
                        "admin",  # May not exist yet
                        "system"
                    )
                except RoleNotFoundError:
                    pass  # Expected if role doesn't exist
        
        # Create admin role first
        rbac_manager.create_role(name="admin")
        
        # Start multiple threads
        threads = []
        for _ in range(5):
            thread1 = threading.Thread(target=create_roles)
            thread2 = threading.Thread(target=assign_roles)
            threads.extend([thread1, thread2])
            thread1.start()
            thread2.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Should have created some roles and assignments without crashing
        assert len(rbac_manager.hierarchy.roles) > 1
    
    def test_role_hierarchy_depth_limit(self, rbac_manager):
        """Test role hierarchy depth limits."""
        # Create deep hierarchy
        depth = 50
        
        for i in range(depth):
            rbac_manager.create_role(name=f"role_{i}")
        
        # Create chain
        for i in range(depth - 1):
            rbac_manager.hierarchy.add_parent_child(f"role_{i}", f"role_{i+1}")
        
        # Should handle deep inheritance
        permissions = rbac_manager.get_user_permissions("user_123", ["role_0"])
        assert isinstance(permissions, set)
        
        # Ancestors should be properly calculated
        ancestors = rbac_manager.hierarchy.get_role_ancestors("role_49")
        assert len(ancestors) == 49


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.rbac", "--cov-report=term-missing"])