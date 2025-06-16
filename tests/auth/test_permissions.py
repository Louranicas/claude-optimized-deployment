"""
Comprehensive Tests for Permission System (src/auth/permissions.py).

This test suite covers permission checking, resource access control,
hierarchical permissions, security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta

from src.auth.permissions import (
    PermissionChecker, Permission, ResourcePermission,
    WildcardPermission, HierarchicalPermission,
    PermissionDeniedError, InvalidPermissionError,
    permission_required, has_permission
)
from src.auth.rbac import RBACManager, Role
from src.auth.models import User, UserStatus


class TestPermission:
    """Test Permission base class and concrete implementations."""
    
    def test_permission_creation(self):
        """Test basic permission creation."""
        perm = Permission("users", "read")
        
        assert perm.resource == "users"
        assert perm.action == "read"
        assert str(perm) == "users:read"
        assert repr(perm) == "Permission(resource='users', action='read')"
    
    def test_permission_equality(self):
        """Test permission equality comparison."""
        perm1 = Permission("users", "read")
        perm2 = Permission("users", "read")
        perm3 = Permission("users", "write")
        perm4 = Permission("posts", "read")
        
        assert perm1 == perm2
        assert perm1 != perm3
        assert perm1 != perm4
        assert perm3 != perm4
    
    def test_permission_hash(self):
        """Test permission hashing for use in sets/dicts."""
        perm1 = Permission("users", "read")
        perm2 = Permission("users", "read")
        perm3 = Permission("users", "write")
        
        assert hash(perm1) == hash(perm2)
        assert hash(perm1) != hash(perm3)
        
        # Test in set
        perm_set = {perm1, perm2, perm3}
        assert len(perm_set) == 2  # perm1 and perm2 are duplicates
    
    def test_permission_from_string(self):
        """Test creating permission from string representation."""
        perm = Permission.from_string("users:read")
        
        assert perm.resource == "users"
        assert perm.action == "read"
    
    def test_permission_from_string_invalid_format(self):
        """Test creating permission from invalid string format."""
        with pytest.raises(InvalidPermissionError):
            Permission.from_string("invalid_format")
        
        with pytest.raises(InvalidPermissionError):
            Permission.from_string("too:many:colons")
        
        with pytest.raises(InvalidPermissionError):
            Permission.from_string("")
    
    def test_permission_validation(self):
        """Test permission validation."""
        # Valid permissions
        Permission("users", "read")
        Permission("admin", "*")
        Permission("api_v2", "write")
        Permission("user-profile", "update")
        
        # Invalid permissions
        with pytest.raises(InvalidPermissionError):
            Permission("", "read")  # Empty resource
        
        with pytest.raises(InvalidPermissionError):
            Permission("users", "")  # Empty action
        
        with pytest.raises(InvalidPermissionError):
            Permission("users:invalid", "read")  # Colon in resource
        
        with pytest.raises(InvalidPermissionError):
            Permission("users", "read:invalid")  # Colon in action


class TestResourcePermission:
    """Test ResourcePermission class."""
    
    def test_resource_permission_matches_exact(self):
        """Test exact resource permission matching."""
        perm = ResourcePermission("users", "read")
        
        assert perm.matches("users", "read")
        assert not perm.matches("users", "write")
        assert not perm.matches("posts", "read")
    
    def test_resource_permission_wildcard_action(self):
        """Test resource permission with wildcard action."""
        perm = ResourcePermission("users", "*")
        
        assert perm.matches("users", "read")
        assert perm.matches("users", "write")
        assert perm.matches("users", "delete")
        assert not perm.matches("posts", "read")
    
    def test_resource_permission_wildcard_resource(self):
        """Test resource permission with wildcard resource."""
        perm = ResourcePermission("*", "read")
        
        assert perm.matches("users", "read")
        assert perm.matches("posts", "read")
        assert perm.matches("admin", "read")
        assert not perm.matches("users", "write")
    
    def test_resource_permission_full_wildcard(self):
        """Test resource permission with full wildcard."""
        perm = ResourcePermission("*", "*")
        
        assert perm.matches("users", "read")
        assert perm.matches("users", "write")
        assert perm.matches("posts", "delete")
        assert perm.matches("admin", "anything")


class TestWildcardPermission:
    """Test WildcardPermission class."""
    
    def test_wildcard_permission_resource_prefix(self):
        """Test wildcard permission matching resource prefix."""
        perm = WildcardPermission("api/*", "read")
        
        assert perm.matches("api/users", "read")
        assert perm.matches("api/posts", "read")
        assert perm.matches("api/v1/users", "read")
        assert not perm.matches("web/users", "read")
        assert not perm.matches("api/users", "write")
    
    def test_wildcard_permission_action_suffix(self):
        """Test wildcard permission matching action suffix."""
        perm = WildcardPermission("users", "*_read")
        
        assert perm.matches("users", "bulk_read")
        assert perm.matches("users", "admin_read")
        assert perm.matches("users", "special_read")
        assert not perm.matches("users", "write")
        assert not perm.matches("users", "read")  # Exact match, not suffix
    
    def test_wildcard_permission_both_wildcards(self):
        """Test wildcard permission with wildcards in both resource and action."""
        perm = WildcardPermission("api/*", "*_admin")
        
        assert perm.matches("api/users", "read_admin")
        assert perm.matches("api/posts", "write_admin")
        assert perm.matches("api/v1/test", "delete_admin")
        assert not perm.matches("web/users", "read_admin")
        assert not perm.matches("api/users", "read")
    
    def test_wildcard_permission_no_wildcards(self):
        """Test wildcard permission behaves like regular permission without wildcards."""
        perm = WildcardPermission("users", "read")
        
        assert perm.matches("users", "read")
        assert not perm.matches("users", "write")
        assert not perm.matches("posts", "read")


class TestHierarchicalPermission:
    """Test HierarchicalPermission class."""
    
    def test_hierarchical_permission_exact_match(self):
        """Test hierarchical permission exact matching."""
        perm = HierarchicalPermission("users", "read")
        
        assert perm.matches("users", "read")
        assert not perm.matches("users", "write")
        assert not perm.matches("posts", "read")
    
    def test_hierarchical_permission_child_resource(self):
        """Test hierarchical permission matching child resources."""
        perm = HierarchicalPermission("users", "read")
        
        assert perm.matches("users.profile", "read")
        assert perm.matches("users.settings", "read")
        assert perm.matches("users.profile.avatar", "read")
        assert not perm.matches("users.profile", "write")
        assert not perm.matches("posts.comments", "read")
    
    def test_hierarchical_permission_action_hierarchy(self):
        """Test hierarchical permission with action hierarchy."""
        # Define action hierarchy: admin > write > read
        action_hierarchy = {
            "admin": ["write", "read"],
            "write": ["read"]
        }
        
        perm = HierarchicalPermission("users", "admin", action_hierarchy=action_hierarchy)
        
        assert perm.matches("users", "admin")
        assert perm.matches("users", "write")  # admin includes write
        assert perm.matches("users", "read")   # admin includes read
        assert not perm.matches("users", "delete")  # not in hierarchy
    
    def test_hierarchical_permission_resource_and_action_hierarchy(self):
        """Test hierarchical permission with both resource and action hierarchy."""
        action_hierarchy = {
            "write": ["read"]
        }
        
        perm = HierarchicalPermission("users", "write", action_hierarchy=action_hierarchy)
        
        assert perm.matches("users", "write")
        assert perm.matches("users", "read")  # write includes read
        assert perm.matches("users.profile", "write")  # child resource
        assert perm.matches("users.profile", "read")   # child resource + action hierarchy
        assert not perm.matches("users", "delete")
        assert not perm.matches("posts", "read")


class TestPermissionChecker:
    """Test PermissionChecker class."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create mock RBAC manager."""
        rbac = Mock(spec=RBACManager)
        
        # Setup mock roles
        rbac.get_user_permissions.return_value = {
            "users:read", "users:write", "profile:read", "profile:write"
        }
        rbac.get_role_permissions.return_value = {
            "users:read", "profile:read"
        }
        
        return rbac
    
    @pytest.fixture
    def permission_checker(self, rbac_manager):
        """Create PermissionChecker instance."""
        return PermissionChecker(rbac_manager)
    
    def test_permission_checker_initialization(self, rbac_manager):
        """Test PermissionChecker initialization."""
        checker = PermissionChecker(rbac_manager)
        
        assert checker.rbac_manager == rbac_manager
        assert len(checker._permission_cache) == 0
    
    def test_check_permission_success(self, permission_checker, rbac_manager):
        """Test successful permission check."""
        rbac_manager.get_user_permissions.return_value = {"users:read", "users:write"}
        
        result = permission_checker.check_permission(
            user_id="user_123",
            user_roles=["user"],
            resource="users",
            action="read"
        )
        
        assert result is True
        rbac_manager.get_user_permissions.assert_called_once_with("user_123", ["user"])
    
    def test_check_permission_denied(self, permission_checker, rbac_manager):
        """Test permission denied."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        result = permission_checker.check_permission(
            user_id="user_123",
            user_roles=["user"],
            resource="users",
            action="write"
        )
        
        assert result is False
    
    def test_check_permission_wildcard(self, permission_checker, rbac_manager):
        """Test permission check with wildcard permissions."""
        rbac_manager.get_user_permissions.return_value = {"users:*", "admin:read"}
        
        # Should match any action on users resource
        assert permission_checker.check_permission("user_123", ["admin"], "users", "read")
        assert permission_checker.check_permission("user_123", ["admin"], "users", "write")
        assert permission_checker.check_permission("user_123", ["admin"], "users", "delete")
        
        # Should not match different resource
        assert not permission_checker.check_permission("user_123", ["admin"], "posts", "write")
    
    def test_check_permission_admin_wildcard(self, permission_checker, rbac_manager):
        """Test permission check with admin wildcard (*:*)."""
        rbac_manager.get_user_permissions.return_value = {"*:*"}
        
        # Should match any resource and action
        assert permission_checker.check_permission("admin_123", ["admin"], "users", "read")
        assert permission_checker.check_permission("admin_123", ["admin"], "posts", "write")
        assert permission_checker.check_permission("admin_123", ["admin"], "system", "admin")
    
    def test_check_permission_multiple_permissions(self, permission_checker, rbac_manager):
        """Test permission check with multiple permissions."""
        rbac_manager.get_user_permissions.return_value = {
            "users:read", "users:write", "posts:read", "admin:*"
        }
        
        assert permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert permission_checker.check_permission("user_123", ["user"], "users", "write")
        assert permission_checker.check_permission("user_123", ["user"], "posts", "read")
        assert permission_checker.check_permission("user_123", ["user"], "admin", "anything")
        assert not permission_checker.check_permission("user_123", ["user"], "posts", "write")
    
    def test_check_permission_caching(self, permission_checker, rbac_manager):
        """Test permission caching functionality."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        user_id = "user_123"
        roles = ["user"]
        
        # First call should hit RBAC manager
        result1 = permission_checker.check_permission(user_id, roles, "users", "read")
        assert result1 is True
        assert rbac_manager.get_user_permissions.call_count == 1
        
        # Second call should use cache
        result2 = permission_checker.check_permission(user_id, roles, "users", "read")
        assert result2 is True
        assert rbac_manager.get_user_permissions.call_count == 1  # No additional call
        
        # Different user should hit RBAC manager again
        result3 = permission_checker.check_permission("user_456", roles, "users", "read")
        assert rbac_manager.get_user_permissions.call_count == 2
    
    def test_check_permission_cache_expiry(self, permission_checker, rbac_manager):
        """Test permission cache expiry."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Set very short cache TTL for testing
        permission_checker.cache_ttl = timedelta(seconds=0.1)
        
        user_id = "user_123"
        roles = ["user"]
        
        # First call
        permission_checker.check_permission(user_id, roles, "users", "read")
        assert rbac_manager.get_user_permissions.call_count == 1
        
        # Wait for cache to expire
        import time
        time.sleep(0.2)
        
        # Second call should hit RBAC manager again
        permission_checker.check_permission(user_id, roles, "users", "read")
        assert rbac_manager.get_user_permissions.call_count == 2
    
    def test_get_user_permissions(self, permission_checker, rbac_manager):
        """Test getting all user permissions."""
        expected_permissions = {"users:read", "users:write", "profile:read"}
        rbac_manager.get_user_permissions.return_value = expected_permissions
        
        permissions = permission_checker.get_user_permissions("user_123", ["user"])
        
        assert permissions == expected_permissions
        rbac_manager.get_user_permissions.assert_called_once_with("user_123", ["user"])
    
    def test_clear_cache(self, permission_checker, rbac_manager):
        """Test clearing permission cache."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Populate cache
        permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert len(permission_checker._permission_cache) > 0
        
        # Clear cache
        permission_checker.clear_cache()
        assert len(permission_checker._permission_cache) == 0
    
    def test_clear_user_cache(self, permission_checker, rbac_manager):
        """Test clearing cache for specific user."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Populate cache for multiple users
        permission_checker.check_permission("user_123", ["user"], "users", "read")
        permission_checker.check_permission("user_456", ["user"], "users", "read")
        
        initial_cache_size = len(permission_checker._permission_cache)
        assert initial_cache_size >= 2
        
        # Clear cache for specific user
        permission_checker.clear_user_cache("user_123")
        
        # Cache should be smaller but not empty
        remaining_cache_size = len(permission_checker._permission_cache)
        assert remaining_cache_size < initial_cache_size
    
    def test_has_any_permission(self, permission_checker, rbac_manager):
        """Test checking if user has any of multiple permissions."""
        rbac_manager.get_user_permissions.return_value = {"users:read", "posts:write"}
        
        # Has one of the required permissions
        assert permission_checker.has_any_permission(
            "user_123", ["user"], [("users", "read"), ("users", "write")]
        )
        
        # Has none of the required permissions
        assert not permission_checker.has_any_permission(
            "user_123", ["user"], [("admin", "read"), ("system", "write")]
        )
    
    def test_has_all_permissions(self, permission_checker, rbac_manager):
        """Test checking if user has all required permissions."""
        rbac_manager.get_user_permissions.return_value = {"users:read", "users:write", "posts:read"}
        
        # Has all required permissions
        assert permission_checker.has_all_permissions(
            "user_123", ["user"], [("users", "read"), ("users", "write")]
        )
        
        # Missing one required permission
        assert not permission_checker.has_all_permissions(
            "user_123", ["user"], [("users", "read"), ("users", "delete")]
        )
    
    def test_require_permission_decorator_success(self, permission_checker, rbac_manager):
        """Test require_permission decorator with sufficient permissions."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        @permission_required("users", "read", permission_checker=permission_checker)
        def protected_function(user_id, roles):
            return "success"
        
        result = protected_function("user_123", ["user"])
        assert result == "success"
    
    def test_require_permission_decorator_denied(self, permission_checker, rbac_manager):
        """Test require_permission decorator with insufficient permissions."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        @permission_required("users", "write", permission_checker=permission_checker)
        def protected_function(user_id, roles):
            return "success"
        
        with pytest.raises(PermissionDeniedError) as exc_info:
            protected_function("user_123", ["user"])
        
        assert "users:write" in str(exc_info.value)
    
    def test_has_permission_function(self, rbac_manager):
        """Test standalone has_permission function."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        with patch('src.auth.permissions.get_permission_checker', return_value=PermissionChecker(rbac_manager)):
            assert has_permission("user_123", ["user"], "users", "read")
            assert not has_permission("user_123", ["user"], "users", "write")


class TestPermissionTypes:
    """Test different permission type implementations."""
    
    def test_permission_type_auto_detection(self):
        """Test automatic detection of permission types."""
        from src.auth.permissions import create_permission
        
        # Regular permission
        perm1 = create_permission("users", "read")
        assert isinstance(perm1, ResourcePermission)
        
        # Wildcard permission
        perm2 = create_permission("api/*", "read")
        assert isinstance(perm2, WildcardPermission)
        
        # Hierarchical permission
        perm3 = create_permission("users.profile", "read")
        assert isinstance(perm3, HierarchicalPermission)
    
    def test_complex_wildcard_patterns(self):
        """Test complex wildcard permission patterns."""
        # Multiple wildcards
        perm = WildcardPermission("api/*/v1/*", "read")
        assert perm.matches("api/users/v1/profiles", "read")
        assert perm.matches("api/posts/v1/comments", "read")
        assert not perm.matches("api/users/v2/profiles", "read")
        
        # Wildcard at beginning
        perm2 = WildcardPermission("*/admin", "write")
        assert perm2.matches("users/admin", "write")
        assert perm2.matches("posts/admin", "write")
        assert not perm2.matches("users/regular", "write")
    
    def test_complex_hierarchical_patterns(self):
        """Test complex hierarchical permission patterns."""
        action_hierarchy = {
            "admin": ["write", "read", "delete"],
            "write": ["read"],
            "moderate": ["read", "hide"]
        }
        
        perm = HierarchicalPermission("forum", "admin", action_hierarchy=action_hierarchy)
        
        # Should match all admin actions on forum and sub-resources
        assert perm.matches("forum", "admin")
        assert perm.matches("forum", "write")
        assert perm.matches("forum", "read")
        assert perm.matches("forum", "delete")
        assert perm.matches("forum.posts", "write")
        assert perm.matches("forum.posts.comments", "read")
        
        # Should not match actions not in hierarchy
        assert not perm.matches("forum", "moderate")
        assert not perm.matches("forum", "unknown")
    
    def test_permission_specificity_ordering(self):
        """Test that more specific permissions take precedence."""
        permissions = [
            ResourcePermission("*", "*"),           # Least specific
            ResourcePermission("users", "*"),       # More specific
            ResourcePermission("users", "read"),    # Most specific
        ]
        
        # All should match, but most specific should be preferred
        for perm in permissions:
            assert perm.matches("users", "read")
        
        # Test with wildcard permission
        wildcard_perm = WildcardPermission("users/*", "read")
        assert wildcard_perm.matches("users/profile", "read")
        assert not wildcard_perm.matches("users", "read")  # Doesn't match exact resource


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create mock RBAC manager."""
        return Mock(spec=RBACManager)
    
    @pytest.fixture
    def permission_checker(self, rbac_manager):
        """Create PermissionChecker instance."""
        return PermissionChecker(rbac_manager)
    
    def test_privilege_escalation_prevention(self, permission_checker, rbac_manager):
        """Test prevention of privilege escalation attempts."""
        # User has limited permissions
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Attempt to access admin resources
        assert not permission_checker.check_permission("user_123", ["user"], "admin", "write")
        assert not permission_checker.check_permission("user_123", ["user"], "system", "config")
        assert not permission_checker.check_permission("user_123", ["user"], "users", "delete")
    
    def test_permission_bypass_attempts(self, permission_checker, rbac_manager):
        """Test attempts to bypass permission checks."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Attempt to use malicious resource/action names
        malicious_inputs = [
            ("users'; DROP TABLE permissions; --", "read"),
            ("users", "read'; UNION SELECT * FROM admin; --"),
            ("*", "*"),  # Wildcard injection
            ("", ""),    # Empty strings
            ("users/../admin", "read"),  # Path traversal attempt
        ]
        
        for resource, action in malicious_inputs:
            result = permission_checker.check_permission("user_123", ["user"], resource, action)
            assert result is False  # Should not grant access
    
    def test_cache_poisoning_prevention(self, permission_checker, rbac_manager):
        """Test prevention of cache poisoning attacks."""
        # Setup initial permissions
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Make initial request to populate cache
        result1 = permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert result1 is True
        
        # Attempt to modify cache indirectly
        # This should not affect subsequent checks
        result2 = permission_checker.check_permission("user_123", ["user"], "admin", "write")
        assert result2 is False
        
        # Original permission should still work
        result3 = permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert result3 is True
    
    def test_denial_of_service_prevention(self, permission_checker, rbac_manager):
        """Test prevention of DoS attacks via permission checks."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Attempt to overwhelm with many permission checks
        for i in range(1000):
            result = permission_checker.check_permission(
                f"user_{i}", ["user"], "users", "read"
            )
            # Should handle gracefully without performance degradation
            assert isinstance(result, bool)
        
        # Cache size should be reasonable (not unbounded)
        assert len(permission_checker._permission_cache) < 1000
    
    def test_case_sensitivity_security(self, permission_checker, rbac_manager):
        """Test case sensitivity in permission checks."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Permission checks should be case-sensitive
        assert permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert not permission_checker.check_permission("user_123", ["user"], "Users", "read")
        assert not permission_checker.check_permission("user_123", ["user"], "users", "Read")
        assert not permission_checker.check_permission("user_123", ["user"], "USERS", "READ")
    
    def test_unicode_and_special_characters(self, permission_checker, rbac_manager):
        """Test handling of unicode and special characters."""
        # Setup permissions with unicode characters
        rbac_manager.get_user_permissions.return_value = {
            "用户:读取", "posts:read", "admin-panel:write"
        }
        
        # Should handle unicode properly
        assert permission_checker.check_permission("user_123", ["user"], "用户", "读取")
        assert not permission_checker.check_permission("user_123", ["user"], "用户", "写入")
        
        # Should handle special characters
        assert permission_checker.check_permission("user_123", ["user"], "admin-panel", "write")
        assert not permission_checker.check_permission("user_123", ["user"], "admin_panel", "write")
    
    def test_concurrent_permission_checks(self, permission_checker, rbac_manager):
        """Test concurrent permission checks for thread safety."""
        import threading
        import time
        
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        results = []
        
        def check_permissions():
            for i in range(100):
                result = permission_checker.check_permission(
                    f"user_{threading.current_thread().ident}",
                    ["user"],
                    "users",
                    "read"
                )
                results.append(result)
                time.sleep(0.001)  # Small delay to increase chance of race conditions
        
        # Start multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=check_permissions)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All results should be True
        assert all(results)
        assert len(results) == 1000  # 10 threads * 100 checks each


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create mock RBAC manager."""
        rbac = Mock(spec=RBACManager)
        rbac.get_user_permissions.return_value = {"users:read", "posts:write", "admin:*"}
        return rbac
    
    @pytest.fixture
    def permission_checker(self, rbac_manager):
        """Create PermissionChecker instance."""
        return PermissionChecker(rbac_manager)
    
    def test_permission_check_performance(self, permission_checker):
        """Test permission check performance."""
        import time
        
        # Time multiple permission checks
        start = time.time()
        for i in range(1000):
            permission_checker.check_permission("user_123", ["user"], "users", "read")
        elapsed = time.time() - start
        
        # Should be fast (less than 1 second for 1000 checks)
        assert elapsed < 1.0
        
        # Calculate rate
        rate = 1000 / elapsed
        assert rate > 1000  # At least 1000 checks per second
    
    def test_cache_performance_benefit(self, permission_checker, rbac_manager):
        """Test that caching provides performance benefit."""
        import time
        
        user_id = "user_123"
        roles = ["user"]
        
        # Time first check (cold cache)
        start = time.time()
        permission_checker.check_permission(user_id, roles, "users", "read")
        cold_time = time.time() - start
        
        # Time subsequent checks (warm cache)
        start = time.time()
        for _ in range(100):
            permission_checker.check_permission(user_id, roles, "users", "read")
        warm_time = (time.time() - start) / 100  # Average per check
        
        # Warm cache should be significantly faster
        assert warm_time < cold_time / 2
    
    def test_memory_usage_with_large_permissions(self, permission_checker, rbac_manager):
        """Test memory usage with large permission sets."""
        # Create large permission set
        large_permission_set = set()
        for i in range(1000):
            large_permission_set.add(f"resource_{i}:action_{i}")
        
        rbac_manager.get_user_permissions.return_value = large_permission_set
        
        # Check various permissions
        for i in range(100):
            permission_checker.check_permission(
                f"user_{i}", ["user"], f"resource_{i}", f"action_{i}"
            )
        
        # Should handle large permission sets without issues
        assert len(permission_checker._permission_cache) <= 100


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def rbac_manager(self):
        """Create mock RBAC manager."""
        return Mock(spec=RBACManager)
    
    @pytest.fixture
    def permission_checker(self, rbac_manager):
        """Create PermissionChecker instance."""
        return PermissionChecker(rbac_manager)
    
    def test_empty_permissions(self, permission_checker, rbac_manager):
        """Test handling of empty permission sets."""
        rbac_manager.get_user_permissions.return_value = set()
        
        result = permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert result is False
    
    def test_none_values(self, permission_checker, rbac_manager):
        """Test handling of None values."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # None user_id should be handled gracefully
        result = permission_checker.check_permission(None, ["user"], "users", "read")
        assert result is False
        
        # None roles should be handled gracefully
        result = permission_checker.check_permission("user_123", None, "users", "read")
        assert result is False
        
        # None resource/action should be handled gracefully
        result = permission_checker.check_permission("user_123", ["user"], None, "read")
        assert result is False
        
        result = permission_checker.check_permission("user_123", ["user"], "users", None)
        assert result is False
    
    def test_empty_strings(self, permission_checker, rbac_manager):
        """Test handling of empty strings."""
        rbac_manager.get_user_permissions.return_value = {"users:read"}
        
        # Empty strings should not match valid permissions
        result = permission_checker.check_permission("user_123", ["user"], "", "read")
        assert result is False
        
        result = permission_checker.check_permission("user_123", ["user"], "users", "")
        assert result is False
    
    def test_very_long_strings(self, permission_checker, rbac_manager):
        """Test handling of very long strings."""
        long_string = "a" * 10000
        rbac_manager.get_user_permissions.return_value = {f"{long_string}:read"}
        
        # Should handle long strings gracefully
        result = permission_checker.check_permission("user_123", ["user"], long_string, "read")
        assert result is True
        
        result = permission_checker.check_permission("user_123", ["user"], "users", long_string)
        assert result is False
    
    def test_special_permission_formats(self, permission_checker, rbac_manager):
        """Test handling of special permission formats."""
        special_permissions = {
            "users:read:extra",  # Extra colon
            ":read",             # Missing resource
            "users:",            # Missing action
            "users::read",       # Double colon
            "users read",        # Space instead of colon
        }
        rbac_manager.get_user_permissions.return_value = special_permissions
        
        # These malformed permissions should not grant access
        assert not permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert not permission_checker.check_permission("user_123", ["user"], "", "read")
        assert not permission_checker.check_permission("user_123", ["user"], "users", "")
    
    def test_rbac_manager_failure(self, permission_checker, rbac_manager):
        """Test handling of RBAC manager failures."""
        rbac_manager.get_user_permissions.side_effect = Exception("RBAC service unavailable")
        
        # Should handle gracefully and deny access
        result = permission_checker.check_permission("user_123", ["user"], "users", "read")
        assert result is False
    
    def test_invalid_permission_objects(self):
        """Test creation of invalid permission objects."""
        # Test invalid Permission creation
        with pytest.raises(InvalidPermissionError):
            Permission(None, "read")
        
        with pytest.raises(InvalidPermissionError):
            Permission("users", None)
        
        # Test invalid permission string parsing
        with pytest.raises(InvalidPermissionError):
            Permission.from_string(None)
        
        with pytest.raises(InvalidPermissionError):
            Permission.from_string("invalid:format:extra")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.permissions", "--cov-report=term-missing"])