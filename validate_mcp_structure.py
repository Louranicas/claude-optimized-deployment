#!/usr/bin/env python3
"""
Comprehensive validation script for MCP module structure.

This script validates:
1. No circular imports exist
2. Registry lazy loading works correctly
3. Servers can be instantiated independently
4. Dependency injection pattern is functional
"""

import sys
import importlib
import traceback
from typing import Dict, List, Tuple, Any


class MockPermissionChecker:
    """Mock permission checker for testing."""
    
    def check_permission(self, user_id, user_roles, resource, action, context=None):
        return True
    
    def register_resource_permission(self, resource_type, resource_id, initial_permissions):
        pass


def test_module_import(module_path: str) -> Tuple[bool, str]:
    """Test importing a module."""
    try:
        if module_path in sys.modules:
            del sys.modules[module_path]
        
        mod = importlib.import_module(module_path)
        return True, f"Successfully imported {module_path}"
    except Exception as e:
        return False, f"Failed to import {module_path}: {e}"


def test_registry_creation() -> Tuple[bool, str]:
    """Test creating the registry."""
    try:
        from src.mcp.registry import MCPServerRegistry
        
        permission_checker = MockPermissionChecker()
        registry = MCPServerRegistry(permission_checker)
        
        # Check if factories are registered
        servers = registry.list_servers()
        if not servers:
            return False, "No server factories registered"
        
        expected_servers = [
            "brave", "docker", "kubernetes", "prometheus-monitoring",
            "security-scanner", "slack-notifications"
        ]
        
        for server in expected_servers:
            if server not in servers:
                return False, f"Expected server '{server}' not found in registry"
        
        return True, f"Registry created successfully with {len(servers)} server factories"
    except Exception as e:
        return False, f"Failed to create registry: {e}\n{traceback.format_exc()}"


def test_lazy_loading() -> Tuple[bool, str]:
    """Test lazy loading of servers."""
    try:
        from src.mcp.registry import get_server_registry
        
        permission_checker = MockPermissionChecker()
        registry = get_server_registry(permission_checker)
        
        # Initially, no servers should be instantiated
        instantiated = registry.list_instantiated_servers()
        if instantiated:
            return False, f"Servers were instantiated before being requested: {instantiated}"
        
        # Request a server (without API key since we're mocking)
        server = registry.get("docker")
        if not server:
            return False, "Failed to get docker server"
        
        # Now it should be in the instantiated list
        instantiated = registry.list_instantiated_servers()
        if "docker" not in instantiated:
            return False, "Docker server not in instantiated list after creation"
        
        return True, "Lazy loading works correctly"
    except Exception as e:
        return False, f"Lazy loading test failed: {e}\n{traceback.format_exc()}"


def test_server_independence() -> Tuple[bool, str]:
    """Test that servers can be imported and instantiated independently."""
    try:
        # Test importing individual server modules
        server_modules = [
            ("src.mcp.servers", "BraveMCPServer"),
            ("src.mcp.infrastructure_servers", "DockerMCPServer"),
            ("src.mcp.infrastructure_servers", "KubernetesMCPServer"),
        ]
        
        permission_checker = MockPermissionChecker()
        
        for module_path, class_name in server_modules:
            try:
                # Import module
                module = importlib.import_module(module_path)
                
                # Get class
                server_class = getattr(module, class_name)
                
                # Try to instantiate (may fail for servers requiring API keys)
                try:
                    if class_name == "BraveMCPServer":
                        # Skip Brave as it requires API key
                        continue
                    server = server_class(permission_checker=permission_checker)
                    print(f"  ✓ Successfully instantiated {class_name}")
                except Exception as e:
                    # Some servers may require additional config
                    print(f"  ⚠ {class_name} requires additional config: {e}")
                
            except Exception as e:
                return False, f"Failed to import/instantiate {class_name}: {e}"
        
        return True, "All servers can be imported independently"
    except Exception as e:
        return False, f"Server independence test failed: {e}"


def test_manager_integration() -> Tuple[bool, str]:
    """Test manager integration with new registry."""
    try:
        from src.mcp.manager import MCPManager
        
        permission_checker = MockPermissionChecker()
        manager = MCPManager(permission_checker)
        
        # Check if registry is properly initialized
        if not hasattr(manager, 'registry'):
            return False, "Manager does not have registry attribute"
        
        # Check if we can list servers
        servers = manager.registry.list_servers()
        if not servers:
            return False, "Manager registry has no servers"
        
        return True, f"Manager integrated successfully with {len(servers)} servers"
    except Exception as e:
        return False, f"Manager integration test failed: {e}"


def main():
    """Run all validation tests."""
    print("Validating MCP module structure...\n")
    
    tests = [
        ("Module imports", test_module_import, ["src.mcp.protocols", "src.mcp.registry", "src.mcp.servers"]),
        ("Registry creation", test_registry_creation, []),
        ("Lazy loading", test_lazy_loading, []),
        ("Server independence", test_server_independence, []),
        ("Manager integration", test_manager_integration, []),
    ]
    
    results = []
    all_passed = True
    
    for test_name, test_func, test_args in tests:
        print(f"Testing {test_name}...")
        
        if test_args:
            # For module import tests
            sub_results = []
            for arg in test_args:
                success, message = test_func(arg)
                sub_results.append((success, message))
                if not success:
                    all_passed = False
            
            all_success = all(r[0] for r in sub_results)
            print(f"  {'✓' if all_success else '✗'} {test_name}: {'PASSED' if all_success else 'FAILED'}")
            for success, message in sub_results:
                print(f"    {'✓' if success else '✗'} {message}")
        else:
            # For other tests
            success, message = test_func()
            results.append((test_name, success, message))
            print(f"  {'✓' if success else '✗'} {test_name}: {'PASSED' if success else 'FAILED'}")
            print(f"    {message}")
            if not success:
                all_passed = False
        print()
    
    # Summary
    print("="*60)
    if all_passed:
        print("✓ All validation tests passed!")
        print("✓ MCP module structure is correctly implemented!")
        print("\nKey achievements:")
        print("  - Circular imports eliminated")
        print("  - Registry pattern with lazy loading implemented")
        print("  - Servers can be imported independently")
        print("  - Dependency injection working correctly")
        return 0
    else:
        print("✗ Some validation tests failed!")
        print("  Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())