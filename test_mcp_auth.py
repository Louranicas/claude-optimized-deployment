#!/usr/bin/env python3
"""
Test script to demonstrate MCP server authentication.
"""

import asyncio
import logging
from typing import Dict, Any

from src.mcp.protocols import MCPServer
from src.mcp.servers import BraveMCPServer, MCPServerRegistry
from src.auth.models import User
from src.auth.permissions import PermissionChecker, ResourceType
from src.auth.rbac import RBACManager
from src.core.exceptions import AuthenticationError, PermissionDeniedError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Test MCP server authentication."""
    # Initialize RBAC and permission checker
    rbac_manager = RBACManager()
    permission_checker = PermissionChecker(rbac_manager)
    
    # Create test users
    admin_user = User(
        id="admin-1",
        username="admin",
        email="admin@example.com",
        password_hash="",
        roles=["admin"]
    )
    
    regular_user = User(
        id="user-1",
        username="john",
        email="john@example.com",
        password_hash="",
        roles=["user"]
    )
    
    # Initialize MCP server registry with permission checker
    registry = MCPServerRegistry(permission_checker=permission_checker)
    
    # Get the Brave search server
    brave_server = registry.get("brave")
    
    print("\n=== Testing MCP Server Authentication ===\n")
    
    # Test 1: List tools without authentication (should work)
    print("1. Listing tools without authentication:")
    try:
        tools = brave_server.get_tools()
        print(f"   ✓ Success: Found {len(tools)} tools")
        for tool in tools:
            print(f"     - {tool.name}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 2: List tools with regular user
    print("\n2. Listing tools with regular user:")
    try:
        tools = brave_server.get_tools(user=regular_user)
        print(f"   ✓ Success: User can see {len(tools)} tools")
    except PermissionDeniedError as e:
        print(f"   ✗ Permission denied: {e}")
    
    # Test 3: Call tool without authentication (should fail)
    print("\n3. Calling tool without authentication:")
    try:
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "test"}
        )
        print(f"   ✗ Unexpected success: {result}")
    except AuthenticationError as e:
        print(f"   ✓ Expected error: {e}")
    
    # Test 4: Call tool with regular user (should fail by default)
    print("\n4. Calling tool with regular user:")
    try:
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "test"},
            user=regular_user
        )
        print(f"   ✗ Unexpected success: {result}")
    except PermissionDeniedError as e:
        print(f"   ✓ Expected permission denied: {e}")
    
    # Test 5: Grant permission to regular user
    print("\n5. Granting permission to regular user:")
    resource_perm = permission_checker.register_resource_permission(
        resource_type=ResourceType.MCP_SERVER,
        resource_id="brave-search",
        initial_permissions={
            f"user:{regular_user.id}": {
                "execute": True
            }
        }
    )
    print("   ✓ Permission granted")
    
    # Test 6: Call tool with regular user after permission grant
    print("\n6. Calling tool with regular user (after permission grant):")
    try:
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "Claude AI"},
            user=regular_user
        )
        print(f"   ✓ Success: Got {len(result.get('results', []))} search results")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 7: Call tool with admin user (should always work)
    print("\n7. Calling tool with admin user:")
    try:
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "MCP protocol"},
            user=admin_user
        )
        print(f"   ✓ Success: Admin got {len(result.get('results', []))} search results")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 8: Context-based permissions
    print("\n8. Testing context-based permissions:")
    # Add IP-based restriction
    resource_perm.grant_permission(
        f"user:{regular_user.id}",
        "execute",
        conditions={
            "allowed_ips": ["192.168.1.100", "10.0.0.1"]
        }
    )
    
    try:
        # Call with allowed IP
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "security"},
            user=regular_user,
            context={"client_ip": "192.168.1.100"}
        )
        print("   ✓ Success: Call allowed from authorized IP")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    try:
        # Call with disallowed IP
        result = await brave_server.call_tool(
            "brave_web_search",
            {"query": "security"},
            user=regular_user,
            context={"client_ip": "192.168.2.50"}
        )
        print("   ✗ Unexpected success from unauthorized IP")
    except PermissionDeniedError as e:
        print("   ✓ Expected: Permission denied from unauthorized IP")
    
    print("\n=== Authentication Test Complete ===\n")


if __name__ == "__main__":
    asyncio.run(main())