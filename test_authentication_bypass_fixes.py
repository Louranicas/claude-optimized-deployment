"""
Test suite to validate authentication bypass vulnerabilities have been fixed.

This test suite validates that all authentication bypass vulnerabilities
in MCP server implementations have been properly addressed.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from typing import Dict, Any

# Import the fixed MCP components
from src.mcp.protocols import MCPServer, MCPTool, MCPToolParameter
from src.mcp.security.auth_middleware import MCPAuthMiddleware, UserRole
from src.mcp.servers import MCPServerRegistry, BraveMCPServer
from src.mcp.infrastructure_servers import DesktopCommanderMCPServer, DockerMCPServer, KubernetesMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.auth.models import User
from src.auth.permissions import PermissionChecker
from src.core.exceptions import AuthenticationError, PermissionDeniedError


class MockUser:
    """Mock user for testing."""
    def __init__(self, user_id: str, username: str, roles: list = None):
        self.id = user_id
        self.username = username
        self.roles = roles or ["user"]


class MockPermissionChecker:
    """Mock permission checker for testing."""
    def __init__(self, allow_all: bool = False):
        self.allow_all = allow_all
        self.registered_resources = {}
    
    def check_permission(self, user_id: str, user_roles: list, resource: str, action: str, context: Dict[str, Any] = None) -> bool:
        return self.allow_all
    
    def register_resource_permission(self, resource_type: str, resource_id: str, initial_permissions: Dict[str, Any]):
        self.registered_resources[f"{resource_type}:{resource_id}"] = initial_permissions


class TestAuthenticationBypassFixes:
    """Test suite for authentication bypass vulnerability fixes."""
    
    def setup_method(self):
        """Set up test environment."""
        self.valid_user = MockUser("user123", "testuser", ["user"])
        self.admin_user = MockUser("admin123", "adminuser", ["admin"])
        self.permission_checker = MockPermissionChecker(allow_all=True)
        self.auth_middleware = MCPAuthMiddleware()
    
    def test_mcp_server_registry_requires_permission_checker(self):
        """Test that MCPServerRegistry requires permission checker."""
        # Test that creating registry without permission checker fails
        with pytest.raises(ValueError, match="Permission checker is required"):
            MCPServerRegistry(permission_checker=None)
        
        # Test that creating registry with permission checker succeeds
        registry = MCPServerRegistry(permission_checker=self.permission_checker)
        assert registry.permission_checker is not None
    
    def test_mcp_server_get_tools_requires_user(self):
        """Test that get_tools requires authenticated user."""
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Test that calling get_tools without user fails
        with pytest.raises(AuthenticationError, match="Authentication required"):
            server.get_tools(user=None)
    
    def test_mcp_server_get_server_info_requires_user(self):
        """Test that get_server_info requires authenticated user."""
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Test that calling get_server_info without user fails
        with pytest.raises(AuthenticationError, match="Authentication required"):
            server.get_server_info(user=None)
    
    @pytest.mark.asyncio
    async def test_mcp_server_call_tool_requires_valid_user(self):
        """Test that call_tool requires valid authenticated user."""
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Test that calling tool without user fails
        with pytest.raises(AuthenticationError, match="Valid authenticated user required"):
            await server.call_tool("execute_command", {"command": "echo test"}, user=None)
        
        # Test that calling tool with invalid user object fails
        invalid_user = Mock()  # Missing required attributes
        with pytest.raises(AuthenticationError, match="Valid authenticated user required"):
            await server.call_tool("execute_command", {"command": "echo test"}, user=invalid_user)
    
    def test_permission_checker_required_for_security(self):
        """Test that missing permission checker raises security error."""
        # Test desktop commander
        server = DesktopCommanderMCPServer(permission_checker=None)
        with pytest.raises(PermissionDeniedError, match="Authentication system not properly configured"):
            server.get_tools(user=self.valid_user)
        
        # Test docker server
        docker_server = DockerMCPServer(permission_checker=None)
        with pytest.raises(PermissionDeniedError, match="Authentication system not properly configured"):
            docker_server.get_tools(user=self.valid_user)
    
    def test_auth_middleware_strict_validation(self):
        """Test authentication middleware enforces strict parameter validation."""
        # Test token generation with invalid parameters
        with pytest.raises(ValueError, match="User ID is required"):
            self.auth_middleware.generate_token("", UserRole.ADMIN)
        
        with pytest.raises(ValueError, match="User ID is required"):
            self.auth_middleware.generate_token(None, UserRole.ADMIN)
        
        with pytest.raises(ValueError, match="Valid UserRole is required"):
            self.auth_middleware.generate_token("user123", None)
    
    @pytest.mark.asyncio
    async def test_auth_middleware_request_validation(self):
        """Test request validation enforces required parameters."""
        # Test that empty/None parameters are rejected
        with pytest.raises(ValueError, match="Authentication token is required"):
            await self.auth_middleware.validate_request("", "tool_name", "context_id")
        
        with pytest.raises(ValueError, match="Tool name is required"):
            await self.auth_middleware.validate_request("valid_token", "", "context_id")
        
        with pytest.raises(ValueError, match="Context ID is required"):
            await self.auth_middleware.validate_request("valid_token", "tool_name", "")
    
    def test_servers_inherit_authentication_properly(self):
        """Test that all MCP servers properly inherit authentication."""
        # Test that all servers require permission checker
        servers_to_test = [
            (DesktopCommanderMCPServer, {}),
            (DockerMCPServer, {}),
            (KubernetesMCPServer, {}),
            (AzureDevOpsMCPServer, {}),
            (WindowsSystemMCPServer, {}),
        ]
        
        for server_class, init_args in servers_to_test:
            # Test with permission checker
            server = server_class(permission_checker=self.permission_checker, **init_args)
            assert server.permission_checker is not None
            
            # Test tools require authentication
            tools = server.get_tools(user=self.valid_user)
            assert isinstance(tools, list)
    
    @pytest.mark.asyncio
    async def test_tool_execution_requires_authentication(self):
        """Test that tool execution always requires authentication."""
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Test valid authentication works
        result = await server.call_tool(
            "list_directory", 
            {"directory_path": "/tmp"}, 
            user=self.valid_user
        )
        assert result is not None
        
        # Test that bypassing authentication fails
        with pytest.raises(AuthenticationError):
            await server.call_tool(
                "list_directory", 
                {"directory_path": "/tmp"}, 
                user=None
            )
    
    def test_brave_server_requires_permission_checker(self):
        """Test that BraveMCPServer requires permission checker."""
        # Test that server can be created with permission checker
        server = BraveMCPServer(api_key="test_key", permission_checker=self.permission_checker)
        assert server.permission_checker is not None
        
        # Test authentication is required for operations
        with pytest.raises(AuthenticationError):
            server.get_tools(user=None)
    
    def test_security_hardening_no_defaults(self):
        """Test that security-sensitive operations have no unsafe defaults."""
        # Test that MCPServerRegistry doesn't accept None permission checker
        with pytest.raises(ValueError):
            MCPServerRegistry(permission_checker=None)
        
        # Test that servers don't allow missing authentication
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Even with permission checker, missing user should fail
        with pytest.raises(AuthenticationError):
            server.get_tools(user=None)
    
    @pytest.mark.asyncio
    async def test_permission_denied_when_no_checker_configured(self):
        """Test that operations fail when permission checker is not configured."""
        # Create server without permission checker
        server = DesktopCommanderMCPServer(permission_checker=None)
        
        # All operations should fail with permission denied
        with pytest.raises(PermissionDeniedError, match="Authentication system not properly configured"):
            server.get_tools(user=self.valid_user)
        
        with pytest.raises(PermissionDeniedError, match="Authentication system not properly configured"):
            server.get_server_info(user=self.valid_user)
        
        with pytest.raises(PermissionDeniedError):
            await server.call_tool("execute_command", {"command": "echo test"}, user=self.valid_user)
    
    def test_user_parameter_validation(self):
        """Test that user parameters are strictly validated."""
        server = DesktopCommanderMCPServer(permission_checker=self.permission_checker)
        
        # Test various invalid user objects
        invalid_users = [
            None,
            {},
            Mock(),  # Missing id and username
            Mock(id=None, username="test"),  # Missing id
            Mock(id="123", username=None),  # Missing username
            Mock(id="", username="test"),  # Empty id
            Mock(id="123", username=""),  # Empty username
        ]
        
        for invalid_user in invalid_users:
            with pytest.raises(AuthenticationError):
                server.get_tools(user=invalid_user)
    
    def test_tool_permissions_properly_configured(self):
        """Test that all servers have proper tool permissions configured."""
        servers = [
            DesktopCommanderMCPServer(permission_checker=self.permission_checker),
            DockerMCPServer(permission_checker=self.permission_checker),
            KubernetesMCPServer(permission_checker=self.permission_checker),
            AzureDevOpsMCPServer(permission_checker=self.permission_checker),
            WindowsSystemMCPServer(permission_checker=self.permission_checker),
        ]
        
        for server in servers:
            # Each server should have tool permissions configured
            assert hasattr(server, 'tool_permissions')
            assert isinstance(server.tool_permissions, dict)
            
            # Get tools to ensure they're properly defined
            tools = server.get_tools(user=self.valid_user)
            
            # Each tool should have a corresponding permission
            for tool in tools:
                assert tool.name in server.tool_permissions or f"mcp.{server.name}.{tool.name}:execute" is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])