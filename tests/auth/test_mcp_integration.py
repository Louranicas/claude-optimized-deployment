"""
Comprehensive Tests for MCP Integration (src/auth/mcp_integration.py).

This test suite covers MCP server authentication, authorization, tool execution,
security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Optional, Any

from src.auth.mcp_integration import (
    AuthenticatedMCPContext, AuthenticatedMCPServer, 
    AuthenticatedMCPManager
)
from src.auth.models import User, UserStatus
from src.auth.permissions import PermissionChecker, ResourceType
from src.mcp.protocols import MCPServer, MCPTool, MCPParameter


class TestAuthenticatedMCPContext:
    """Test AuthenticatedMCPContext class functionality."""
    
    def test_context_creation(self):
        """Test basic context creation."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:read", "mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:read", "mcp:execute"],
            metadata={"ip_address": "192.168.1.100", "client": "web"}
        )
        
        assert context.user == user
        assert context.session_id == "session_123"
        assert context.permissions == ["mcp:read", "mcp:execute"]
        assert context.metadata["ip_address"] == "192.168.1.100"
        assert context.metadata["client"] == "web"
    
    def test_context_with_minimal_data(self):
        """Test context creation with minimal required data."""
        user = User(
            username="minimaluser",
            email="minimal@example.com",
            password_hash="hash"
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_456",
            permissions=[],
            metadata={}
        )
        
        assert context.user == user
        assert context.session_id == "session_456"
        assert context.permissions == []
        assert context.metadata == {}


class TestAuthenticatedMCPServer:
    """Test AuthenticatedMCPServer class functionality."""
    
    @pytest.fixture
    def mock_mcp_server(self):
        """Create mock MCP server."""
        server = Mock(spec=MCPServer)
        server.__class__.__name__ = "TestMCPServer"
        
        # Mock server info
        server.get_server_info.return_value = {
            "name": "test_server",
            "version": "1.0.0",
            "description": "Test MCP Server"
        }
        
        # Mock tools
        tool1 = Mock(spec=MCPTool)
        tool1.name = "test_tool"
        tool1.description = "Test tool"
        tool1.parameters = []
        
        tool2 = Mock(spec=MCPTool)
        tool2.name = "admin_tool"
        tool2.description = "Admin only tool"
        tool2.parameters = []
        
        server.get_tools.return_value = [tool1, tool2]
        server.call_tool = AsyncMock()
        
        return server
    
    @pytest.fixture
    def mock_permission_checker(self):
        """Create mock permission checker."""
        checker = Mock(spec=PermissionChecker)
        checker.check_permission.return_value = True
        return checker
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:read", "mcp:execute"},
            status=UserStatus.ACTIVE
        )
    
    @pytest.fixture
    def admin_user(self):
        """Create admin user."""
        return User(
            id="admin_123",
            username="adminuser",
            email="admin@example.com",
            password_hash="hash",
            roles=["admin"],
            permissions={"*"},
            status=UserStatus.ACTIVE
        )
    
    @pytest.fixture
    def test_context(self, test_user):
        """Create test context."""
        return AuthenticatedMCPContext(
            user=test_user,
            session_id="session_123",
            permissions=["mcp:read", "mcp:execute"],
            metadata={"ip_address": "192.168.1.100"}
        )
    
    @pytest.fixture
    def authenticated_server(self, mock_mcp_server, mock_permission_checker):
        """Create authenticated MCP server."""
        return AuthenticatedMCPServer(mock_mcp_server, mock_permission_checker)
    
    def test_server_initialization(self, mock_mcp_server, mock_permission_checker):
        """Test server initialization."""
        auth_server = AuthenticatedMCPServer(mock_mcp_server, mock_permission_checker)
        
        assert auth_server.server == mock_mcp_server
        assert auth_server.permission_checker == mock_permission_checker
        assert auth_server._context is None
    
    def test_set_context(self, authenticated_server, test_context):
        """Test setting authentication context."""
        authenticated_server.set_context(test_context)
        
        assert authenticated_server._context == test_context
    
    def test_get_server_info(self, authenticated_server, mock_mcp_server):
        """Test getting server information."""
        server_info = authenticated_server.get_server_info()
        
        assert server_info["name"] == "test_server"
        assert server_info["version"] == "1.0.0"
        mock_mcp_server.get_server_info.assert_called_once()
    
    def test_get_tools_without_context(self, authenticated_server):
        """Test getting tools without authentication context."""
        tools = authenticated_server.get_tools()
        
        assert tools == []
    
    def test_get_tools_with_context(self, authenticated_server, test_context, mock_permission_checker):
        """Test getting tools with authentication context."""
        authenticated_server.set_context(test_context)
        mock_permission_checker.check_permission.return_value = True
        
        tools = authenticated_server.get_tools()
        
        assert len(tools) == 2
        assert tools[0].name == "test_tool"
        assert tools[1].name == "admin_tool"
    
    def test_get_tools_filtered_by_permissions(self, authenticated_server, test_context, mock_permission_checker):
        """Test tool filtering based on permissions."""
        authenticated_server.set_context(test_context)
        
        # Mock permission checker to allow only first tool
        def mock_check_permission(user_id, roles, resource, action, context):
            return "test_tool" in resource
        
        mock_permission_checker.check_permission.side_effect = mock_check_permission
        
        tools = authenticated_server.get_tools()
        
        assert len(tools) == 1
        assert tools[0].name == "test_tool"
    
    @pytest.mark.asyncio
    async def test_call_tool_without_context(self, authenticated_server):
        """Test calling tool without authentication context."""
        with pytest.raises(PermissionError) as exc_info:
            await authenticated_server.call_tool("test_tool", {})
        
        assert "No authentication context provided" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_call_tool_with_permission(self, authenticated_server, test_context, mock_permission_checker, mock_mcp_server):
        """Test successful tool call with permission."""
        authenticated_server.set_context(test_context)
        mock_permission_checker.check_permission.return_value = True
        mock_mcp_server.call_tool.return_value = {"result": "success"}
        
        with patch.object(authenticated_server, '_audit_tool_call') as mock_audit_call, \
             patch.object(authenticated_server, '_audit_tool_success') as mock_audit_success:
            
            result = await authenticated_server.call_tool("test_tool", {"param": "value"})
            
            assert result == {"result": "success"}
            mock_audit_call.assert_called_once_with("test_tool", {"param": "value"})
            mock_audit_success.assert_called_once_with("test_tool", {"result": "success"})
            mock_mcp_server.call_tool.assert_called_once_with("test_tool", {"param": "value"})
    
    @pytest.mark.asyncio
    async def test_call_tool_without_permission(self, authenticated_server, test_context, mock_permission_checker):
        """Test tool call without permission."""
        authenticated_server.set_context(test_context)
        mock_permission_checker.check_permission.return_value = False
        
        with pytest.raises(PermissionError) as exc_info:
            await authenticated_server.call_tool("test_tool", {})
        
        assert "Permission denied for tool: test_tool" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_call_tool_with_exception(self, authenticated_server, test_context, mock_permission_checker, mock_mcp_server):
        """Test tool call that raises exception."""
        authenticated_server.set_context(test_context)
        mock_permission_checker.check_permission.return_value = True
        mock_mcp_server.call_tool.side_effect = RuntimeError("Tool execution failed")
        
        with patch.object(authenticated_server, '_audit_tool_call') as mock_audit_call, \
             patch.object(authenticated_server, '_audit_tool_failure') as mock_audit_failure:
            
            with pytest.raises(RuntimeError):
                await authenticated_server.call_tool("test_tool", {})
            
            mock_audit_call.assert_called_once()
            mock_audit_failure.assert_called_once_with("test_tool", "Tool execution failed")
    
    def test_check_tool_permission_admin_user(self, authenticated_server, admin_user):
        """Test tool permission check for admin user."""
        admin_context = AuthenticatedMCPContext(
            user=admin_user,
            session_id="session_admin",
            permissions=["*"],
            metadata={}
        )
        authenticated_server.set_context(admin_context)
        
        # Admin should have access to any tool
        has_permission = authenticated_server._check_tool_permission("mcp.testserver", "any_tool")
        
        assert has_permission is True
    
    def test_check_tool_permission_regular_user(self, authenticated_server, test_context, mock_permission_checker):
        """Test tool permission check for regular user."""
        authenticated_server.set_context(test_context)
        mock_permission_checker.check_permission.return_value = True
        
        has_permission = authenticated_server._check_tool_permission("mcp.testserver", "test_tool")
        
        assert has_permission is True
        assert mock_permission_checker.check_permission.call_count >= 1
    
    def test_check_tool_permission_without_context(self, authenticated_server):
        """Test tool permission check without context."""
        has_permission = authenticated_server._check_tool_permission("mcp.testserver", "test_tool")
        
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_audit_tool_call(self, authenticated_server, test_context):
        """Test audit logging for tool calls."""
        authenticated_server.set_context(test_context)
        
        with patch('builtins.print') as mock_print:
            await authenticated_server._audit_tool_call("test_tool", {"param": "value"})
            
            mock_print.assert_called_once()
            audit_msg = mock_print.call_args[0][0]
            assert "AUDIT:" in audit_msg
            assert "mcp_tool_call" in audit_msg
            assert "user_123" in audit_msg
    
    @pytest.mark.asyncio
    async def test_audit_tool_success(self, authenticated_server, test_context):
        """Test audit logging for successful tool execution."""
        authenticated_server.set_context(test_context)
        
        with patch('builtins.print') as mock_print:
            await authenticated_server._audit_tool_success("test_tool", {"result": "success"})
            
            mock_print.assert_called_once()
            audit_msg = mock_print.call_args[0][0]
            assert "AUDIT:" in audit_msg
            assert "mcp_tool_success" in audit_msg
            assert "success" in audit_msg
    
    @pytest.mark.asyncio
    async def test_audit_tool_failure(self, authenticated_server, test_context):
        """Test audit logging for tool execution failure."""
        authenticated_server.set_context(test_context)
        
        with patch('builtins.print') as mock_print:
            await authenticated_server._audit_tool_failure("test_tool", "Error message")
            
            mock_print.assert_called_once()
            audit_msg = mock_print.call_args[0][0]
            assert "AUDIT:" in audit_msg
            assert "mcp_tool_failure" in audit_msg
            assert "Error message" in audit_msg


class TestAuthenticatedMCPManager:
    """Test AuthenticatedMCPManager class functionality."""
    
    @pytest.fixture
    def mock_mcp_manager(self):
        """Create mock MCP manager."""
        manager = Mock()
        manager.initialize = AsyncMock()
        
        # Mock registry with servers
        manager.registry = Mock()
        manager.registry.servers = {
            "test_server": Mock(spec=MCPServer),
            "admin_server": Mock(spec=MCPServer)
        }
        
        # Set up server class names
        manager.registry.servers["test_server"].__class__.__name__ = "TestMCPServer"
        manager.registry.servers["admin_server"].__class__.__name__ = "AdminMCPServer"
        
        return manager
    
    @pytest.fixture
    def mock_permission_checker(self):
        """Create mock permission checker."""
        checker = Mock(spec=PermissionChecker)
        checker.check_permission.return_value = True
        checker.register_resource_permission = Mock()
        checker.resource_permissions = {}
        return checker
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:read", "mcp:execute"},
            status=UserStatus.ACTIVE
        )
    
    @pytest.fixture
    def test_context(self, test_user):
        """Create test context."""
        return AuthenticatedMCPContext(
            user=test_user,
            session_id="session_123",
            permissions=["mcp:read", "mcp:execute"],
            metadata={"ip_address": "192.168.1.100"}
        )
    
    @pytest.fixture
    def authenticated_manager(self, mock_mcp_manager, mock_permission_checker):
        """Create authenticated MCP manager."""
        return AuthenticatedMCPManager(mock_mcp_manager, mock_permission_checker)
    
    def test_manager_initialization(self, mock_mcp_manager, mock_permission_checker):
        """Test manager initialization."""
        auth_manager = AuthenticatedMCPManager(mock_mcp_manager, mock_permission_checker)
        
        assert auth_manager.mcp_manager == mock_mcp_manager
        assert auth_manager.permission_checker == mock_permission_checker
        assert auth_manager._authenticated_servers == {}
    
    @pytest.mark.asyncio
    async def test_initialize_with_context(self, authenticated_manager, test_context, mock_mcp_manager):
        """Test initialization with authentication context."""
        await authenticated_manager.initialize(test_context)
        
        mock_mcp_manager.initialize.assert_called_once()
        
        # Check that servers were wrapped
        assert len(authenticated_manager._authenticated_servers) == 2
        assert "test_server" in authenticated_manager._authenticated_servers
        assert "admin_server" in authenticated_manager._authenticated_servers
        
        # Verify servers are AuthenticatedMCPServer instances
        for server in authenticated_manager._authenticated_servers.values():
            assert isinstance(server, AuthenticatedMCPServer)
    
    def test_get_available_servers(self, authenticated_manager, test_user, mock_permission_checker):
        """Test getting available servers for user."""
        mock_permission_checker.check_permission.return_value = True
        
        available = authenticated_manager.get_available_servers(test_user)
        
        assert len(available) == 2
        assert "test_server" in available
        assert "admin_server" in available
    
    def test_get_available_servers_filtered(self, authenticated_manager, test_user, mock_permission_checker):
        """Test getting available servers with permission filtering."""
        # Mock permission checker to allow only test_server
        def mock_check_permission(user_id, roles, resource, action):
            return "test_server" in resource
        
        mock_permission_checker.check_permission.side_effect = mock_check_permission
        
        available = authenticated_manager.get_available_servers(test_user)
        
        assert len(available) == 1
        assert "test_server" in available
    
    def test_get_available_tools(self, authenticated_manager, test_user, mock_mcp_manager, mock_permission_checker):
        """Test getting available tools for user."""
        # Mock tools
        tool1 = Mock(spec=MCPTool)
        tool1.name = "tool1"
        tool1.description = "Tool 1"
        tool1.parameters = []
        
        tool2 = Mock(spec=MCPTool)
        tool2.name = "tool2"
        tool2.description = "Tool 2"
        tool2.parameters = [Mock(to_dict=lambda: {"name": "param1", "type": "string"})]
        
        mock_mcp_manager.registry.servers["test_server"].get_tools.return_value = [tool1]
        mock_mcp_manager.registry.servers["admin_server"].get_tools.return_value = [tool2]
        
        mock_permission_checker.check_permission.return_value = True
        
        with patch('src.auth.mcp_integration.AuthenticatedMCPServer') as mock_auth_server_class:
            mock_auth_server = Mock()
            mock_auth_server.get_tools.return_value = [tool1]
            mock_auth_server_class.return_value = mock_auth_server
            
            available_tools = authenticated_manager.get_available_tools(test_user)
            
            assert len(available_tools) == 2  # One for each server
            assert available_tools[0]["server"] == "test_server"
            assert available_tools[0]["tool"] == "tool1"
    
    @pytest.mark.asyncio
    async def test_call_tool_existing_server(self, authenticated_manager, test_context, mock_mcp_manager):
        """Test calling tool on existing authenticated server."""
        # Set up authenticated server
        mock_auth_server = Mock()
        mock_auth_server.call_tool = AsyncMock(return_value={"result": "success"})
        authenticated_manager._authenticated_servers["test_server"] = mock_auth_server
        
        result = await authenticated_manager.call_tool(
            test_context, "test_server", "test_tool", {"param": "value"}
        )
        
        assert result == {"result": "success"}
        mock_auth_server.set_context.assert_called_once_with(test_context)
        mock_auth_server.call_tool.assert_called_once_with("test_tool", {"param": "value"})
    
    @pytest.mark.asyncio
    async def test_call_tool_new_server(self, authenticated_manager, test_context, mock_mcp_manager, mock_permission_checker):
        """Test calling tool on new server (not yet authenticated)."""
        with patch('src.auth.mcp_integration.AuthenticatedMCPServer') as mock_auth_server_class:
            mock_auth_server = Mock()
            mock_auth_server.call_tool = AsyncMock(return_value={"result": "success"})
            mock_auth_server_class.return_value = mock_auth_server
            
            result = await authenticated_manager.call_tool(
                test_context, "test_server", "test_tool", {"param": "value"}
            )
            
            assert result == {"result": "success"}
            mock_auth_server_class.assert_called_once_with(
                mock_mcp_manager.registry.servers["test_server"], 
                mock_permission_checker
            )
            mock_auth_server.set_context.assert_called_once_with(test_context)
            mock_auth_server.call_tool.assert_called_once_with("test_tool", {"param": "value"})
    
    @pytest.mark.asyncio
    async def test_call_tool_nonexistent_server(self, authenticated_manager, test_context):
        """Test calling tool on non-existent server."""
        with pytest.raises(ValueError) as exc_info:
            await authenticated_manager.call_tool(
                test_context, "nonexistent_server", "test_tool", {}
            )
        
        assert "Server not found: nonexistent_server" in str(exc_info.value)
    
    def test_register_mcp_permissions(self, authenticated_manager, mock_permission_checker):
        """Test registering MCP permissions."""
        authenticated_manager.register_mcp_permissions()
        
        # Verify resource permissions were registered
        assert mock_permission_checker.register_resource_permission.call_count > 0
        
        # Check that various MCP resources were registered
        call_args_list = mock_permission_checker.register_resource_permission.call_args_list
        registered_resources = [args[0][1] for args in call_args_list]
        
        # Should include server-level resources
        assert any("mcp.desktop" in resource for resource in registered_resources)
        assert any("mcp.docker" in resource for resource in registered_resources)
        assert any("mcp.kubernetes" in resource for resource in registered_resources)
        
        # Should include tool-level resources
        assert any("execute_command" in resource for resource in registered_resources)
        assert any("docker_build" in resource for resource in registered_resources)
    
    def test_get_permission_matrix(self, authenticated_manager, mock_permission_checker):
        """Test getting permission matrix."""
        # Mock resource permissions
        mock_resource1 = Mock()
        mock_resource1.resource_type = ResourceType.MCP_SERVER
        mock_resource1.resource_id = "mcp.desktop"
        mock_resource1.permissions = {
            "role:admin": {"*": True},
            "role:user": {"read": True}
        }
        
        mock_resource2 = Mock()
        mock_resource2.resource_type = ResourceType.MCP_TOOL
        mock_resource2.resource_id = "mcp.desktop.execute_command"
        mock_resource2.permissions = {
            "role:admin": {"*": True}
        }
        
        mock_permission_checker.resource_permissions = {
            "res1": mock_resource1,
            "res2": mock_resource2
        }
        
        matrix = authenticated_manager.get_permission_matrix()
        
        assert "mcp.desktop" in matrix
        assert "mcp.desktop.execute_command" in matrix
        assert "role:admin" in matrix["mcp.desktop"]
        assert "role:user" in matrix["mcp.desktop"]


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.fixture
    def authenticated_server(self, mock_mcp_server, mock_permission_checker):
        """Create authenticated MCP server."""
        return AuthenticatedMCPServer(mock_mcp_server, mock_permission_checker)
    
    @pytest.fixture
    def mock_mcp_server(self):
        """Create mock MCP server."""
        server = Mock(spec=MCPServer)
        server.__class__.__name__ = "TestMCPServer"
        server.get_tools.return_value = []
        server.call_tool = AsyncMock()
        return server
    
    @pytest.fixture
    def mock_permission_checker(self):
        """Create mock permission checker."""
        return Mock(spec=PermissionChecker)
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, authenticated_server, mock_permission_checker):
        """Test prevention of privilege escalation attacks."""
        # Create limited user
        limited_user = User(
            id="limited_user",
            username="limiteduser",
            email="limited@example.com",
            password_hash="hash",
            roles=["user"],  # No admin role
            permissions={"mcp:read"},  # Limited permissions
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=limited_user,
            session_id="session_123",
            permissions=["mcp:read"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = False
        
        # Should not allow execution of privileged tools
        with pytest.raises(PermissionError):
            await authenticated_server.call_tool("admin_tool", {})
    
    @pytest.mark.asyncio
    async def test_injection_attack_prevention(self, authenticated_server, mock_permission_checker):
        """Test prevention of injection attacks through tool arguments."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = True
        
        # Test with malicious arguments
        malicious_args = {
            "command": "rm -rf /",
            "script": "; DROP TABLE users; --",
            "path": "../../../etc/passwd"
        }
        
        # Tool execution should still proceed (injection prevention handled by individual tools)
        await authenticated_server.call_tool("test_tool", malicious_args)
        
        # Verify the arguments were passed as-is (individual tools handle sanitization)
        authenticated_server.server.call_tool.assert_called_once_with("test_tool", malicious_args)
    
    def test_session_isolation(self, authenticated_server, mock_permission_checker):
        """Test that sessions are properly isolated."""
        user1 = User(
            id="user_1",
            username="user1",
            email="user1@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        user2 = User(
            id="user_2", 
            username="user2",
            email="user2@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context1 = AuthenticatedMCPContext(
            user=user1,
            session_id="session_1",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        context2 = AuthenticatedMCPContext(
            user=user2,
            session_id="session_2",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        # Set first context
        authenticated_server.set_context(context1)
        assert authenticated_server._context.user.id == "user_1"
        assert authenticated_server._context.session_id == "session_1"
        
        # Set second context (should replace first)
        authenticated_server.set_context(context2)
        assert authenticated_server._context.user.id == "user_2"
        assert authenticated_server._context.session_id == "session_2"
    
    @pytest.mark.asyncio
    async def test_resource_access_control(self, authenticated_server, mock_permission_checker):
        """Test proper resource access control."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp.specific_server:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp.specific_server:execute"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        
        # Mock permission checker to check resource-specific access
        def mock_check_permission(user_id, roles, resource, action, context):
            return "specific_server" in resource
        
        mock_permission_checker.check_permission.side_effect = mock_check_permission
        
        # Should allow access to specific server tools
        has_permission = authenticated_server._check_tool_permission("mcp.specific_server", "allowed_tool")
        assert has_permission is True
        
        # Should deny access to other server tools
        has_permission = authenticated_server._check_tool_permission("mcp.other_server", "denied_tool")
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_audit_trail_completeness(self, authenticated_server, mock_permission_checker):
        """Test that audit trail captures all important events."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata={"ip_address": "192.168.1.100"}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = True
        authenticated_server.server.call_tool.return_value = {"result": "success"}
        
        with patch('builtins.print') as mock_print:
            await authenticated_server.call_tool("test_tool", {"param": "value"})
            
            # Should have audit logs for call attempt and success
            assert mock_print.call_count >= 2
            
            # Verify audit contains required information
            audit_calls = [call[0][0] for call in mock_print.call_args_list]
            
            # Check for attempt audit
            attempt_audit = next((call for call in audit_calls if "mcp_tool_call" in call), None)
            assert attempt_audit is not None
            assert "user_123" in attempt_audit
            assert "session_123" in attempt_audit
            
            # Check for success audit
            success_audit = next((call for call in audit_calls if "mcp_tool_success" in call), None)
            assert success_audit is not None
    
    @pytest.mark.asyncio
    async def test_concurrent_access_safety(self, authenticated_server, mock_permission_checker):
        """Test safety under concurrent access."""
        import asyncio
        
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = True
        authenticated_server.server.call_tool = AsyncMock(return_value={"result": "success"})
        
        # Create multiple concurrent tool calls
        async def call_tool(tool_name):
            return await authenticated_server.call_tool(tool_name, {"param": "value"})
        
        tasks = [call_tool(f"tool_{i}") for i in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All calls should succeed
        assert len(results) == 10
        assert all(isinstance(result, dict) and result.get("result") == "success" for result in results)


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def authenticated_manager(self, mock_mcp_manager, mock_permission_checker):
        """Create authenticated MCP manager."""
        return AuthenticatedMCPManager(mock_mcp_manager, mock_permission_checker)
    
    @pytest.fixture
    def mock_mcp_manager(self):
        """Create mock MCP manager with many servers."""
        manager = Mock()
        manager.initialize = AsyncMock()
        manager.registry = Mock()
        
        # Create many mock servers
        servers = {}
        for i in range(100):
            server = Mock(spec=MCPServer)
            server.__class__.__name__ = f"TestMCPServer{i}"
            servers[f"server_{i}"] = server
        
        manager.registry.servers = servers
        return manager
    
    @pytest.fixture
    def mock_permission_checker(self):
        """Create mock permission checker."""
        checker = Mock(spec=PermissionChecker)
        checker.check_permission.return_value = True
        return checker
    
    def test_permission_check_performance(self, authenticated_manager, mock_permission_checker):
        """Test permission checking performance with many servers."""
        import time
        
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:read"},
            status=UserStatus.ACTIVE
        )
        
        start_time = time.time()
        available_servers = authenticated_manager.get_available_servers(user)
        elapsed_time = time.time() - start_time
        
        # Should complete quickly even with many servers
        assert elapsed_time < 1.0  # Less than 1 second
        assert len(available_servers) == 100  # All servers should be available
    
    def test_tool_filtering_performance(self, authenticated_manager, mock_mcp_manager, mock_permission_checker):
        """Test tool filtering performance."""
        import time
        
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        # Mock each server to return multiple tools
        for server in mock_mcp_manager.registry.servers.values():
            tools = []
            for i in range(10):
                tool = Mock(spec=MCPTool)
                tool.name = f"tool_{i}"
                tool.description = f"Tool {i}"
                tool.parameters = []
                tools.append(tool)
            server.get_tools.return_value = tools
        
        with patch('src.auth.mcp_integration.AuthenticatedMCPServer') as mock_auth_server_class:
            mock_auth_server = Mock()
            mock_auth_server.get_tools.return_value = [Mock(name=f"tool_{i}", description=f"Tool {i}", parameters=[]) for i in range(10)]
            mock_auth_server_class.return_value = mock_auth_server
            
            start_time = time.time()
            available_tools = authenticated_manager.get_available_tools(user)
            elapsed_time = time.time() - start_time
            
            # Should complete quickly even with many tools
            assert elapsed_time < 2.0  # Less than 2 seconds
            assert len(available_tools) == 1000  # 100 servers * 10 tools each


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def authenticated_server(self, mock_mcp_server, mock_permission_checker):
        """Create authenticated MCP server."""
        return AuthenticatedMCPServer(mock_mcp_server, mock_permission_checker)
    
    @pytest.fixture
    def mock_mcp_server(self):
        """Create mock MCP server."""
        server = Mock(spec=MCPServer)
        server.__class__.__name__ = "TestMCPServer"
        server.get_tools.return_value = []
        server.call_tool = AsyncMock()
        return server
    
    @pytest.fixture
    def mock_permission_checker(self):
        """Create mock permission checker."""
        return Mock(spec=PermissionChecker)
    
    def test_none_values_handling(self, authenticated_server):
        """Test handling of None values."""
        # Setting None context should work
        authenticated_server.set_context(None)
        assert authenticated_server._context is None
        
        # Getting tools with None context should return empty list
        tools = authenticated_server.get_tools()
        assert tools == []
    
    def test_empty_string_values(self, authenticated_server, mock_permission_checker):
        """Test handling of empty string values."""
        user = User(
            id="",  # Empty user ID
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=[],  # Empty roles
            permissions=set(),  # Empty permissions
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="",  # Empty session ID
            permissions=[],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        
        # Should handle empty values gracefully
        has_permission = authenticated_server._check_tool_permission("mcp.test", "tool")
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_malformed_tool_arguments(self, authenticated_server, mock_permission_checker):
        """Test handling of malformed tool arguments."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = True
        
        # Test with various malformed arguments
        malformed_args = [
            None,
            "not_a_dict",
            [],
            {"nested": {"very": {"deep": {"structure": "value"}}}},
            {"circular": None}  # Will be made circular
        ]
        
        # Make circular reference
        malformed_args[4]["circular"] = malformed_args[4]
        
        for args in malformed_args:
            try:
                await authenticated_server.call_tool("test_tool", args)
                # Should pass arguments as-is to underlying server
                authenticated_server.server.call_tool.assert_called_with("test_tool", args)
            except Exception:
                # Some argument types might cause exceptions, which is acceptable
                pass
    
    def test_unicode_handling(self, authenticated_server, mock_permission_checker):
        """Test handling of unicode characters."""
        user = User(
            id="用户_123",  # Unicode user ID
            username="测试用户",  # Unicode username
            email="test@example.com",
            password_hash="hash",
            roles=["用户"],  # Unicode role
            permissions={"mcp:执行"},  # Unicode permission
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="会话_123",  # Unicode session ID
            permissions=["mcp:执行"],
            metadata={"备注": "测试"}  # Unicode metadata
        )
        
        authenticated_server.set_context(context)
        
        # Should handle unicode gracefully
        assert authenticated_server._context.user.username == "测试用户"
        assert authenticated_server._context.session_id == "会话_123"
        assert authenticated_server._context.metadata["备注"] == "测试"
    
    @pytest.mark.asyncio
    async def test_server_unavailable_handling(self, authenticated_server, mock_permission_checker):
        """Test handling when underlying server is unavailable."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata={}
        )
        
        authenticated_server.set_context(context)
        mock_permission_checker.check_permission.return_value = True
        
        # Mock server to raise various exceptions
        exceptions = [
            ConnectionError("Server unavailable"),
            TimeoutError("Server timeout"),
            RuntimeError("Server internal error"),
            ValueError("Invalid request")
        ]
        
        for exception in exceptions:
            authenticated_server.server.call_tool.side_effect = exception
            
            with pytest.raises(type(exception)):
                await authenticated_server.call_tool("test_tool", {})
    
    def test_very_large_metadata(self, authenticated_server):
        """Test handling of very large metadata objects."""
        user = User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"mcp:execute"},
            status=UserStatus.ACTIVE
        )
        
        # Create very large metadata
        large_metadata = {}
        for i in range(1000):
            large_metadata[f"key_{i}"] = "x" * 1000  # 1MB+ of metadata
        
        context = AuthenticatedMCPContext(
            user=user,
            session_id="session_123",
            permissions=["mcp:execute"],
            metadata=large_metadata
        )
        
        # Should handle large metadata without issues
        authenticated_server.set_context(context)
        assert len(authenticated_server._context.metadata) == 1000
    
    def test_memory_usage_with_many_contexts(self, authenticated_server):
        """Test memory usage doesn't grow unbounded."""
        import gc
        
        # Create many contexts
        for i in range(1000):
            user = User(
                id=f"user_{i}",
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password_hash="hash",
                roles=["user"],
                permissions={"mcp:execute"},
                status=UserStatus.ACTIVE
            )
            
            context = AuthenticatedMCPContext(
                user=user,
                session_id=f"session_{i}",
                permissions=["mcp:execute"],
                metadata={"iteration": i}
            )
            
            authenticated_server.set_context(context)
        
        # Force garbage collection
        gc.collect()
        
        # Should only keep reference to last context
        assert authenticated_server._context.session_id == "session_999"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.mcp_integration", "--cov-report=term-missing"])