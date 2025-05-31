"""Integration tests for MCP Manager orchestration and tool discovery."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List

from src.mcp.manager import MCPManager, get_mcp_manager
from src.mcp.protocols import MCPServerInfo, MCPTool, MCPToolParameter, MCPToolCall, MCPToolResult
from src.mcp.servers import MCPServerRegistry


class TestMCPOrchestration:
    """Test MCP Manager orchestration capabilities."""

    @pytest.fixture
    async def mcp_manager(self):
        """Create a fresh MCP manager for testing."""
        manager = MCPManager()
        await manager.initialize()
        return manager

    @pytest.fixture
    def mock_server_info(self):
        """Mock server information for testing."""
        return {
            "test-server": MCPServerInfo(
                name="test-server",
                version="1.0.0",
                description="Test MCP server",
                capabilities=["tools", "resources"]
            ),
            "docker": MCPServerInfo(
                name="docker",
                version="1.0.0",
                description="Docker MCP server",
                capabilities=["tools"]
            ),
            "kubernetes": MCPServerInfo(
                name="kubernetes",
                version="1.0.0",
                description="Kubernetes MCP server",
                capabilities=["tools"]
            )
        }

    @pytest.fixture
    def mock_tools(self):
        """Mock tool definitions for testing."""
        return {
            "test-server": [
                MCPTool(
                    name="test_tool",
                    description="Test tool",
                    parameters=[
                        MCPToolParameter(
                            name="input",
                            type="string",
                            description="Test input",
                            required=True
                        )
                    ]
                )
            ],
            "docker": [
                MCPTool(
                    name="docker_build",
                    description="Build Docker image",
                    parameters=[
                        MCPToolParameter(
                            name="dockerfile_path",
                            type="string",
                            description="Path to Dockerfile",
                            required=True
                        ),
                        MCPToolParameter(
                            name="image_tag",
                            type="string",
                            description="Image tag",
                            required=True
                        )
                    ]
                ),
                MCPTool(
                    name="docker_ps",
                    description="List containers",
                    parameters=[]
                )
            ],
            "kubernetes": [
                MCPTool(
                    name="kubectl_apply",
                    description="Apply manifests",
                    parameters=[
                        MCPToolParameter(
                            name="manifest_path",
                            type="string",
                            description="Path to manifests",
                            required=True
                        )
                    ]
                )
            ]
        }

    @pytest.mark.asyncio
    async def test_manager_initialization(self, mcp_manager):
        """Test MCP Manager initialization."""
        assert mcp_manager is not None
        assert mcp_manager.initialized
        assert hasattr(mcp_manager, 'registry')
        assert hasattr(mcp_manager, 'call_tool')
        assert hasattr(mcp_manager, 'get_available_tools')

    @pytest.mark.asyncio
    async def test_singleton_pattern(self):
        """Test that get_mcp_manager returns singleton."""
        manager1 = get_mcp_manager()
        manager2 = get_mcp_manager()
        assert manager1 is manager2

    @pytest.mark.asyncio
    async def test_server_discovery(self, mcp_manager, mock_server_info):
        """Test server discovery and registration."""
        with patch.object(mcp_manager.registry, 'get_server') as mock_get_server:
            # Mock server discovery
            mock_servers = []
            for name, info in mock_server_info.items():
                mock_server = MagicMock()
                mock_server.get_server_info = AsyncMock(return_value=info)
                mock_servers.append((name, mock_server))
                
            with patch.object(mcp_manager.registry, 'servers', dict(mock_servers)):
                # Test server discovery
                servers = await mcp_manager.discover_servers()
                
                assert len(servers) == len(mock_server_info)
                assert "test-server" in servers
                assert "docker" in servers
                assert "kubernetes" in servers

    @pytest.mark.asyncio
    async def test_tool_discovery(self, mcp_manager, mock_tools):
        """Test tool discovery across all servers."""
        with patch.object(mcp_manager, '_discover_server_tools') as mock_discover:
            # Setup mock returns
            async def mock_discover_tools(server_name):
                return mock_tools.get(server_name, [])
            
            mock_discover.side_effect = mock_discover_tools
            
            # Discover tools
            all_tools = await mcp_manager.discover_all_tools()
            
            # Verify tool discovery
            assert len(all_tools) > 0
            tool_names = [tool.name for tool in all_tools]
            assert "test_tool" in tool_names
            assert "docker_build" in tool_names
            assert "kubectl_apply" in tool_names

    @pytest.mark.asyncio
    async def test_get_available_tools(self, mcp_manager, mock_tools):
        """Test getting available tools with caching."""
        with patch.object(mcp_manager, '_discover_server_tools') as mock_discover:
            # Setup mock returns
            all_tools = []
            for server_tools in mock_tools.values():
                all_tools.extend(server_tools)
            
            mock_discover.return_value = all_tools
            
            # Get available tools (should trigger discovery)
            tools1 = mcp_manager.get_available_tools()
            
            # Get again (should use cache)
            tools2 = mcp_manager.get_available_tools()
            
            # Verify
            assert tools1 == tools2
            assert len(tools1) > 0

    @pytest.mark.asyncio
    async def test_tool_name_resolution(self, mcp_manager):
        """Test tool name resolution with server prefixes."""
        # Test with full name
        server, tool = mcp_manager._resolve_tool_name("docker.docker_build")
        assert server == "docker"
        assert tool == "docker_build"
        
        # Test without prefix (should fail or return None)
        server, tool = mcp_manager._resolve_tool_name("docker_build")
        assert server is None or server == ""
        assert tool == "docker_build"

    @pytest.mark.asyncio
    async def test_call_tool_routing(self, mcp_manager):
        """Test tool call routing to correct server."""
        with patch.object(mcp_manager.registry, 'get_server') as mock_get_server:
            # Setup mock server
            mock_server = MagicMock()
            mock_server.call_tool = AsyncMock(
                return_value=MCPToolResult(
                    success=True,
                    output="Tool executed",
                    metadata={"test": "data"}
                )
            )
            mock_get_server.return_value = mock_server
            
            # Call tool
            result = await mcp_manager.call_tool(
                "docker.docker_build",
                {"dockerfile_path": "./", "image_tag": "test:latest"}
            )
            
            # Verify routing
            assert result.success
            mock_get_server.assert_called_once_with("docker")
            mock_server.call_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_parallel_tool_execution(self, mcp_manager):
        """Test parallel execution of multiple tools."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns
            mock_call.side_effect = [
                MCPToolResult(success=True, output=f"Result {i}") 
                for i in range(5)
            ]
            
            # Execute tools in parallel
            tasks = [
                mcp_manager.call_tool(f"test.tool{i}", {"param": i})
                for i in range(5)
            ]
            
            results = await asyncio.gather(*tasks)
            
            # Verify parallel execution
            assert len(results) == 5
            assert all(r.success for r in results)
            assert mock_call.call_count == 5

    @pytest.mark.asyncio
    async def test_tool_parameter_validation(self, mcp_manager):
        """Test tool parameter validation."""
        with patch.object(mcp_manager, '_get_tool_definition') as mock_get_tool:
            # Setup mock tool with required parameters
            mock_tool = MCPTool(
                name="test_tool",
                description="Test tool",
                parameters=[
                    MCPToolParameter(
                        name="required_param",
                        type="string",
                        description="Required parameter",
                        required=True
                    ),
                    MCPToolParameter(
                        name="optional_param",
                        type="integer",
                        description="Optional parameter",
                        required=False
                    )
                ]
            )
            mock_get_tool.return_value = mock_tool
            
            # Test with missing required parameter
            with pytest.raises(ValueError, match="required_param"):
                await mcp_manager.call_tool("test.test_tool", {"optional_param": 123})
            
            # Test with all required parameters
            with patch.object(mcp_manager.registry, 'get_server') as mock_get_server:
                mock_server = MagicMock()
                mock_server.call_tool = AsyncMock(
                    return_value=MCPToolResult(success=True, output="OK")
                )
                mock_get_server.return_value = mock_server
                
                result = await mcp_manager.call_tool(
                    "test.test_tool",
                    {"required_param": "value", "optional_param": 123}
                )
                assert result.success

    @pytest.mark.asyncio
    async def test_server_health_monitoring(self, mcp_manager):
        """Test server health monitoring capabilities."""
        with patch.object(mcp_manager, 'check_server_health') as mock_health:
            # Setup mock health checks
            mock_health.side_effect = [
                {"docker": "healthy", "kubernetes": "healthy"},
                {"docker": "healthy", "kubernetes": "unhealthy"},
                {"docker": "healthy", "kubernetes": "healthy"}
            ]
            
            # Check health over time
            health_results = []
            for _ in range(3):
                health = await mcp_manager.check_server_health()
                health_results.append(health)
            
            # Verify health monitoring
            assert len(health_results) == 3
            assert health_results[1]["kubernetes"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_tool_execution_timeout(self, mcp_manager):
        """Test tool execution with timeout."""
        with patch.object(mcp_manager.registry, 'get_server') as mock_get_server:
            # Setup mock server with slow tool
            mock_server = MagicMock()
            
            async def slow_tool(*args, **kwargs):
                await asyncio.sleep(5)  # Simulate slow operation
                return MCPToolResult(success=True, output="Done")
            
            mock_server.call_tool = slow_tool
            mock_get_server.return_value = mock_server
            
            # Call with timeout
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    mcp_manager.call_tool("test.slow_tool", {}),
                    timeout=1.0
                )

    @pytest.mark.asyncio
    async def test_server_capability_checking(self, mcp_manager, mock_server_info):
        """Test checking server capabilities before tool execution."""
        with patch.object(mcp_manager, 'get_server_info') as mock_get_info:
            mock_get_info.return_value = mock_server_info["test-server"]
            
            # Check capabilities
            has_tools = await mcp_manager.server_supports_capability("test-server", "tools")
            has_resources = await mcp_manager.server_supports_capability("test-server", "resources")
            has_unknown = await mcp_manager.server_supports_capability("test-server", "unknown")
            
            assert has_tools
            assert has_resources
            assert not has_unknown

    @pytest.mark.asyncio
    async def test_dynamic_tool_registration(self, mcp_manager):
        """Test dynamic tool registration at runtime."""
        # Create new tool
        new_tool = MCPTool(
            name="dynamic_tool",
            description="Dynamically registered tool",
            parameters=[]
        )
        
        # Register tool
        with patch.object(mcp_manager, 'register_tool') as mock_register:
            await mcp_manager.register_tool("test-server", new_tool)
            mock_register.assert_called_once_with("test-server", new_tool)

    @pytest.mark.asyncio
    async def test_batch_tool_execution(self, mcp_manager):
        """Test batch execution of multiple tools."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns
            mock_call.side_effect = [
                MCPToolResult(success=True, output=f"Batch result {i}")
                for i in range(10)
            ]
            
            # Execute batch
            batch_calls = [
                ("docker.docker_ps", {}),
                ("kubernetes.kubectl_get", {"resource": "pods"}),
                ("prometheus.prometheus_query", {"query": "up"}),
            ] * 3  # 9 calls total
            batch_calls.append(("slack.send_notification", {"message": "Batch complete"}))
            
            results = await mcp_manager.execute_batch(batch_calls)
            
            # Verify batch execution
            assert len(results) == 10
            assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_tool_dependency_resolution(self, mcp_manager):
        """Test resolution of tool dependencies."""
        # Define tool dependencies
        dependencies = {
            "deploy": ["build", "test"],
            "build": ["lint"],
            "test": ["lint"],
            "lint": []
        }
        
        with patch.object(mcp_manager, 'get_tool_dependencies') as mock_deps:
            mock_deps.side_effect = lambda tool: dependencies.get(tool.split('.')[-1], [])
            
            # Resolve execution order
            execution_order = await mcp_manager.resolve_tool_execution_order("app.deploy")
            
            # Verify dependency resolution
            assert execution_order == ["lint", "build", "test", "deploy"]

    @pytest.mark.asyncio
    async def test_cross_server_transaction(self, mcp_manager):
        """Test transactional execution across multiple servers."""
        with patch.object(mcp_manager, 'execute_transaction') as mock_transaction:
            # Define transaction steps
            transaction_steps = [
                ("docker.docker_build", {"dockerfile_path": "./", "image_tag": "app:latest"}),
                ("security-scanner.docker_security_scan", {"image_name": "app:latest"}),
                ("kubernetes.kubectl_apply", {"manifest_path": "./k8s/"})
            ]
            
            # Execute transaction
            mock_transaction.return_value = {
                "success": True,
                "results": [
                    MCPToolResult(success=True, output="Built"),
                    MCPToolResult(success=True, output="Secure"),
                    MCPToolResult(success=True, output="Deployed")
                ]
            }
            
            result = await mcp_manager.execute_transaction(transaction_steps)
            
            # Verify transaction
            assert result["success"]
            assert len(result["results"]) == 3

    @pytest.mark.asyncio
    async def test_server_fallback_mechanism(self, mcp_manager):
        """Test fallback to alternative servers on failure."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Primary server fails, fallback succeeds
            mock_call.side_effect = [
                MCPToolResult(success=False, error="Primary server unavailable"),
                MCPToolResult(success=True, output="Fallback server succeeded")
            ]
            
            # Define fallback chain
            fallback_servers = ["primary.tool", "fallback.tool"]
            
            # Execute with fallback
            result = None
            for server_tool in fallback_servers:
                result = await mcp_manager.call_tool(server_tool, {"param": "value"})
                if result.success:
                    break
            
            # Verify fallback worked
            assert result.success
            assert "Fallback server succeeded" in result.output
            assert mock_call.call_count == 2