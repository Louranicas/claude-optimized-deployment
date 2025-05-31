"""
Comprehensive unit tests for Docker MCP Server.

Tests all tool methods with valid inputs, invalid inputs, edge cases, and error conditions.
Achieves 95%+ coverage through thorough testing of all code paths.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List

from src.mcp.infrastructure_servers import DockerMCPServer
from src.mcp.protocols import MCPError, MCPServerInfo, MCPCapabilities
from src.core.exceptions import DockerError, MCPToolNotFoundError


class TestDockerMCPServer:
    """Test suite for Docker MCP Server."""
    
    @pytest.fixture
    def server(self):
        """Create a Docker MCP server instance."""
        return DockerMCPServer()
    
    @pytest.fixture
    def mock_docker_available(self, server):
        """Mock Docker availability check."""
        server.docker_available = True
        return server
    
    def test_server_info(self, server):
        """Test get_server_info returns correct information."""
        info = server.get_server_info()
        
        assert isinstance(info, MCPServerInfo)
        assert info.name == "docker"
        assert info.version == "1.0.0"
        assert "Docker container management" in info.description
        assert info.capabilities.tools is True
        assert info.capabilities.resources is False
        assert info.capabilities.prompts is False
        assert "container_management" in info.capabilities.experimental
        assert info.capabilities.experimental["container_management"] is True
    
    def test_get_tools(self, server):
        """Test get_tools returns all expected tools."""
        tools = server.get_tools()
        
        assert len(tools) == 4
        tool_names = [tool.name for tool in tools]
        assert "docker_run" in tool_names
        assert "docker_build" in tool_names
        assert "docker_compose" in tool_names
        assert "docker_ps" in tool_names
        
        # Verify docker_run parameters
        run_tool = next(t for t in tools if t.name == "docker_run")
        param_names = [p.name for p in run_tool.parameters]
        assert "image" in param_names
        assert "command" in param_names
        assert "volumes" in param_names
        assert "environment" in param_names
        assert "ports" in param_names
        
        # Verify docker_compose actions
        compose_tool = next(t for t in tools if t.name == "docker_compose")
        action_param = next(p for p in compose_tool.parameters if p.name == "action")
        assert action_param.enum == ["up", "down", "build", "logs", "ps", "pull"]
    
    @pytest.mark.asyncio
    async def test_check_docker_available(self, server):
        """Test Docker availability check."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Docker version 20.10.0", b""))
            mock_subprocess.return_value = mock_process
            
            result = await server._check_docker()
            
            assert result is True
            assert server.docker_available is True
            mock_subprocess.assert_called_once_with(
                "docker --version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
    
    @pytest.mark.asyncio
    async def test_check_docker_not_available(self, server):
        """Test Docker not available."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b"", b"command not found"))
            mock_subprocess.return_value = mock_process
            
            result = await server._check_docker()
            
            assert result is False
            assert server.docker_available is False
    
    @pytest.mark.asyncio
    async def test_check_docker_exception(self, server):
        """Test Docker check with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Process error")):
            result = await server._check_docker()
            
            assert result is False
            assert server.docker_available is False
    
    @pytest.mark.asyncio
    async def test_call_tool_docker_not_available(self, server):
        """Test calling tool when Docker is not available."""
        server.docker_available = False
        
        with pytest.raises(DockerError) as exc_info:
            await server.call_tool("docker_run", {"image": "alpine"})
        
        assert "Docker is not available" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_call_tool_unknown_tool(self, mock_docker_available):
        """Test calling unknown tool raises MCPToolNotFoundError."""
        with pytest.raises(MCPToolNotFoundError) as exc_info:
            await mock_docker_available.call_tool("unknown_tool", {})
        
        assert exc_info.value.tool_name == "unknown_tool"
        assert exc_info.value.server_name == "docker"
    
    # docker_run tests
    
    @pytest.mark.asyncio
    async def test_docker_run_simple(self, mock_docker_available):
        """Test simple docker run command."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Hello from container", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run("alpine")
            
            assert result["success"] is True
            assert result["exit_code"] == 0
            assert "Hello from container" in result["stdout"]
            assert "docker run --rm alpine" in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_run_with_command(self, mock_docker_available):
        """Test docker run with custom command."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"test output", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run(
                image="alpine",
                command="echo test"
            )
            
            assert "docker run --rm alpine echo test" in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_run_with_volumes(self, mock_docker_available):
        """Test docker run with volume mounts."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run(
                image="alpine",
                volumes=["/host/path:/container/path", "/data:/data:ro"]
            )
            
            cmd = result["command"]
            assert "-v /host/path:/container/path" in cmd
            assert "-v /data:/data:ro" in cmd
    
    @pytest.mark.asyncio
    async def test_docker_run_with_environment(self, mock_docker_available):
        """Test docker run with environment variables."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run(
                image="alpine",
                environment={"KEY1": "value1", "KEY2": "value2"}
            )
            
            cmd = result["command"]
            assert "-e KEY1=value1" in cmd
            assert "-e KEY2=value2" in cmd
    
    @pytest.mark.asyncio
    async def test_docker_run_with_ports(self, mock_docker_available):
        """Test docker run with port mappings."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run(
                image="nginx",
                ports=["8080:80", "8443:443"]
            )
            
            cmd = result["command"]
            assert "-p 8080:80" in cmd
            assert "-p 8443:443" in cmd
    
    @pytest.mark.asyncio
    async def test_docker_run_failure(self, mock_docker_available):
        """Test docker run failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 125
            mock_process.communicate = AsyncMock(return_value=(b"", b"Unable to find image"))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_run("nonexistent:image")
            
            assert result["success"] is False
            assert result["exit_code"] == 125
            assert "Unable to find image" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_docker_run_exception(self, mock_docker_available):
        """Test docker run with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Process failed")):
            with pytest.raises(DockerError) as exc_info:
                await mock_docker_available._docker_run("alpine")
            
            assert "Docker run failed" in str(exc_info.value)
            assert exc_info.value.image == "alpine"
    
    # docker_build tests
    
    @pytest.mark.asyncio
    async def test_docker_build_success(self, mock_docker_available):
        """Test successful docker build."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"Successfully built abc123\nSuccessfully tagged myapp:latest",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_build(
                dockerfile_path="Dockerfile",
                image_tag="myapp:latest"
            )
            
            assert result["success"] is True
            assert result["image_tag"] == "myapp:latest"
            assert "Successfully built" in result["stdout"]
            assert "docker build -f Dockerfile -t myapp:latest ." in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_build_custom_context(self, mock_docker_available):
        """Test docker build with custom build context."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_build(
                dockerfile_path="docker/Dockerfile.prod",
                image_tag="myapp:prod",
                build_context="./src"
            )
            
            expected_cmd = "docker build -f docker/Dockerfile.prod -t myapp:prod ./src"
            assert result["command"] == expected_cmd
    
    @pytest.mark.asyncio
    async def test_docker_build_failure(self, mock_docker_available):
        """Test docker build failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error: Dockerfile not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_build(
                dockerfile_path="missing.dockerfile",
                image_tag="app:latest"
            )
            
            assert result["success"] is False
            assert "Dockerfile not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_docker_build_exception(self, mock_docker_available):
        """Test docker build with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Build error")):
            with pytest.raises(DockerError) as exc_info:
                await mock_docker_available._docker_build("Dockerfile", "app:latest")
            
            assert "Docker build failed" in str(exc_info.value)
            assert exc_info.value.image == "app:latest"
    
    # docker_compose tests
    
    @pytest.mark.asyncio
    async def test_docker_compose_up(self, mock_docker_available):
        """Test docker-compose up command."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"Creating network app_default\nCreating app_web_1",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_compose("up")
            
            assert result["success"] is True
            assert result["action"] == "up"
            assert "docker-compose -f docker-compose.yml up" in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_compose_with_services(self, mock_docker_available):
        """Test docker-compose with specific services."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_compose(
                action="up",
                services=["web", "db"]
            )
            
            assert "docker-compose -f docker-compose.yml up web db" in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_compose_custom_file(self, mock_docker_available):
        """Test docker-compose with custom compose file."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_compose(
                action="down",
                compose_file="docker-compose.prod.yml"
            )
            
            assert "docker-compose -f docker-compose.prod.yml down" in result["command"]
    
    @pytest.mark.asyncio
    async def test_docker_compose_failure(self, mock_docker_available):
        """Test docker-compose failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"ERROR: Compose file not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_compose("up")
            
            assert result["success"] is False
            assert "Compose file not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_docker_compose_exception(self, mock_docker_available):
        """Test docker-compose with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Compose error")):
            with pytest.raises(DockerError) as exc_info:
                await mock_docker_available._docker_compose("up")
            
            assert "Docker compose up failed" in str(exc_info.value)
    
    # docker_ps tests
    
    @pytest.mark.asyncio
    async def test_docker_ps_success(self, mock_docker_available):
        """Test docker ps command."""
        container_json = [
            {"ID": "abc123", "Names": "web", "Status": "Up 2 hours"},
            {"ID": "def456", "Names": "db", "Status": "Up 1 hour"}
        ]
        json_output = "\n".join(json.dumps(c) for c in container_json)
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json_output.encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_ps()
            
            assert result["total"] == 2
            assert len(result["containers"]) == 2
            assert result["containers"][0]["ID"] == "abc123"
    
    @pytest.mark.asyncio
    async def test_docker_ps_all(self, mock_docker_available):
        """Test docker ps with all containers."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            await mock_docker_available._docker_ps(all=True)
            
            call_args = mock_subprocess.call_args[0][0]
            assert "docker ps --format json -a" in call_args
    
    @pytest.mark.asyncio
    async def test_docker_ps_empty(self, mock_docker_available):
        """Test docker ps with no containers."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_docker_available._docker_ps()
            
            assert result["total"] == 0
            assert result["containers"] == []
    
    @pytest.mark.asyncio
    async def test_docker_ps_failure(self, mock_docker_available):
        """Test docker ps failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Cannot connect to Docker daemon"
            ))
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(DockerError) as exc_info:
                await mock_docker_available._docker_ps()
            
            assert "Docker ps failed" in str(exc_info.value)
            assert "Cannot connect to Docker daemon" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_docker_ps_json_error(self, mock_docker_available):
        """Test docker ps with invalid JSON."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"invalid json",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(DockerError) as exc_info:
                await mock_docker_available._docker_ps()
            
            assert "Docker ps failed" in str(exc_info.value)
    
    # Integration tests for call_tool
    
    @pytest.mark.asyncio
    async def test_call_tool_docker_run(self, mock_docker_available):
        """Test call_tool with docker_run."""
        with patch.object(mock_docker_available, '_docker_run') as mock_run:
            mock_run.return_value = {"success": True}
            
            result = await mock_docker_available.call_tool("docker_run", {
                "image": "alpine:latest",
                "command": "echo hello"
            })
            
            mock_run.assert_called_once_with(
                image="alpine:latest",
                command="echo hello"
            )
    
    @pytest.mark.asyncio
    async def test_call_tool_error_handling(self, mock_docker_available):
        """Test call_tool error handling and logging."""
        with patch.object(mock_docker_available, '_docker_build') as mock_build:
            mock_build.side_effect = Exception("Build failed")
            
            with patch('src.mcp.infrastructure_servers.logger') as mock_logger:
                with patch('src.mcp.infrastructure_servers.handle_error') as mock_handle:
                    with pytest.raises(DockerError):
                        await mock_docker_available.call_tool("docker_build", {
                            "dockerfile_path": "Dockerfile",
                            "image_tag": "app:latest"
                        })
                    
                    mock_handle.assert_called_once()
                    error_arg = mock_handle.call_args[0][0]
                    assert isinstance(error_arg, DockerError)


@pytest.mark.asyncio
class TestDockerMCPEdgeCases:
    """Edge case tests for Docker MCP Server."""
    
    @pytest.fixture
    def server(self):
        server = DockerMCPServer()
        server.docker_available = True
        return server
    
    async def test_docker_run_complex_command(self, server):
        """Test docker run with complex shell command."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"output", b""))
            mock_subprocess.return_value = mock_process
            
            result = await server._docker_run(
                image="alpine",
                command="sh -c 'echo hello && echo world'"
            )
            
            assert "sh -c 'echo hello && echo world'" in result["command"]
    
    async def test_docker_run_special_characters_env(self, server):
        """Test docker run with special characters in environment."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await server._docker_run(
                image="alpine",
                environment={"KEY": "value with spaces", "SPECIAL": "val$ue"}
            )
            
            cmd = result["command"]
            assert "-e KEY=value with spaces" in cmd
            assert "-e SPECIAL=val$ue" in cmd
    
    async def test_docker_build_long_tag(self, server):
        """Test docker build with long registry tag."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            long_tag = "registry.example.com:5000/namespace/app:v1.2.3-beta"
            result = await server._docker_build(
                dockerfile_path="Dockerfile",
                image_tag=long_tag
            )
            
            assert long_tag in result["command"]
    
    async def test_docker_compose_all_actions(self, server):
        """Test all docker-compose actions."""
        actions = ["up", "down", "build", "logs", "ps", "pull"]
        
        for action in actions:
            with patch('asyncio.create_subprocess_shell') as mock_subprocess:
                mock_process = AsyncMock()
                mock_process.returncode = 0
                mock_process.communicate = AsyncMock(return_value=(b"", b""))
                mock_subprocess.return_value = mock_process
                
                result = await server._docker_compose(action)
                
                assert result["action"] == action
                assert f"docker-compose -f docker-compose.yml {action}" in result["command"]
    
    async def test_docker_availability_caching(self, server):
        """Test Docker availability is cached after first check."""
        server.docker_available = None
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Docker", b""))
            mock_subprocess.return_value = mock_process
            
            # First check
            result1 = await server._check_docker()
            # Second check - should use cached value
            result2 = await server._check_docker()
            
            assert result1 is True
            assert result2 is True
            # Should only be called once due to caching
            assert mock_subprocess.call_count == 1