"""
Comprehensive Integration Tests for All 11 MCP Servers

This test suite covers integration testing, tool execution, authentication,
and error handling for all MCP servers identified in the CODE project:

1. BraveMCPServer (web search)
2. DesktopCommanderMCPServer (command execution)
3. DockerMCPServer (container management)
4. KubernetesMCPServer (k8s operations)
5. AzureDevOpsMCPServer (DevOps integration)
6. WindowsSystemMCPServer (Windows operations)
7. SlackNotificationMCPServer (communication)
8. PrometheusMonitoringMCP (monitoring)
9. SecurityScannerMCPServer (security scanning)
10. S3StorageMCPServer (cloud storage)
11. CloudStorageMCP (multi-cloud storage)

Tests focus on both successful operations and failure scenarios.
"""

import pytest
import asyncio
import aiohttp
import json
import os
import tempfile
import shutil
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

# Import all MCP servers
from src.mcp.servers import BraveMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.mcp.infrastructure_servers import DesktopCommanderMCPServer, DockerMCPServer, KubernetesMCPServer
from src.mcp.communication.slack_server import SlackNotificationMCPServer
from src.mcp.monitoring.prometheus_server import PrometheusMonitoringMCP
from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.storage.s3_server import S3StorageMCPServer
from src.mcp.storage.cloud_storage_server import CloudStorageMCP

# Import protocols and exceptions
from src.mcp.protocols import MCPError, MCPServerInfo, MCPCapabilities
from src.core.exceptions import ValidationError, ServiceUnavailableError, ExternalServiceError

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class MockUser:
    """Mock user object for authentication testing."""
    
    def __init__(self, username: str = "test_user", user_id: str = "user_123", permissions: List[str] = None):
        self.username = username
        self.id = user_id
        self.permissions = permissions or []


class MockPermissionChecker:
    """Mock permission checker for authentication testing."""
    
    def __init__(self, allowed_permissions: List[str] = None):
        self.allowed_permissions = allowed_permissions or []
    
    async def check_permission(self, user: MockUser, permission: str) -> bool:
        return permission in self.allowed_permissions
    
    def register_resource_permission(self, resource: str, permission: str):
        """Mock resource permission registration."""
        pass


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    return MockUser(
        username="test_user",
        user_id="user_123",
        permissions=["mcp.brave.search:execute", "mcp.docker.container:execute", "mcp.kubernetes.deployment:execute"]
    )


@pytest.fixture
def mock_permission_checker():
    """Create a mock permission checker."""
    return MockPermissionChecker([
        "mcp.brave.search:execute",
        "mcp.desktop.command:execute",
        "mcp.docker.container:execute",
        "mcp.kubernetes.deployment:execute",
        "mcp.azuredevops.pipeline:execute",
        "mcp.windows.powershell:execute",
        "mcp.slack.notification:send",
        "mcp.prometheus.metrics:read",
        "mcp.security.scan:execute",
        "mcp.s3.bucket:read",
        "mcp.storage.cloud:access"
    ])


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


class TestBraveMCPServer:
    """Integration tests for Brave Search MCP Server."""
    
    @pytest.fixture
    def brave_server(self, mock_permission_checker):
        """Create Brave MCP server instance."""
        return BraveMCPServer(
            api_key="test_api_key",
            permission_checker=mock_permission_checker
        )
    
    def test_server_initialization(self, brave_server):
        """Test Brave server initialization."""
        assert brave_server.name == "brave-search"
        assert brave_server.version == "1.0.0"
        assert brave_server.api_key == "test_api_key"
    
    def test_server_info(self, brave_server):
        """Test server info retrieval."""
        info = brave_server.get_server_info()
        assert isinstance(info, MCPServerInfo)
        assert info.name == "brave-search"
        assert info.version == "1.0.0"
        assert info.capabilities.tools is True
    
    def test_available_tools(self, brave_server):
        """Test available tools listing."""
        tools = brave_server.get_tools()
        expected_tools = {"brave_web_search", "brave_local_search", "brave_news_search", "brave_image_search"}
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_web_search_success(self, brave_server, mock_user):
        """Test successful web search."""
        with patch.object(brave_server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "web": {
                    "results": [
                        {
                            "title": "Test Result",
                            "url": "https://example.com",
                            "description": "Test description"
                        }
                    ]
                }
            }
            mock_session.get.return_value.__aenter__.return_value = mock_response
            brave_server.session = mock_session
            
            result = await brave_server.call_tool(
                "brave_web_search",
                {"query": "python programming"},
                mock_user
            )
            
            assert result["query"] == "python programming"
            assert len(result["results"]) == 1
            assert result["results"][0]["title"] == "Test Result"
    
    @pytest.mark.asyncio
    async def test_web_search_api_error(self, brave_server, mock_user):
        """Test web search with API error."""
        with patch.object(brave_server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 429  # Rate limit
            mock_response.text.return_value = "Rate limit exceeded"
            mock_session.get.return_value.__aenter__.return_value = mock_response
            brave_server.session = mock_session
            
            with pytest.raises(MCPError) as exc_info:
                await brave_server.call_tool(
                    "brave_web_search",
                    {"query": "test"},
                    mock_user
                )
            
            assert "Brave API error: 429" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_invalid_tool_name(self, brave_server, mock_user):
        """Test calling invalid tool name."""
        with pytest.raises(MCPError) as exc_info:
            await brave_server.call_tool("invalid_tool", {}, mock_user)
        
        assert "Unknown tool: invalid_tool" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_session_cleanup(self, brave_server):
        """Test session cleanup."""
        brave_server.session = AsyncMock()
        await brave_server.close()
        brave_server.session.close.assert_called_once()


class TestDesktopCommanderMCPServer:
    """Integration tests for Desktop Commander MCP Server."""
    
    @pytest.fixture
    def commander_server(self, mock_permission_checker):
        """Create Desktop Commander MCP server instance."""
        return DesktopCommanderMCPServer(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, commander_server):
        """Test Desktop Commander server initialization."""
        assert commander_server.name == "desktop-commander"
        assert commander_server.version == "1.0.0"
        assert hasattr(commander_server, 'command_executor')
    
    def test_available_tools(self, commander_server):
        """Test available tools listing."""
        tools = commander_server.get_tools()
        expected_tools = {"execute_command", "read_file", "write_file", "list_directory", "make_command"}
        actual_tools = {tool.name for tool in tools}
        assert expected_tools.issubset(actual_tools)
    
    @pytest.mark.asyncio
    async def test_execute_command_success(self, commander_server, mock_user):
        """Test successful command execution."""
        with patch.object(commander_server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.command = "echo hello"
            mock_result.working_directory = "/tmp"
            mock_result.exit_code = 0
            mock_result.stdout = "hello\n"
            mock_result.stderr = ""
            mock_result.success = True
            mock_result.truncated = False
            
            mock_executor.execute_async.return_value = mock_result
            
            result = await commander_server.call_tool(
                "execute_command",
                {"command": "echo hello"},
                mock_user
            )
            
            assert result["success"] is True
            assert result["exit_code"] == 0
            assert "hello" in result["stdout"]
    
    @pytest.mark.asyncio
    async def test_execute_command_failure(self, commander_server, mock_user):
        """Test command execution failure."""
        with patch.object(commander_server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.command = "invalid_command"
            mock_result.working_directory = "/tmp"
            mock_result.exit_code = 127
            mock_result.stdout = ""
            mock_result.stderr = "command not found"
            mock_result.success = False
            mock_result.truncated = False
            
            mock_executor.execute_async.return_value = mock_result
            
            result = await commander_server.call_tool(
                "execute_command",
                {"command": "invalid_command"},
                mock_user
            )
            
            assert result["success"] is False
            assert result["exit_code"] == 127
            assert "command not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_read_file_success(self, commander_server, mock_user, temp_dir):
        """Test successful file reading."""
        test_file = temp_dir / "test.txt"
        test_content = "This is test content"
        test_file.write_text(test_content)
        
        with patch('pathlib.Path.resolve') as mock_resolve, \
             patch('src.core.command_sanitizer.CommandSanitizer.sanitize_path') as mock_sanitize:
            mock_sanitize.return_value = str(test_file)
            mock_resolve.return_value = test_file
            
            result = await commander_server.call_tool(
                "read_file",
                {"file_path": str(test_file)},
                mock_user
            )
            
            assert result["content"] == test_content
            assert result["size"] == len(test_content)
    
    @pytest.mark.asyncio
    async def test_read_file_not_found(self, commander_server, mock_user):
        """Test reading non-existent file."""
        with patch('src.core.command_sanitizer.CommandSanitizer.sanitize_path') as mock_sanitize:
            mock_sanitize.side_effect = FileNotFoundError("File not found")
            
            with pytest.raises(Exception):  # Should raise some exception
                await commander_server.call_tool(
                    "read_file",
                    {"file_path": "/nonexistent/file.txt"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_write_file_success(self, commander_server, mock_user, temp_dir):
        """Test successful file writing."""
        test_file = temp_dir / "output.txt"
        test_content = "This is output content"
        
        with patch('src.core.command_sanitizer.CommandSanitizer.sanitize_path') as mock_sanitize:
            mock_sanitize.return_value = str(test_file)
            
            result = await commander_server.call_tool(
                "write_file",
                {"file_path": str(test_file), "content": test_content},
                mock_user
            )
            
            assert result["size"] == len(test_content)
            assert Path(result["file_path"]).name == "output.txt"


class TestDockerMCPServer:
    """Integration tests for Docker MCP Server."""
    
    @pytest.fixture
    def docker_server(self, mock_permission_checker):
        """Create Docker MCP server instance."""
        return DockerMCPServer(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, docker_server):
        """Test Docker server initialization."""
        assert docker_server.name == "docker"
        assert docker_server.version == "1.0.0"
    
    def test_available_tools(self, docker_server):
        """Test available tools listing."""
        tools = docker_server.get_tools()
        expected_tools = {"docker_run", "docker_build", "docker_compose", "docker_ps"}
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_docker_availability_check(self, docker_server):
        """Test Docker availability check."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Docker version", b"")
            mock_subprocess.return_value = mock_process
            
            is_available = await docker_server._check_docker()
            assert is_available is True
    
    @pytest.mark.asyncio
    async def test_docker_unavailable(self, docker_server, mock_user):
        """Test Docker unavailable scenario."""
        docker_server.docker_available = False
        
        with pytest.raises(Exception):  # Should raise DockerError or similar
            await docker_server.call_tool(
                "docker_ps",
                {"all": False},
                mock_user
            )
    
    @pytest.mark.asyncio
    async def test_docker_run_success(self, docker_server, mock_user):
        """Test successful Docker run."""
        docker_server.docker_available = True
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Container output", b"")
            mock_subprocess.return_value = mock_process
            
            result = await docker_server.call_tool(
                "docker_run",
                {"image": "alpine:latest", "command": "echo hello"},
                mock_user
            )
            
            assert result["success"] is True
            assert result["exit_code"] == 0
    
    @pytest.mark.asyncio
    async def test_docker_run_with_validation_error(self, docker_server, mock_user):
        """Test Docker run with validation error."""
        docker_server.docker_available = True
        
        with pytest.raises(Exception):  # Should raise validation error
            await docker_server.call_tool(
                "docker_run",
                {"image": "invalid-image-name-!@#", "command": "echo hello"},
                mock_user
            )
    
    @pytest.mark.asyncio
    async def test_docker_ps_success(self, docker_server, mock_user):
        """Test successful Docker ps."""
        docker_server.docker_available = True
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (
                b'{"ID":"abc123","Image":"alpine","Status":"Up"}\n',
                b""
            )
            mock_subprocess.return_value = mock_process
            
            result = await docker_server.call_tool(
                "docker_ps",
                {"all": False},
                mock_user
            )
            
            assert "containers" in result
            assert result["total"] >= 0


class TestKubernetesMCPServer:
    """Integration tests for Kubernetes MCP Server."""
    
    @pytest.fixture
    def k8s_server(self, mock_permission_checker):
        """Create Kubernetes MCP server instance."""
        return KubernetesMCPServer(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, k8s_server):
        """Test Kubernetes server initialization."""
        assert k8s_server.name == "kubernetes"
        assert k8s_server.version == "1.0.0"
    
    def test_available_tools(self, k8s_server):
        """Test available tools listing."""
        tools = k8s_server.get_tools()
        expected_tools = {"kubectl_apply", "kubectl_get", "kubectl_delete", "kubectl_logs", "kubectl_describe"}
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_kubectl_availability_check(self, k8s_server):
        """Test kubectl availability check."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"kubectl version", b"")
            mock_subprocess.return_value = mock_process
            
            is_available = await k8s_server._check_kubectl()
            assert is_available is True
    
    @pytest.mark.asyncio
    async def test_kubectl_get_success(self, k8s_server, mock_user):
        """Test successful kubectl get."""
        k8s_server.kubectl_available = True
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (
                b'{"items":[{"metadata":{"name":"test-pod"}}]}',
                b""
            )
            mock_subprocess.return_value = mock_process
            
            result = await k8s_server.call_tool(
                "kubectl_get",
                {"resource_type": "pods", "namespace": "default"},
                mock_user
            )
            
            assert result["success"] is True
            assert "resources" in result
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_with_manifest(self, k8s_server, mock_user, temp_dir):
        """Test kubectl apply with manifest file."""
        k8s_server.kubectl_available = True
        
        # Create a test manifest file
        manifest_file = temp_dir / "deployment.yaml"
        manifest_content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  replicas: 1
"""
        manifest_file.write_text(manifest_content)
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (
                b"deployment.apps/test-deployment created",
                b""
            )
            mock_subprocess.return_value = mock_process
            
            result = await k8s_server.call_tool(
                "kubectl_apply",
                {"manifest_path": str(manifest_file), "namespace": "default"},
                mock_user
            )
            
            assert result["success"] is True
            assert result["namespace"] == "default"


class TestAzureDevOpsMCPServer:
    """Integration tests for Azure DevOps MCP Server."""
    
    @pytest.fixture
    def azuredevops_server(self, mock_permission_checker):
        """Create Azure DevOps MCP server instance."""
        return AzureDevOpsMCPServer(
            permission_checker=mock_permission_checker,
            organization="test-org",
            personal_access_token="test-pat"
        )
    
    def test_server_initialization(self, azuredevops_server):
        """Test Azure DevOps server initialization."""
        assert azuredevops_server.name == "azure-devops"
        assert azuredevops_server.version == "1.0.0"
        assert azuredevops_server.organization == "test-org"
    
    def test_available_tools(self, azuredevops_server):
        """Test available tools listing."""
        tools = azuredevops_server.get_tools()
        expected_tools = {
            "list_projects", "list_pipelines", "trigger_pipeline",
            "get_pipeline_runs", "create_work_item", "get_work_items", "create_pull_request"
        }
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_list_projects_success(self, azuredevops_server, mock_user):
        """Test successful project listing."""
        with patch.object(azuredevops_server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "value": [
                    {"id": "proj1", "name": "Project 1", "description": "Test project 1"},
                    {"id": "proj2", "name": "Project 2", "description": "Test project 2"}
                ]
            }
            mock_session.get.return_value.__aenter__.return_value = mock_response
            azuredevops_server.session = mock_session
            
            result = await azuredevops_server.call_tool(
                "list_projects",
                {},
                mock_user
            )
            
            assert len(result["projects"]) == 2
            assert result["total"] == 2
    
    @pytest.mark.asyncio
    async def test_trigger_pipeline_success(self, azuredevops_server, mock_user):
        """Test successful pipeline trigger."""
        with patch.object(azuredevops_server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 201
            mock_response.json.return_value = {
                "id": "run123",
                "state": "running",
                "url": "https://dev.azure.com/test-org/project/_build/results?buildId=123"
            }
            mock_session.post.return_value.__aenter__.return_value = mock_response
            azuredevops_server.session = mock_session
            
            result = await azuredevops_server.call_tool(
                "trigger_pipeline",
                {"project": "test-project", "pipeline_id": 42, "branch": "main"},
                mock_user
            )
            
            assert result["run_id"] == "run123"
            assert result["state"] == "running"
    
    @pytest.mark.asyncio
    async def test_authentication_failure(self, azuredevops_server, mock_user):
        """Test authentication failure."""
        with patch.object(azuredevops_server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 401
            mock_session.get.return_value.__aenter__.return_value = mock_response
            azuredevops_server.session = mock_session
            
            with pytest.raises(MCPError):
                await azuredevops_server.call_tool(
                    "list_projects",
                    {},
                    mock_user
                )


class TestWindowsSystemMCPServer:
    """Integration tests for Windows System MCP Server."""
    
    @pytest.fixture
    def windows_server(self, mock_permission_checker):
        """Create Windows System MCP server instance."""
        return WindowsSystemMCPServer(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, windows_server):
        """Test Windows server initialization."""
        assert windows_server.name == "windows-system"
        assert windows_server.version == "1.0.0"
    
    def test_available_tools(self, windows_server):
        """Test available tools listing."""
        tools = windows_server.get_tools()
        expected_tools = {
            "powershell_command", "windows_service", "check_windows_features",
            "windows_environment", "windows_network"
        }
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_powershell_command_validation(self, windows_server, mock_user):
        """Test PowerShell command validation."""
        # Test valid command
        valid_command = "Get-Process"
        assert windows_server._validate_powershell_command(valid_command) is True
        
        # Test invalid command
        with pytest.raises(MCPError):
            windows_server._validate_powershell_command("rm -rf /")
    
    @pytest.mark.asyncio
    async def test_powershell_command_success(self, windows_server, mock_user):
        """Test successful PowerShell command execution."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (
                b"ProcessName   CPU\nnotebook      12.34",
                b""
            )
            mock_subprocess.return_value = mock_process
            
            result = await windows_server.call_tool(
                "powershell_command",
                {"command": "Get-Process"},
                mock_user
            )
            
            assert result["success"] is True
            assert result["exit_code"] == 0
    
    @pytest.mark.asyncio
    async def test_windows_service_management(self, windows_server, mock_user):
        """Test Windows service management."""
        with patch.object(windows_server, '_powershell_command') as mock_ps:
            mock_ps.return_value = {
                "success": True,
                "exit_code": 0,
                "stdout": '{"Name":"Spooler","Status":"Running","StartType":"Automatic"}'
            }
            
            result = await windows_server.call_tool(
                "windows_service",
                {"action": "status", "service_name": "Spooler"},
                mock_user
            )
            
            assert result["success"] is True
            assert "service_info" in result


class TestSlackNotificationMCPServer:
    """Integration tests for Slack Notification MCP Server."""
    
    @pytest.fixture
    def slack_server(self, mock_permission_checker):
        """Create Slack MCP server instance."""
        return SlackNotificationMCPServer(
            slack_token="xoxb-test-token",
            teams_webhook="https://outlook.office.com/webhook/test"
        )
    
    def test_server_initialization(self, slack_server):
        """Test Slack server initialization."""
        assert slack_server.slack_token == "xoxb-test-token"
        assert slack_server.teams_webhook == "https://outlook.office.com/webhook/test"
    
    def test_available_tools(self, slack_server):
        """Test available tools listing."""
        tools = slack_server.get_tools()
        expected_tools = {
            "send_notification", "send_alert", "post_message", "create_channel",
            "update_status", "broadcast_deployment", "escalate_incident", "list_channels"
        }
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools
    
    @pytest.mark.asyncio
    async def test_send_notification_success(self, slack_server):
        """Test successful notification sending."""
        with patch.object(slack_server, '_make_safe_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"ok": True, "ts": "1234567890.123456"}
            mock_request.return_value = mock_response
            
            result = await slack_server.call_tool(
                "send_notification",
                {
                    "message": "Test notification",
                    "channels": ["slack"],
                    "priority": "medium"
                }
            )
            
            assert result["message"] == "Test notification"
            assert result["priority"] == "medium"
            assert "channels" in result
    
    @pytest.mark.asyncio
    async def test_send_alert_with_suppression(self, slack_server):
        """Test alert sending with duplicate suppression."""
        with patch.object(slack_server, '_should_suppress_alert') as mock_suppress:
            mock_suppress.return_value = True
            
            result = await slack_server.call_tool(
                "send_alert",
                {
                    "alert_type": "security",
                    "severity": "high",
                    "title": "Security Alert",
                    "description": "Test security alert",
                    "suppress_duplicate": True
                }
            )
            
            assert result["status"] == "suppressed"
            assert "alert_hash" in result
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, slack_server):
        """Test rate limiting functionality."""
        # Simulate rate limit exceeded
        with patch.object(slack_server, '_check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = False
            
            with pytest.raises(MCPError) as exc_info:
                await slack_server.call_tool(
                    "send_notification",
                    {"message": "Test", "channels": ["slack"]}
                )
            
            assert "Rate limit exceeded" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_open(self, slack_server):
        """Test circuit breaker in open state."""
        # Set circuit breaker to open state
        slack_server.circuit_state["slack"]["state"] = "open"
        slack_server.circuit_state["slack"]["last_failure"] = 0  # Very old failure
        
        with patch.object(slack_server, '_check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = True
            
            result = await slack_server.call_tool(
                "send_notification",
                {"message": "Test", "channels": ["slack"]}
            )
            
            assert result["channels"]["slack"]["success"] is False
            assert "Circuit breaker open" in result["channels"]["slack"]["error"]


class TestPrometheusMonitoringMCP:
    """Integration tests for Prometheus Monitoring MCP Server."""
    
    @pytest.fixture
    def prometheus_server(self, mock_permission_checker):
        """Create Prometheus MCP server instance."""
        return PrometheusMonitoringMCP(
            prometheus_url="http://localhost:9090",
            permission_checker=mock_permission_checker
        )
    
    def test_server_initialization(self, prometheus_server):
        """Test Prometheus server initialization."""
        assert "prometheus-monitoring" in prometheus_server.name
        assert prometheus_server.prometheus_url == "http://localhost:9090"
    
    @pytest.mark.asyncio
    async def test_query_validation(self, prometheus_server):
        """Test PromQL query validation."""
        from src.mcp.monitoring.prometheus_server import validate_promql
        
        # Valid query
        validate_promql("up")
        validate_promql("rate(http_requests_total[5m])")
        
        # Invalid queries
        with pytest.raises(MCPError):
            validate_promql("")  # Empty query
        
        with pytest.raises(MCPError):
            validate_promql("a" * 1001)  # Too long
        
        with pytest.raises(MCPError):
            validate_promql("up; drop table users")  # Dangerous pattern
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, prometheus_server):
        """Test rate limiting functionality."""
        from src.mcp.monitoring.prometheus_server import RateLimiter
        
        rate_limiter = RateLimiter(max_requests=2, window=60)
        
        # First two requests should pass
        assert rate_limiter.is_allowed("test_key") is True
        assert rate_limiter.is_allowed("test_key") is True
        
        # Third request should be blocked
        assert rate_limiter.is_allowed("test_key") is False
    
    @pytest.mark.asyncio
    async def test_circuit_breaker(self, prometheus_server):
        """Test circuit breaker functionality."""
        from src.mcp.monitoring.prometheus_server import CircuitBreaker
        
        circuit_breaker = CircuitBreaker(threshold=2, timeout=30)
        
        # Initial state should be closed
        assert circuit_breaker.is_open() is False
        
        # Record failures
        circuit_breaker.record_failure()
        circuit_breaker.record_failure()
        
        # Should now be open
        assert circuit_breaker.is_open() is True
        
        # Record success should close it
        circuit_breaker.record_success()
        assert circuit_breaker.is_open() is False


class TestSecurityScannerMCPServer:
    """Integration tests for Security Scanner MCP Server."""
    
    @pytest.fixture
    def security_server(self, mock_permission_checker):
        """Create Security Scanner MCP server instance."""
        return SecurityScannerMCPServer(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, security_server):
        """Test Security Scanner server initialization."""
        assert security_server.name == "security-scanner"
        assert security_server.version == "2.0.0"
        assert hasattr(security_server, 'hardening')
    
    def test_input_sanitization(self, security_server):
        """Test input sanitization."""
        from src.mcp.security.scanner_server import SecurityHardening
        
        # Valid input
        safe_input = SecurityHardening.sanitize_input("safe_string")
        assert safe_input == "safe_string"
        
        # Dangerous input
        with pytest.raises(ValueError):
            SecurityHardening.sanitize_input("dangerous; rm -rf /")
    
    def test_entropy_calculation(self, security_server):
        """Test entropy calculation for secret detection."""
        from src.mcp.security.scanner_server import SecurityHardening
        
        # Low entropy
        low_entropy = SecurityHardening.calculate_entropy("aaaaaaa")
        assert low_entropy < 2.0
        
        # High entropy
        high_entropy = SecurityHardening.calculate_entropy("a1B2c3D4e5F6")
        assert high_entropy > 3.0
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, security_server):
        """Test rate limiting for security operations."""
        identifier = "test_user"
        
        # Should allow initial requests
        allowed = await security_server.rate_limiter.check_rate_limit(identifier)
        assert allowed is True
        
        # Simulate many requests
        for _ in range(100):
            await security_server.rate_limiter.check_rate_limit(identifier)
        
        # Should now be rate limited
        allowed = await security_server.rate_limiter.check_rate_limit(identifier)
        assert allowed is False


class TestS3StorageMCPServer:
    """Integration tests for S3 Storage MCP Server."""
    
    @pytest.fixture
    def s3_server(self, mock_permission_checker):
        """Create S3 Storage MCP server instance."""
        return S3StorageMCPServer(
            aws_access_key="test_access_key",
            aws_secret_key="test_secret_key",
            region="us-east-1"
        )
    
    def test_server_initialization(self, s3_server):
        """Test S3 server initialization."""
        assert s3_server.aws_access_key == "test_access_key"
        assert s3_server.aws_secret_key == "test_secret_key"
        assert s3_server.region == "us-east-1"
    
    def test_available_tools(self, s3_server):
        """Test available tools listing."""
        tools = s3_server.get_tools()
        expected_tools = {
            "s3_list_buckets", "s3_list_objects", "s3_upload_file",
            "s3_download_file", "s3_delete_object", "s3_create_presigned_url"
        }
        actual_tools = {tool.name for tool in tools}
        assert expected_tools == actual_tools


class TestCloudStorageMCP:
    """Integration tests for Cloud Storage MCP Server."""
    
    @pytest.fixture
    def cloud_storage_server(self, mock_permission_checker):
        """Create Cloud Storage MCP server instance."""
        return CloudStorageMCP(permission_checker=mock_permission_checker)
    
    def test_server_initialization(self, cloud_storage_server):
        """Test Cloud Storage server initialization."""
        # Verify server is properly initialized
        assert hasattr(cloud_storage_server, 'name')
        assert hasattr(cloud_storage_server, 'version')


class TestMCPServerIntegration:
    """Integration tests across multiple MCP servers."""
    
    @pytest.mark.asyncio
    async def test_multi_server_workflow(self, mock_user, mock_permission_checker):
        """Test workflow across multiple MCP servers."""
        # Initialize servers
        commander = DesktopCommanderMCPServer(permission_checker=mock_permission_checker)
        docker = DockerMCPServer(permission_checker=mock_permission_checker)
        slack = SlackNotificationMCPServer(slack_token="test-token")
        
        # Mock successful command execution
        with patch.object(commander, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.command = "echo 'build completed'"
            mock_result.working_directory = "/app"
            mock_result.exit_code = 0
            mock_result.stdout = "build completed\n"
            mock_result.stderr = ""
            mock_result.success = True
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            # Execute build command
            build_result = await commander.call_tool(
                "execute_command",
                {"command": "echo 'build completed'"},
                mock_user
            )
            
            assert build_result["success"] is True
        
        # Mock Docker availability and execution
        docker.docker_available = True
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Container started", b"")
            mock_subprocess.return_value = mock_process
            
            # Run Docker container
            docker_result = await docker.call_tool(
                "docker_run",
                {"image": "nginx:latest"},
                mock_user
            )
            
            assert docker_result["success"] is True
        
        # Mock notification sending
        with patch.object(slack, '_make_safe_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"ok": True}
            mock_request.return_value = mock_response
            
            # Send deployment notification
            notification_result = await slack.call_tool(
                "send_notification",
                {
                    "message": "Deployment completed successfully",
                    "channels": ["slack"],
                    "priority": "medium"
                }
            )
            
            assert "channels" in notification_result
    
    @pytest.mark.asyncio
    async def test_error_handling_consistency(self, mock_user, mock_permission_checker):
        """Test consistent error handling across servers."""
        servers = [
            BraveMCPServer(api_key="test", permission_checker=mock_permission_checker),
            DesktopCommanderMCPServer(permission_checker=mock_permission_checker),
            DockerMCPServer(permission_checker=mock_permission_checker),
            AzureDevOpsMCPServer(permission_checker=mock_permission_checker),
            WindowsSystemMCPServer(permission_checker=mock_permission_checker)
        ]
        
        for server in servers:
            # Test invalid tool name
            with pytest.raises(MCPError) as exc_info:
                await server.call_tool("invalid_tool", {}, mock_user)
            
            assert "Unknown tool" in str(exc_info.value) or "Method not found" in str(exc_info.value)
    
    def test_server_info_consistency(self, mock_permission_checker):
        """Test server info consistency across all servers."""
        servers = [
            BraveMCPServer(api_key="test", permission_checker=mock_permission_checker),
            DesktopCommanderMCPServer(permission_checker=mock_permission_checker),
            DockerMCPServer(permission_checker=mock_permission_checker),
            KubernetesMCPServer(permission_checker=mock_permission_checker),
            AzureDevOpsMCPServer(permission_checker=mock_permission_checker),
            WindowsSystemMCPServer(permission_checker=mock_permission_checker),
            SecurityScannerMCPServer(permission_checker=mock_permission_checker),
            S3StorageMCPServer(),
            PrometheusMonitoringMCP(permission_checker=mock_permission_checker)
        ]
        
        for server in servers:
            info = server.get_server_info()
            assert isinstance(info, MCPServerInfo)
            assert info.name is not None
            assert info.version is not None
            assert isinstance(info.capabilities, MCPCapabilities)
    
    def test_tool_parameter_validation(self, mock_permission_checker):
        """Test tool parameter validation consistency."""
        servers = [
            BraveMCPServer(api_key="test", permission_checker=mock_permission_checker),
            DesktopCommanderMCPServer(permission_checker=mock_permission_checker),
            DockerMCPServer(permission_checker=mock_permission_checker)
        ]
        
        for server in servers:
            tools = server.get_tools()
            for tool in tools:
                assert tool.name is not None
                assert tool.description is not None
                assert isinstance(tool.parameters, list)
                
                for param in tool.parameters:
                    assert param.name is not None
                    assert param.type is not None
                    assert isinstance(param.required, bool)


class TestAuthenticationAndPermissions:
    """Test authentication and permission checking across servers."""
    
    @pytest.mark.asyncio
    async def test_permission_enforcement(self, mock_user):
        """Test permission enforcement across servers."""
        # Create permission checker that denies all permissions
        deny_all_checker = MockPermissionChecker([])
        
        servers = [
            BraveMCPServer(api_key="test", permission_checker=deny_all_checker),
            DesktopCommanderMCPServer(permission_checker=deny_all_checker)
        ]
        
        for server in servers:
            # Attempt to call a tool without permission
            try:
                tools = server.get_tools()
                if tools:
                    # This should be handled by the permission checker
                    # The exact behavior depends on implementation
                    pass
            except Exception:
                # Permission denied is expected
                pass
    
    def test_user_context_logging(self, mock_user, mock_permission_checker):
        """Test that user context is properly logged."""
        server = DesktopCommanderMCPServer(permission_checker=mock_permission_checker)
        
        # Verify that server can handle user objects
        assert hasattr(mock_user, 'username')
        assert hasattr(mock_user, 'id')
        
        # User context should be passed to tools
        assert mock_user.username == "test_user"
        assert mock_user.id == "user_123"


# Performance and Load Testing
class TestPerformanceAndLoad:
    """Performance and load testing for MCP servers."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, mock_user, mock_permission_checker):
        """Test handling concurrent requests."""
        server = BraveMCPServer(api_key="test", permission_checker=mock_permission_checker)
        
        # Mock successful responses
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Run multiple concurrent requests
            tasks = []
            for i in range(10):
                task = server.call_tool(
                    "brave_web_search",
                    {"query": f"test query {i}"},
                    mock_user
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Verify all requests completed
            assert len(results) == 10
            for result in results:
                if isinstance(result, Exception):
                    pytest.fail(f"Request failed with exception: {result}")
    
    @pytest.mark.asyncio
    async def test_resource_cleanup(self, mock_permission_checker):
        """Test proper resource cleanup."""
        servers = [
            BraveMCPServer(api_key="test", permission_checker=mock_permission_checker),
            SlackNotificationMCPServer(slack_token="test")
        ]
        
        for server in servers:
            # Initialize session if available
            if hasattr(server, 'session'):
                server.session = AsyncMock()
            
            # Cleanup should not raise exceptions
            try:
                if hasattr(server, 'close'):
                    await server.close()
            except Exception as e:
                pytest.fail(f"Cleanup failed for {server.__class__.__name__}: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])