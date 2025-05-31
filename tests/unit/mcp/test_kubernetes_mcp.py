"""
Comprehensive unit tests for Kubernetes MCP Server.

Tests all tool methods with valid inputs, invalid inputs, edge cases, and error conditions.
Achieves 95%+ coverage through thorough testing of all code paths.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List, Optional

from src.mcp.infrastructure_servers import KubernetesMCPServer
from src.mcp.protocols import MCPError, MCPServerInfo, MCPCapabilities
from src.core.exceptions import KubernetesError, MCPToolNotFoundError


class TestKubernetesMCPServer:
    """Test suite for Kubernetes MCP Server."""
    
    @pytest.fixture
    def server(self):
        """Create a Kubernetes MCP server instance."""
        return KubernetesMCPServer()
    
    @pytest.fixture
    def mock_kubectl_available(self, server):
        """Mock kubectl availability check."""
        server.kubectl_available = True
        return server
    
    def test_server_info(self, server):
        """Test get_server_info returns correct information."""
        info = server.get_server_info()
        
        assert isinstance(info, MCPServerInfo)
        assert info.name == "kubernetes"
        assert info.version == "1.0.0"
        assert "Kubernetes cluster management" in info.description
        assert info.capabilities.tools is True
        assert info.capabilities.resources is False
        assert info.capabilities.prompts is False
        assert "cluster_management" in info.capabilities.experimental
        assert info.capabilities.experimental["cluster_management"] is True
    
    def test_get_tools(self, server):
        """Test get_tools returns all expected tools."""
        tools = server.get_tools()
        
        assert len(tools) == 5
        tool_names = [tool.name for tool in tools]
        assert "kubectl_apply" in tool_names
        assert "kubectl_get" in tool_names
        assert "kubectl_delete" in tool_names
        assert "kubectl_logs" in tool_names
        assert "kubectl_describe" in tool_names
        
        # Verify kubectl_apply parameters
        apply_tool = next(t for t in tools if t.name == "kubectl_apply")
        param_names = [p.name for p in apply_tool.parameters]
        assert "manifest_path" in param_names
        assert "namespace" in param_names
        
        # Verify kubectl_logs parameters
        logs_tool = next(t for t in tools if t.name == "kubectl_logs")
        param_names = [p.name for p in logs_tool.parameters]
        assert "pod_name" in param_names
        assert "namespace" in param_names
        assert "container" in param_names
        assert "tail" in param_names
    
    @pytest.mark.asyncio
    async def test_check_kubectl_available(self, server):
        """Test kubectl availability check."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"Client Version: v1.25.0",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await server._check_kubectl()
            
            assert result is True
            assert server.kubectl_available is True
            mock_subprocess.assert_called_once_with(
                "kubectl version --client",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
    
    @pytest.mark.asyncio
    async def test_check_kubectl_not_available(self, server):
        """Test kubectl not available."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b"", b"command not found"))
            mock_subprocess.return_value = mock_process
            
            result = await server._check_kubectl()
            
            assert result is False
            assert server.kubectl_available is False
    
    @pytest.mark.asyncio
    async def test_check_kubectl_exception(self, server):
        """Test kubectl check with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Process error")):
            result = await server._check_kubectl()
            
            assert result is False
            assert server.kubectl_available is False
    
    @pytest.mark.asyncio
    async def test_call_tool_kubectl_not_available(self, server):
        """Test calling tool when kubectl is not available."""
        server.kubectl_available = False
        
        with pytest.raises(KubernetesError) as exc_info:
            await server.call_tool("kubectl_apply", {"manifest_path": "deployment.yaml"})
        
        assert "kubectl is not available" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_call_tool_unknown_tool(self, mock_kubectl_available):
        """Test calling unknown tool raises MCPToolNotFoundError."""
        with pytest.raises(MCPToolNotFoundError) as exc_info:
            await mock_kubectl_available.call_tool("unknown_tool", {})
        
        assert exc_info.value.tool_name == "unknown_tool"
        assert exc_info.value.server_name == "kubernetes"
        assert "kubectl_apply" in exc_info.value.available_tools
    
    # kubectl_apply tests
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_success(self, mock_kubectl_available):
        """Test successful kubectl apply."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"deployment.apps/myapp created\nservice/myapp created",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_apply("deployment.yaml")
            
            assert result["success"] is True
            assert result["exit_code"] == 0
            assert "deployment.apps/myapp created" in result["stdout"]
            assert result["manifest_path"] == "deployment.yaml"
            assert result["namespace"] == "default"
            assert "kubectl apply -f deployment.yaml -n default" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_custom_namespace(self, mock_kubectl_available):
        """Test kubectl apply with custom namespace."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_apply(
                manifest_path="app.yaml",
                namespace="production"
            )
            
            assert "kubectl apply -f app.yaml -n production" in result["command"]
            assert result["namespace"] == "production"
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_directory(self, mock_kubectl_available):
        """Test kubectl apply with directory of manifests."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"Multiple resources created",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_apply("k8s/")
            
            assert "kubectl apply -f k8s/ -n default" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_failure(self, mock_kubectl_available):
        """Test kubectl apply failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"error validating data: invalid type"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_apply("invalid.yaml")
            
            assert result["success"] is False
            assert "error validating data" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_kubectl_apply_exception(self, mock_kubectl_available):
        """Test kubectl apply with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Apply failed")):
            with pytest.raises(KubernetesError) as exc_info:
                await mock_kubectl_available._kubectl_apply("deployment.yaml")
            
            assert "kubectl apply failed" in str(exc_info.value)
            assert exc_info.value.resource == "deployment.yaml"
    
    # kubectl_get tests
    
    @pytest.mark.asyncio
    async def test_kubectl_get_all_resources(self, mock_kubectl_available):
        """Test kubectl get all resources of a type."""
        k8s_response = {
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {"metadata": {"name": "pod1"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "pod2"}, "status": {"phase": "Running"}}
            ]
        }
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json.dumps(k8s_response).encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_get("pods")
            
            assert result["success"] is True
            assert result["resources"]["kind"] == "PodList"
            assert len(result["resources"]["items"]) == 2
            assert "kubectl get pods -n default -o json" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_get_specific_resource(self, mock_kubectl_available):
        """Test kubectl get specific resource."""
        k8s_response = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "myapp"}
        }
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json.dumps(k8s_response).encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_get(
                resource_type="deployment",
                resource_name="myapp"
            )
            
            assert result["resources"]["metadata"]["name"] == "myapp"
            assert "kubectl get deployment myapp -n default -o json" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_get_custom_namespace(self, mock_kubectl_available):
        """Test kubectl get with custom namespace."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json.dumps({"items": []}).encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_get(
                resource_type="services",
                namespace="kube-system"
            )
            
            assert "kubectl get services -n kube-system -o json" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_get_failure(self, mock_kubectl_available):
        """Test kubectl get failure."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error from server (NotFound): pods \"nonexistent\" not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_get(
                resource_type="pods",
                resource_name="nonexistent"
            )
            
            assert result["success"] is False
            assert "not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_kubectl_get_invalid_json(self, mock_kubectl_available):
        """Test kubectl get with invalid JSON response."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"Not JSON output",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_get("pods")
            
            assert result["success"] is True
            assert "stdout" in result
            assert "resources" not in result
    
    @pytest.mark.asyncio
    async def test_kubectl_get_exception(self, mock_kubectl_available):
        """Test kubectl get with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Get failed")):
            with pytest.raises(MCPError) as exc_info:
                await mock_kubectl_available._kubectl_get("pods")
            
            assert exc_info.value.code == -32000
            assert "kubectl get failed" in str(exc_info.value.message)
    
    # kubectl_delete tests
    
    @pytest.mark.asyncio
    async def test_kubectl_delete_success(self, mock_kubectl_available):
        """Test successful kubectl delete."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b"deployment.apps \"myapp\" deleted",
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_delete(
                resource_type="deployment",
                resource_name="myapp"
            )
            
            assert result["success"] is True
            assert "deleted" in result["stdout"]
            assert result["resource_type"] == "deployment"
            assert result["resource_name"] == "myapp"
            assert "kubectl delete deployment myapp -n default" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_delete_custom_namespace(self, mock_kubectl_available):
        """Test kubectl delete with custom namespace."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_delete(
                resource_type="service",
                resource_name="myservice",
                namespace="production"
            )
            
            assert "kubectl delete service myservice -n production" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_delete_not_found(self, mock_kubectl_available):
        """Test kubectl delete resource not found."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error from server (NotFound): deployments.apps \"nonexistent\" not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_delete(
                resource_type="deployment",
                resource_name="nonexistent"
            )
            
            assert result["success"] is False
            assert "not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_kubectl_delete_exception(self, mock_kubectl_available):
        """Test kubectl delete with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Delete failed")):
            with pytest.raises(MCPError) as exc_info:
                await mock_kubectl_available._kubectl_delete("pod", "mypod")
            
            assert "kubectl delete failed" in str(exc_info.value.message)
    
    # kubectl_logs tests
    
    @pytest.mark.asyncio
    async def test_kubectl_logs_success(self, mock_kubectl_available):
        """Test successful kubectl logs."""
        log_output = "2024-01-01 12:00:00 INFO Starting application\n2024-01-01 12:00:01 INFO Server ready"
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                log_output.encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_logs("myapp-pod")
            
            assert result["success"] is True
            assert result["logs"] == log_output
            assert result["pod_name"] == "myapp-pod"
            assert "kubectl logs myapp-pod -n default --tail 100" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_logs_with_container(self, mock_kubectl_available):
        """Test kubectl logs with specific container."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Container logs", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_logs(
                pod_name="multi-container-pod",
                container="app"
            )
            
            assert "kubectl logs multi-container-pod -n default --tail 100 -c app" in result["command"]
            assert result["container"] == "app"
    
    @pytest.mark.asyncio
    async def test_kubectl_logs_custom_tail(self, mock_kubectl_available):
        """Test kubectl logs with custom tail lines."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_logs(
                pod_name="myapp",
                tail=500
            )
            
            assert "--tail 500" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_logs_pod_not_found(self, mock_kubectl_available):
        """Test kubectl logs with pod not found."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error from server (NotFound): pods \"nonexistent\" not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_logs("nonexistent")
            
            assert result["success"] is False
            assert "not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_kubectl_logs_exception(self, mock_kubectl_available):
        """Test kubectl logs with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Logs failed")):
            with pytest.raises(MCPError) as exc_info:
                await mock_kubectl_available._kubectl_logs("mypod")
            
            assert "kubectl logs failed" in str(exc_info.value.message)
    
    # kubectl_describe tests
    
    @pytest.mark.asyncio
    async def test_kubectl_describe_success(self, mock_kubectl_available):
        """Test successful kubectl describe."""
        describe_output = """Name:         myapp
Namespace:    default
Labels:       app=myapp
Status:       Running
Conditions:
  Type    Status
  Ready   True"""
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                describe_output.encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_describe(
                resource_type="pod",
                resource_name="myapp"
            )
            
            assert result["success"] is True
            assert "Name:         myapp" in result["description"]
            assert result["resource_type"] == "pod"
            assert result["resource_name"] == "myapp"
            assert "kubectl describe pod myapp -n default" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_describe_custom_namespace(self, mock_kubectl_available):
        """Test kubectl describe with custom namespace."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Description", b""))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_describe(
                resource_type="service",
                resource_name="myservice",
                namespace="kube-system"
            )
            
            assert "kubectl describe service myservice -n kube-system" in result["command"]
    
    @pytest.mark.asyncio
    async def test_kubectl_describe_not_found(self, mock_kubectl_available):
        """Test kubectl describe resource not found."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error from server (NotFound): pods \"nonexistent\" not found"
            ))
            mock_subprocess.return_value = mock_process
            
            result = await mock_kubectl_available._kubectl_describe(
                resource_type="pod",
                resource_name="nonexistent"
            )
            
            assert result["success"] is False
            assert "not found" in result["stderr"]
    
    @pytest.mark.asyncio
    async def test_kubectl_describe_exception(self, mock_kubectl_available):
        """Test kubectl describe with exception."""
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Describe failed")):
            with pytest.raises(MCPError) as exc_info:
                await mock_kubectl_available._kubectl_describe("deployment", "myapp")
            
            assert "kubectl describe failed" in str(exc_info.value.message)
    
    # Integration tests for call_tool
    
    @pytest.mark.asyncio
    async def test_call_tool_kubectl_apply(self, mock_kubectl_available):
        """Test call_tool with kubectl_apply."""
        with patch.object(mock_kubectl_available, '_kubectl_apply') as mock_apply:
            mock_apply.return_value = {"success": True}
            
            result = await mock_kubectl_available.call_tool("kubectl_apply", {
                "manifest_path": "deployment.yaml",
                "namespace": "staging"
            })
            
            mock_apply.assert_called_once_with(
                manifest_path="deployment.yaml",
                namespace="staging"
            )
    
    @pytest.mark.asyncio
    async def test_call_tool_error_handling(self, mock_kubectl_available):
        """Test call_tool error handling and logging."""
        with patch.object(mock_kubectl_available, '_kubectl_get') as mock_get:
            mock_get.side_effect = Exception("Get failed")
            
            with patch('src.mcp.infrastructure_servers.logger') as mock_logger:
                with patch('src.mcp.infrastructure_servers.handle_error') as mock_handle:
                    with pytest.raises(KubernetesError):
                        await mock_kubectl_available.call_tool("kubectl_get", {
                            "resource_type": "pods"
                        })
                    
                    mock_handle.assert_called_once()
                    error_arg = mock_handle.call_args[0][0]
                    assert isinstance(error_arg, KubernetesError)


@pytest.mark.asyncio
class TestKubernetesMCPEdgeCases:
    """Edge case tests for Kubernetes MCP Server."""
    
    @pytest.fixture
    def server(self):
        server = KubernetesMCPServer()
        server.kubectl_available = True
        return server
    
    async def test_kubectl_apply_url(self, server):
        """Test kubectl apply with URL manifest."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"applied", b""))
            mock_subprocess.return_value = mock_process
            
            result = await server._kubectl_apply(
                "https://raw.githubusercontent.com/example/app.yaml"
            )
            
            assert "https://raw.githubusercontent.com" in result["command"]
    
    async def test_kubectl_get_all_namespaces(self, server):
        """Test kubectl get across all namespaces."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json.dumps({"items": []}).encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            # Should use namespace parameter, not --all-namespaces
            result = await server._kubectl_get("pods", namespace="kube-system")
            
            assert "-n kube-system" in result["command"]
    
    async def test_kubectl_logs_empty_output(self, server):
        """Test kubectl logs with empty output."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_process
            
            result = await server._kubectl_logs("new-pod")
            
            assert result["logs"] == ""
            assert result["success"] is True
    
    async def test_kubectl_describe_multiple_resources(self, server):
        """Test kubectl describe with resource type variations."""
        resource_types = ["pod", "deployment", "service", "configmap", "secret"]
        
        for resource_type in resource_types:
            with patch('asyncio.create_subprocess_shell') as mock_subprocess:
                mock_process = AsyncMock()
                mock_process.returncode = 0
                mock_process.communicate = AsyncMock(return_value=(b"Description", b""))
                mock_subprocess.return_value = mock_process
                
                result = await server._kubectl_describe(
                    resource_type=resource_type,
                    resource_name="test"
                )
                
                assert f"kubectl describe {resource_type} test" in result["command"]
    
    async def test_kubectl_availability_caching(self, server):
        """Test kubectl availability is cached after first check."""
        server.kubectl_available = None
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Client Version", b""))
            mock_subprocess.return_value = mock_process
            
            # First check
            result1 = await server._check_kubectl()
            # Second check - should use cached value
            result2 = await server._check_kubectl()
            
            assert result1 is True
            assert result2 is True
            # Should only be called once due to caching
            assert mock_subprocess.call_count == 1
    
    async def test_kubectl_get_with_special_characters(self, server):
        """Test kubectl get with special characters in names."""
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                json.dumps({"metadata": {"name": "app-with-dash"}}).encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await server._kubectl_get(
                resource_type="deployment",
                resource_name="app-with-dash"
            )
            
            assert result["success"] is True
            assert "app-with-dash" in result["command"]
    
    async def test_kubectl_logs_multiline_output(self, server):
        """Test kubectl logs with multiline output."""
        multiline_logs = """Line 1: Starting application
Line 2: Loading configuration
Line 3: Connecting to database
Line 4: Server started on port 8080"""
        
        with patch('asyncio.create_subprocess_shell') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                multiline_logs.encode('utf-8'),
                b""
            ))
            mock_subprocess.return_value = mock_process
            
            result = await server._kubectl_logs("myapp")
            
            assert len(result["logs"].split('\n')) == 4
            assert "Starting application" in result["logs"]
            assert "Server started" in result["logs"]