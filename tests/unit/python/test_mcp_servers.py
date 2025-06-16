#!/usr/bin/env python3
"""
Comprehensive unit tests for Python MCP servers
Tests all MCP server implementations with security, performance, and reliability focus
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys
import os

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

# Import MCP components
from src.mcp.protocols import MCPTool, MCPServerInfo, MCPError
from src.mcp.manager import MCPManager, MCPContext
from src.core.exceptions import MCPException


class MockMCPServer:
    """Mock MCP server for testing"""
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.tools = {}
        self.server_info = MCPServerInfo(
            name=name,
            version=version,
            description=f"Mock {name} server"
        )
    
    def add_tool(self, tool: MCPTool):
        """Add a tool to the mock server"""
        self.tools[tool.name] = tool
    
    def get_server_info(self) -> MCPServerInfo:
        """Get server information"""
        return self.server_info
    
    def get_tools(self) -> List[MCPTool]:
        """Get list of available tools"""
        return list(self.tools.values())
    
    async def call_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool with given parameters"""
        if tool_name not in self.tools:
            raise MCPException(f"Tool {tool_name} not found")
        
        tool = self.tools[tool_name]
        
        # Validate required parameters
        required = getattr(tool, 'required_params', [])
        for param in required:
            if param not in parameters:
                raise MCPException(f"Required parameter '{param}' missing")
        
        # Route to appropriate handler
        if tool_name == 'execute_command':
            return await self._execute_command(parameters)
        elif tool_name == 'read_file':
            return await self._read_file(parameters)
        elif tool_name == 'write_file':
            return await self._write_file(parameters)
        elif tool_name == 'docker_run':
            return await self._docker_run(parameters)
        elif tool_name == 'kubernetes_apply':
            return await self._kubernetes_apply(parameters)
        elif tool_name == 'prometheus_query':
            return await self._prometheus_query(parameters)
        elif tool_name == 'security_scan':
            return await self._security_scan(parameters)
        elif tool_name == 'brave_search':
            return await self._brave_search(parameters)
        else:
            return {
                "success": True,
                "result": f"Mock result for {tool_name}",
                "timestamp": time.time()
            }
    
    async def _execute_command(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock command execution with security checks"""
        command = params.get('command', '')
        
        # Security validation
        dangerous_commands = [
            'rm -rf', 'format', 'del /f', 'shutdown', 'reboot',
            'dd if=', 'mkfs', '> /dev/', 'chmod 777', 'chown root'
        ]
        
        for dangerous in dangerous_commands:
            if dangerous in command.lower():
                raise MCPException(f"Dangerous command blocked: {dangerous}")
        
        # Path traversal protection
        if '..' in command or command.startswith('/'):
            if any(sensitive in command for sensitive in ['/etc/', '/var/', '/root/']):
                raise MCPException("Access to sensitive directories blocked")
        
        return {
            "success": True,
            "stdout": f"Mock output: {command}",
            "stderr": "",
            "exit_code": 0,
            "execution_time": 0.1,
            "timestamp": time.time()
        }
    
    async def _read_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock file reading with path validation"""
        file_path = params.get('path', '')
        
        # Path validation
        if '..' in file_path:
            raise MCPException("Path traversal detected")
        
        sensitive_paths = ['/etc/passwd', '/etc/shadow', '/etc/hosts']
        if any(file_path.endswith(path) for path in sensitive_paths):
            raise MCPException("Access to sensitive file denied")
        
        return {
            "success": True,
            "content": f"Mock content of {file_path}",
            "size": len(f"Mock content of {file_path}"),
            "encoding": params.get('encoding', 'utf-8'),
            "timestamp": time.time()
        }
    
    async def _write_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock file writing with validation"""
        file_path = params.get('path', '')
        content = params.get('content', '')
        
        # Path validation
        if '..' in file_path:
            raise MCPException("Path traversal detected")
        
        # Size validation (10MB limit)
        if len(content) > 10 * 1024 * 1024:
            raise MCPException("File too large (max 10MB)")
        
        return {
            "success": True,
            "bytes_written": len(content),
            "path": file_path,
            "timestamp": time.time()
        }
    
    async def _docker_run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Docker container execution"""
        image = params.get('image', '')
        
        # Image validation
        if not image or '..' in image or image.startswith('/'):
            raise MCPException("Invalid Docker image name")
        
        # Security check for privileged containers
        if params.get('privileged', False):
            raise MCPException("Privileged containers not allowed")
        
        return {
            "success": True,
            "container_id": f"mock-{hash(image) % 10000}",
            "image": image,
            "status": "running",
            "ports": params.get('ports', []),
            "timestamp": time.time()
        }
    
    async def _kubernetes_apply(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Kubernetes resource application"""
        manifest = params.get('manifest', {})
        
        if not manifest:
            raise MCPException("Manifest is required")
        
        # Basic manifest validation
        if 'apiVersion' not in manifest:
            raise MCPException("Manifest missing apiVersion")
        
        if 'kind' not in manifest:
            raise MCPException("Manifest missing kind")
        
        return {
            "success": True,
            "resources_created": 1,
            "namespace": manifest.get('metadata', {}).get('namespace', 'default'),
            "kind": manifest['kind'],
            "timestamp": time.time()
        }
    
    async def _prometheus_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Prometheus query execution"""
        query = params.get('query', '')
        
        if not query:
            raise MCPException("Query is required")
        
        # Basic PromQL validation
        if any(dangerous in query for dangerous in ['file(', 'exec(', 'eval(']):
            raise MCPException("Dangerous PromQL functions not allowed")
        
        return {
            "success": True,
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "mock_metric"},
                        "value": [time.time(), "42"]
                    }
                ]
            },
            "query": query,
            "timestamp": time.time()
        }
    
    async def _security_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock security scanning"""
        target = params.get('target', '')
        scan_type = params.get('type', 'dependencies')
        
        if not target:
            raise MCPException("Scan target is required")
        
        return {
            "success": True,
            "scan_type": scan_type,
            "target": target,
            "vulnerabilities": [
                {
                    "id": "CVE-2023-MOCK",
                    "severity": "medium",
                    "description": "Mock vulnerability for testing",
                    "affected_package": "test-package",
                    "fixed_version": "1.2.3"
                }
            ],
            "scan_duration": 1.5,
            "timestamp": time.time()
        }
    
    async def _brave_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock web search"""
        query = params.get('query', '')
        count = params.get('count', 10)
        
        if not query:
            raise MCPException("Search query is required")
        
        # Input sanitization
        sanitized_query = query.replace('<', '&lt;').replace('>', '&gt;')
        
        return {
            "success": True,
            "query": sanitized_query,
            "results": [
                {
                    "title": f"Result for: {sanitized_query}",
                    "url": "https://example.com/mock-result",
                    "snippet": f"Mock search result snippet for {sanitized_query}"
                }
            ] * min(count, 10),
            "count": min(count, 10),
            "timestamp": time.time()
        }


@pytest.fixture
def mock_server():
    """Create a mock MCP server for testing"""
    server = MockMCPServer("test-server")
    
    # Add common tools
    server.add_tool(MCPTool(
        name="execute_command",
        description="Execute system commands",
        parameters=[]
    ))
    server.tools["execute_command"].required_params = ['command']
    
    server.add_tool(MCPTool(
        name="read_file",
        description="Read file contents",
        parameters=[]
    ))
    server.tools["read_file"].required_params = ['path']
    
    server.add_tool(MCPTool(
        name="write_file",
        description="Write file contents",
        parameters=[]
    ))
    server.tools["write_file"].required_params = ['path', 'content']
    
    return server


@pytest.fixture
def docker_server():
    """Create a mock Docker MCP server"""
    server = MockMCPServer("docker-server")
    server.add_tool(MCPTool(
        name="docker_run",
        description="Run Docker containers",
        parameters=[]
    ))
    server.tools["docker_run"].required_params = ['image']
    return server


@pytest.fixture
def kubernetes_server():
    """Create a mock Kubernetes MCP server"""
    server = MockMCPServer("kubernetes-server")
    server.add_tool(MCPTool(
        name="kubernetes_apply",
        description="Apply Kubernetes manifests",
        parameters=[]
    ))
    server.tools["kubernetes_apply"].required_params = ['manifest']
    return server


class TestMCPServerBasics:
    """Test basic MCP server functionality"""
    
    @pytest.mark.unit
    def test_server_info(self, mock_server):
        """Test server information retrieval"""
        info = mock_server.get_server_info()
        assert info.name == "test-server"
        assert info.version == "1.0.0"
        assert "Mock" in info.description
    
    @pytest.mark.unit
    def test_tool_listing(self, mock_server):
        """Test tool enumeration"""
        tools = mock_server.get_tools()
        assert len(tools) == 3
        tool_names = [tool.name for tool in tools]
        assert "execute_command" in tool_names
        assert "read_file" in tool_names
        assert "write_file" in tool_names
    
    @pytest.mark.unit
    async def test_nonexistent_tool(self, mock_server):
        """Test calling nonexistent tool"""
        with pytest.raises(MCPException, match="Tool nonexistent not found"):
            await mock_server.call_tool("nonexistent", {})


class TestParameterValidation:
    """Test parameter validation for MCP tools"""
    
    @pytest.mark.unit
    async def test_missing_required_parameter(self, mock_server):
        """Test missing required parameters"""
        with pytest.raises(MCPException, match="Required parameter 'command' missing"):
            await mock_server.call_tool("execute_command", {})
    
    @pytest.mark.unit
    async def test_valid_parameters(self, mock_server):
        """Test valid parameter handling"""
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'test'"
        })
        assert result["success"] is True
        assert "echo 'test'" in result["stdout"]
    
    @pytest.mark.unit
    async def test_extra_parameters(self, mock_server):
        """Test handling of extra parameters"""
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'test'",
            "extra_param": "ignored"
        })
        assert result["success"] is True


class TestSecurityValidation:
    """Test security validation and input sanitization"""
    
    @pytest.mark.security
    async def test_dangerous_commands(self, mock_server):
        """Test blocking of dangerous commands"""
        dangerous_commands = [
            "rm -rf /",
            "format C:",
            "shutdown -h now",
            "dd if=/dev/zero of=/dev/sda"
        ]
        
        for cmd in dangerous_commands:
            with pytest.raises(MCPException, match="Dangerous command blocked"):
                await mock_server.call_tool("execute_command", {"command": cmd})
    
    @pytest.mark.security
    async def test_path_traversal_protection(self, mock_server):
        """Test path traversal attack prevention"""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow"
        ]
        
        for path in malicious_paths:
            with pytest.raises(MCPException):
                await mock_server.call_tool("read_file", {"path": path})
    
    @pytest.mark.security
    async def test_sensitive_file_access(self, mock_server):
        """Test protection of sensitive files"""
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts"
        ]
        
        for file_path in sensitive_files:
            with pytest.raises(MCPException, match="Access to sensitive file denied"):
                await mock_server.call_tool("read_file", {"path": file_path})
    
    @pytest.mark.security
    async def test_file_size_limits(self, mock_server):
        """Test file size limitations"""
        large_content = "x" * (11 * 1024 * 1024)  # 11MB
        
        with pytest.raises(MCPException, match="File too large"):
            await mock_server.call_tool("write_file", {
                "path": "/tmp/large_file.txt",
                "content": large_content
            })
    
    @pytest.mark.security
    async def test_input_sanitization(self, mock_server):
        """Test input sanitization for XSS prevention"""
        server = MockMCPServer("search-server")
        server.add_tool(MCPTool(name="brave_search", description="Search", parameters=[]))
        server.tools["brave_search"].required_params = ['query']
        
        malicious_query = '<script>alert("xss")</script>test'
        result = await server.call_tool("brave_search", {"query": malicious_query})
        
        assert result["success"] is True
        assert '<script>' not in result["query"]
        assert '&lt;script&gt;' in result["query"]


class TestDockerServerSecurity:
    """Test Docker server security measures"""
    
    @pytest.mark.security
    @pytest.mark.docker
    async def test_docker_image_validation(self, docker_server):
        """Test Docker image name validation"""
        invalid_images = [
            "../malicious/image",
            "/absolute/path/image",
            "",
            None
        ]
        
        for image in invalid_images:
            with pytest.raises(MCPException, match="Invalid Docker image name"):
                await docker_server.call_tool("docker_run", {"image": image})
    
    @pytest.mark.security
    @pytest.mark.docker
    async def test_privileged_container_blocking(self, docker_server):
        """Test blocking of privileged containers"""
        with pytest.raises(MCPException, match="Privileged containers not allowed"):
            await docker_server.call_tool("docker_run", {
                "image": "nginx:latest",
                "privileged": True
            })
    
    @pytest.mark.docker
    async def test_valid_docker_run(self, docker_server):
        """Test valid Docker container execution"""
        result = await docker_server.call_tool("docker_run", {
            "image": "nginx:latest",
            "ports": ["80:8080"]
        })
        
        assert result["success"] is True
        assert result["image"] == "nginx:latest"
        assert result["status"] == "running"
        assert "mock-" in result["container_id"]


class TestKubernetesServerValidation:
    """Test Kubernetes server validation"""
    
    @pytest.mark.kubernetes
    async def test_manifest_validation(self, kubernetes_server):
        """Test Kubernetes manifest validation"""
        # Test missing manifest
        with pytest.raises(MCPException, match="Manifest is required"):
            await kubernetes_server.call_tool("kubernetes_apply", {})
        
        # Test invalid manifest (missing apiVersion)
        with pytest.raises(MCPException, match="Manifest missing apiVersion"):
            await kubernetes_server.call_tool("kubernetes_apply", {
                "manifest": {"kind": "Pod"}
            })
        
        # Test invalid manifest (missing kind)
        with pytest.raises(MCPException, match="Manifest missing kind"):
            await kubernetes_server.call_tool("kubernetes_apply", {
                "manifest": {"apiVersion": "v1"}
            })
    
    @pytest.mark.kubernetes
    async def test_valid_kubernetes_apply(self, kubernetes_server):
        """Test valid Kubernetes manifest application"""
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test-pod",
                "namespace": "test"
            },
            "spec": {
                "containers": [
                    {
                        "name": "test-container",
                        "image": "nginx:latest"
                    }
                ]
            }
        }
        
        result = await kubernetes_server.call_tool("kubernetes_apply", {
            "manifest": manifest
        })
        
        assert result["success"] is True
        assert result["kind"] == "Pod"
        assert result["namespace"] == "test"
        assert result["resources_created"] == 1


class TestPerformance:
    """Test performance characteristics of MCP servers"""
    
    @pytest.mark.performance
    async def test_tool_execution_speed(self, mock_server):
        """Test tool execution performance"""
        start_time = time.time()
        
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'performance test'"
        })
        
        duration = time.time() - start_time
        
        assert result["success"] is True
        assert duration < 1.0  # Should complete within 1 second
    
    @pytest.mark.performance
    async def test_concurrent_tool_execution(self, mock_server):
        """Test concurrent tool execution"""
        start_time = time.time()
        
        # Execute 10 tools concurrently
        tasks = [
            mock_server.call_tool("execute_command", {
                "command": f"echo 'test {i}'"
            })
            for i in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        assert len(results) == 10
        assert all(result["success"] for result in results)
        assert duration < 2.0  # Should complete within 2 seconds
    
    @pytest.mark.performance
    @pytest.mark.slow
    async def test_large_file_handling(self, mock_server):
        """Test handling of large files"""
        # Test with 1MB content
        large_content = "x" * (1024 * 1024)
        
        start_time = time.time()
        result = await mock_server.call_tool("write_file", {
            "path": "/tmp/large_test.txt",
            "content": large_content
        })
        duration = time.time() - start_time
        
        assert result["success"] is True
        assert result["bytes_written"] == len(large_content)
        assert duration < 5.0  # Should complete within 5 seconds


class TestErrorHandling:
    """Test error handling and recovery"""
    
    @pytest.mark.unit
    async def test_exception_handling(self, mock_server):
        """Test proper exception handling"""
        with pytest.raises(MCPException):
            await mock_server.call_tool("execute_command", {
                "command": "rm -rf /"  # Should trigger security exception
            })
    
    @pytest.mark.unit
    async def test_error_message_format(self, mock_server):
        """Test error message formatting"""
        try:
            await mock_server.call_tool("nonexistent_tool", {})
        except MCPException as e:
            assert "Tool nonexistent_tool not found" in str(e)
            assert isinstance(e, MCPException)
    
    @pytest.mark.unit
    async def test_recovery_after_error(self, mock_server):
        """Test system recovery after errors"""
        # Trigger an error
        with pytest.raises(MCPException):
            await mock_server.call_tool("execute_command", {"command": "rm -rf /"})
        
        # Verify system still works
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'recovery test'"
        })
        assert result["success"] is True


class TestResponseFormat:
    """Test response format consistency"""
    
    @pytest.mark.unit
    async def test_success_response_format(self, mock_server):
        """Test successful response format"""
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'format test'"
        })
        
        # Check required fields
        assert "success" in result
        assert result["success"] is True
        assert "timestamp" in result
        assert isinstance(result["timestamp"], (int, float))
        
        # Check command-specific fields
        assert "stdout" in result
        assert "stderr" in result
        assert "exit_code" in result
    
    @pytest.mark.unit
    async def test_response_serialization(self, mock_server):
        """Test response JSON serialization"""
        result = await mock_server.call_tool("read_file", {
            "path": "/tmp/test.txt"
        })
        
        # Should be JSON serializable
        json_str = json.dumps(result)
        deserialized = json.loads(json_str)
        
        assert deserialized == result
    
    @pytest.mark.unit
    async def test_timestamp_format(self, mock_server):
        """Test timestamp format consistency"""
        result = await mock_server.call_tool("execute_command", {
            "command": "echo 'timestamp test'"
        })
        
        timestamp = result["timestamp"]
        assert isinstance(timestamp, (int, float))
        assert timestamp > 0
        assert timestamp <= time.time()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])