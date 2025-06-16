#!/usr/bin/env python3
"""
Comprehensive mock implementations for all MCP servers
Provides realistic test doubles for unit and integration testing
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Union
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass, field
from enum import Enum
import tempfile
import os
import re
from pathlib import Path


class MockServerType(Enum):
    """Types of MCP servers"""
    INFRASTRUCTURE = "infrastructure"
    DEVOPS = "devops"
    MONITORING = "monitoring"
    SECURITY = "security"
    COMMUNICATION = "communication"
    STORAGE = "storage"
    SEARCH = "search"


@dataclass
class MockToolDefinition:
    """Definition of a mock tool"""
    name: str
    description: str
    parameters: List[Dict[str, Any]]
    required_params: List[str] = field(default_factory=list)
    security_level: str = "medium"
    execution_time_ms: int = 100
    failure_rate: float = 0.0


@dataclass
class MockServerConfig:
    """Configuration for a mock server"""
    name: str
    version: str = "1.0.0"
    description: str = ""
    server_type: MockServerType = MockServerType.INFRASTRUCTURE
    tools: List[MockToolDefinition] = field(default_factory=list)
    latency_ms: int = 50
    error_rate: float = 0.0
    rate_limit: int = 100  # requests per second


class BaseMockMCPServer:
    """Base class for all mock MCP servers"""
    
    def __init__(self, config: MockServerConfig):
        self.config = config
        self.name = config.name
        self.version = config.version
        self.tools = {tool.name: tool for tool in config.tools}
        self.request_count = 0
        self.error_count = 0
        self.start_time = time.time()
        self.last_request_time = 0
        self.temp_files = []
        
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.config.description or f"Mock {self.name} server",
            "type": self.config.server_type.value,
            "uptime": time.time() - self.start_time,
            "request_count": self.request_count,
            "error_count": self.error_count
        }
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools"""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
                "security_level": tool.security_level
            }
            for tool in self.tools.values()
        ]
    
    async def call_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool with given parameters"""
        start_time = time.time()
        self.request_count += 1
        self.last_request_time = start_time
        
        # Rate limiting check
        if self._should_rate_limit():
            raise Exception("Rate limit exceeded")
        
        # Check if tool exists
        if tool_name not in self.tools:
            self.error_count += 1
            raise Exception(f"Tool {tool_name} not found")
        
        tool = self.tools[tool_name]
        
        # Simulate latency
        await asyncio.sleep(self.config.latency_ms / 1000.0)
        
        # Simulate tool execution time
        await asyncio.sleep(tool.execution_time_ms / 1000.0)
        
        # Simulate random failures
        if self._should_fail() or self._should_tool_fail(tool):
            self.error_count += 1
            raise Exception(f"Mock failure in {tool_name}")
        
        # Validate parameters
        self._validate_parameters(tool, parameters)
        
        # Execute tool
        result = await self._execute_tool(tool_name, parameters)
        
        execution_time = (time.time() - start_time) * 1000
        
        return {
            "success": True,
            "result": result,
            "execution_time_ms": execution_time,
            "timestamp": time.time(),
            "request_id": str(uuid.uuid4())
        }
    
    def _should_rate_limit(self) -> bool:
        """Check if request should be rate limited"""
        current_time = time.time()
        time_window = 1.0  # 1 second window
        
        # Simple rate limiting logic
        recent_requests = getattr(self, '_recent_requests', [])
        recent_requests = [t for t in recent_requests if current_time - t < time_window]
        recent_requests.append(current_time)
        self._recent_requests = recent_requests
        
        return len(recent_requests) > self.config.rate_limit
    
    def _should_fail(self) -> bool:
        """Check if request should fail"""
        import random
        return random.random() < self.config.error_rate
    
    def _should_tool_fail(self, tool: MockToolDefinition) -> bool:
        """Check if specific tool should fail"""
        import random
        return random.random() < tool.failure_rate
    
    def _validate_parameters(self, tool: MockToolDefinition, parameters: Dict[str, Any]):
        """Validate tool parameters"""
        for param in tool.required_params:
            if param not in parameters:
                raise Exception(f"Required parameter '{param}' missing for tool {tool.name}")
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific tool - to be overridden by subclasses"""
        return {
            "message": f"Mock execution of {tool_name}",
            "parameters": parameters
        }
    
    def cleanup(self):
        """Clean up resources"""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
        self.temp_files.clear()


class MockDesktopCommanderServer(BaseMockMCPServer):
    """Mock desktop commander MCP server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="desktop-commander",
            description="Desktop command execution and file management",
            server_type=MockServerType.INFRASTRUCTURE,
            tools=[
                MockToolDefinition(
                    name="execute_command",
                    description="Execute system commands",
                    parameters=[
                        {"name": "command", "type": "string", "description": "Command to execute"},
                        {"name": "timeout", "type": "number", "description": "Timeout in seconds"}
                    ],
                    required_params=["command"],
                    security_level="high"
                ),
                MockToolDefinition(
                    name="read_file",
                    description="Read file contents",
                    parameters=[
                        {"name": "path", "type": "string", "description": "File path"},
                        {"name": "encoding", "type": "string", "description": "File encoding"}
                    ],
                    required_params=["path"]
                ),
                MockToolDefinition(
                    name="write_file",
                    description="Write file contents",
                    parameters=[
                        {"name": "path", "type": "string", "description": "File path"},
                        {"name": "content", "type": "string", "description": "File content"},
                        {"name": "encoding", "type": "string", "description": "File encoding"}
                    ],
                    required_params=["path", "content"]
                ),
                MockToolDefinition(
                    name="list_directory",
                    description="List directory contents",
                    parameters=[
                        {"name": "path", "type": "string", "description": "Directory path"}
                    ],
                    required_params=["path"]
                )
            ]
        )
        super().__init__(config)
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute desktop commander tools"""
        if tool_name == "execute_command":
            return await self._execute_command(parameters)
        elif tool_name == "read_file":
            return await self._read_file(parameters)
        elif tool_name == "write_file":
            return await self._write_file(parameters)
        elif tool_name == "list_directory":
            return await self._list_directory(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _execute_command(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock command execution with security checks"""
        command = params["command"]
        timeout = params.get("timeout", 30)
        
        # Security validation
        dangerous_commands = ["rm -rf", "format", "del /f", "shutdown", "reboot"]
        if any(dangerous in command.lower() for dangerous in dangerous_commands):
            raise Exception(f"Dangerous command blocked: {command}")
        
        # Simulate command output
        if "echo" in command:
            output = command.replace("echo", "").strip().strip('"\'')
        elif "ls" in command or "dir" in command:
            output = "file1.txt\nfile2.txt\ndirectory1/"
        elif "pwd" in command or "cd" in command:
            output = "/mock/current/directory"
        else:
            output = f"Mock output for: {command}"
        
        return {
            "stdout": output,
            "stderr": "",
            "exit_code": 0,
            "command": command,
            "timeout": timeout
        }
    
    async def _read_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock file reading with path validation"""
        path = params["path"]
        encoding = params.get("encoding", "utf-8")
        
        # Path validation
        if ".." in path or path.startswith("/etc/") or path.startswith("/var/"):
            raise Exception("Invalid or dangerous file path")
        
        # Simulate file content
        content = f"Mock content of {path}\nLine 2\nLine 3"
        
        return {
            "content": content,
            "path": path,
            "size": len(content),
            "encoding": encoding,
            "lines": len(content.split('\n'))
        }
    
    async def _write_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock file writing"""
        path = params["path"]
        content = params["content"]
        encoding = params.get("encoding", "utf-8")
        
        # Path validation
        if ".." in path or path.startswith("/etc/") or path.startswith("/var/"):
            raise Exception("Invalid or dangerous file path")
        
        # Size validation
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise Exception("File too large")
        
        # Create a temporary file for testing
        temp_file = tempfile.mktemp(suffix=f"_{Path(path).name}")
        self.temp_files.append(temp_file)
        
        return {
            "path": path,
            "bytes_written": len(content),
            "encoding": encoding,
            "temp_file": temp_file
        }
    
    async def _list_directory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock directory listing"""
        path = params["path"]
        
        # Path validation
        if ".." in path:
            raise Exception("Invalid directory path")
        
        # Mock directory contents
        files = [
            {"name": "file1.txt", "type": "file", "size": 1024},
            {"name": "file2.py", "type": "file", "size": 2048},
            {"name": "subdirectory", "type": "directory", "size": 0},
            {"name": "README.md", "type": "file", "size": 512}
        ]
        
        return {
            "path": path,
            "files": files,
            "total_files": len([f for f in files if f["type"] == "file"]),
            "total_directories": len([f for f in files if f["type"] == "directory"])
        }


class MockDockerServer(BaseMockMCPServer):
    """Mock Docker MCP server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="docker",
            description="Docker container management",
            server_type=MockServerType.INFRASTRUCTURE,
            tools=[
                MockToolDefinition(
                    name="docker_run",
                    description="Run Docker container",
                    parameters=[
                        {"name": "image", "type": "string", "description": "Docker image"},
                        {"name": "command", "type": "string", "description": "Command to run"},
                        {"name": "ports", "type": "array", "description": "Port mappings"},
                        {"name": "environment", "type": "object", "description": "Environment variables"}
                    ],
                    required_params=["image"],
                    execution_time_ms=2000
                ),
                MockToolDefinition(
                    name="docker_build",
                    description="Build Docker image",
                    parameters=[
                        {"name": "dockerfile_path", "type": "string", "description": "Dockerfile path"},
                        {"name": "tag", "type": "string", "description": "Image tag"},
                        {"name": "build_args", "type": "object", "description": "Build arguments"}
                    ],
                    required_params=["dockerfile_path", "tag"],
                    execution_time_ms=10000
                ),
                MockToolDefinition(
                    name="docker_ps",
                    description="List containers",
                    parameters=[
                        {"name": "all", "type": "boolean", "description": "Show all containers"}
                    ]
                ),
                MockToolDefinition(
                    name="docker_stop",
                    description="Stop container",
                    parameters=[
                        {"name": "container_id", "type": "string", "description": "Container ID"}
                    ],
                    required_params=["container_id"]
                )
            ]
        )
        super().__init__(config)
        self.containers = {}
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Docker tools"""
        if tool_name == "docker_run":
            return await self._docker_run(parameters)
        elif tool_name == "docker_build":
            return await self._docker_build(parameters)
        elif tool_name == "docker_ps":
            return await self._docker_ps(parameters)
        elif tool_name == "docker_stop":
            return await self._docker_stop(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _docker_run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Docker run"""
        image = params["image"]
        command = params.get("command", "")
        ports = params.get("ports", [])
        environment = params.get("environment", {})
        
        # Image validation
        if ".." in image or "/" in image.split(":")[0]:
            raise Exception("Invalid Docker image name")
        
        # Create mock container
        container_id = f"mock_{uuid.uuid4().hex[:12]}"
        container = {
            "id": container_id,
            "image": image,
            "command": command,
            "ports": ports,
            "environment": environment,
            "status": "running",
            "created": time.time()
        }
        
        self.containers[container_id] = container
        
        return {
            "container_id": container_id,
            "image": image,
            "status": "running",
            "ports": ports,
            "logs": f"Mock container {container_id} started successfully"
        }
    
    async def _docker_build(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Docker build"""
        dockerfile_path = params["dockerfile_path"]
        tag = params["tag"]
        build_args = params.get("build_args", {})
        
        # Path validation
        if ".." in dockerfile_path:
            raise Exception("Invalid Dockerfile path")
        
        image_id = f"sha256:{uuid.uuid4().hex}"
        
        return {
            "image_id": image_id,
            "tag": tag,
            "dockerfile_path": dockerfile_path,
            "build_args": build_args,
            "build_time_seconds": 45.2,
            "size_bytes": 128 * 1024 * 1024
        }
    
    async def _docker_ps(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Docker ps"""
        show_all = params.get("all", False)
        
        containers = list(self.containers.values())
        if not show_all:
            containers = [c for c in containers if c["status"] == "running"]
        
        return {
            "containers": containers,
            "total": len(containers),
            "running": len([c for c in containers if c["status"] == "running"]),
            "stopped": len([c for c in containers if c["status"] == "stopped"])
        }
    
    async def _docker_stop(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Docker stop"""
        container_id = params["container_id"]
        
        if container_id not in self.containers:
            raise Exception(f"Container {container_id} not found")
        
        self.containers[container_id]["status"] = "stopped"
        
        return {
            "container_id": container_id,
            "status": "stopped",
            "stop_time": time.time()
        }


class MockKubernetesServer(BaseMockMCPServer):
    """Mock Kubernetes MCP server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="kubernetes",
            description="Kubernetes cluster management",
            server_type=MockServerType.INFRASTRUCTURE,
            tools=[
                MockToolDefinition(
                    name="kubectl_apply",
                    description="Apply Kubernetes manifest",
                    parameters=[
                        {"name": "manifest", "type": "object", "description": "Kubernetes manifest"},
                        {"name": "namespace", "type": "string", "description": "Namespace"}
                    ],
                    required_params=["manifest"],
                    execution_time_ms=3000
                ),
                MockToolDefinition(
                    name="kubectl_get",
                    description="Get Kubernetes resources",
                    parameters=[
                        {"name": "resource_type", "type": "string", "description": "Resource type"},
                        {"name": "namespace", "type": "string", "description": "Namespace"},
                        {"name": "name", "type": "string", "description": "Resource name"}
                    ],
                    required_params=["resource_type"]
                ),
                MockToolDefinition(
                    name="kubectl_delete",
                    description="Delete Kubernetes resource",
                    parameters=[
                        {"name": "resource_type", "type": "string", "description": "Resource type"},
                        {"name": "name", "type": "string", "description": "Resource name"},
                        {"name": "namespace", "type": "string", "description": "Namespace"}
                    ],
                    required_params=["resource_type", "name"]
                )
            ]
        )
        super().__init__(config)
        self.resources = {}
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Kubernetes tools"""
        if tool_name == "kubectl_apply":
            return await self._kubectl_apply(parameters)
        elif tool_name == "kubectl_get":
            return await self._kubectl_get(parameters)
        elif tool_name == "kubectl_delete":
            return await self._kubectl_delete(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _kubectl_apply(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock kubectl apply"""
        manifest = params["manifest"]
        namespace = params.get("namespace", manifest.get("metadata", {}).get("namespace", "default"))
        
        # Manifest validation
        required_fields = ["apiVersion", "kind", "metadata"]
        for field in required_fields:
            if field not in manifest:
                raise Exception(f"Manifest missing required field: {field}")
        
        resource_key = f"{namespace}/{manifest['kind']}/{manifest['metadata']['name']}"
        self.resources[resource_key] = manifest
        
        return {
            "apiVersion": manifest["apiVersion"],
            "kind": manifest["kind"],
            "name": manifest["metadata"]["name"],
            "namespace": namespace,
            "status": "created",
            "resource_version": "12345"
        }
    
    async def _kubectl_get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock kubectl get"""
        resource_type = params["resource_type"]
        namespace = params.get("namespace", "default")
        name = params.get("name")
        
        # Filter resources
        matching_resources = []
        for key, resource in self.resources.items():
            res_namespace, res_kind, res_name = key.split("/")
            if (res_kind.lower() == resource_type.lower() and 
                res_namespace == namespace and 
                (not name or res_name == name)):
                matching_resources.append({
                    "name": res_name,
                    "namespace": res_namespace,
                    "kind": res_kind,
                    "status": "Running",
                    "age": "2m"
                })
        
        return {
            "resource_type": resource_type,
            "namespace": namespace,
            "items": matching_resources,
            "total": len(matching_resources)
        }
    
    async def _kubectl_delete(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock kubectl delete"""
        resource_type = params["resource_type"]
        name = params["name"]
        namespace = params.get("namespace", "default")
        
        resource_key = f"{namespace}/{resource_type}/{name}"
        
        if resource_key not in self.resources:
            raise Exception(f"Resource {resource_key} not found")
        
        del self.resources[resource_key]
        
        return {
            "resource_type": resource_type,
            "name": name,
            "namespace": namespace,
            "status": "deleted"
        }


class MockSecurityScannerServer(BaseMockMCPServer):
    """Mock security scanner MCP server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="security-scanner",
            description="Security scanning and vulnerability assessment",
            server_type=MockServerType.SECURITY,
            tools=[
                MockToolDefinition(
                    name="scan_dependencies",
                    description="Scan dependencies for vulnerabilities",
                    parameters=[
                        {"name": "manifest_path", "type": "string", "description": "Path to manifest file"},
                        {"name": "scan_type", "type": "string", "description": "Type of scan"}
                    ],
                    required_params=["manifest_path"],
                    execution_time_ms=5000
                ),
                MockToolDefinition(
                    name="scan_container",
                    description="Scan container image for vulnerabilities",
                    parameters=[
                        {"name": "image", "type": "string", "description": "Container image"},
                        {"name": "severity_threshold", "type": "string", "description": "Minimum severity"}
                    ],
                    required_params=["image"],
                    execution_time_ms=15000
                ),
                MockToolDefinition(
                    name="scan_code",
                    description="Static code analysis",
                    parameters=[
                        {"name": "source_path", "type": "string", "description": "Source code path"},
                        {"name": "language", "type": "string", "description": "Programming language"}
                    ],
                    required_params=["source_path"],
                    execution_time_ms=8000
                )
            ]
        )
        super().__init__(config)
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security scanning tools"""
        if tool_name == "scan_dependencies":
            return await self._scan_dependencies(parameters)
        elif tool_name == "scan_container":
            return await self._scan_container(parameters)
        elif tool_name == "scan_code":
            return await self._scan_code(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _scan_dependencies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock dependency scanning"""
        manifest_path = params["manifest_path"]
        scan_type = params.get("scan_type", "comprehensive")
        
        # Mock vulnerabilities
        vulnerabilities = [
            {
                "id": "CVE-2023-MOCK-001",
                "severity": "high",
                "package": "mock-package",
                "version": "1.0.0",
                "fixed_version": "1.0.1",
                "description": "Mock security vulnerability for testing"
            },
            {
                "id": "CVE-2023-MOCK-002",
                "severity": "medium",
                "package": "another-package",
                "version": "2.1.0",
                "fixed_version": "2.1.3",
                "description": "Another mock vulnerability"
            }
        ]
        
        return {
            "manifest_path": manifest_path,
            "scan_type": scan_type,
            "vulnerabilities": vulnerabilities,
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": len([v for v in vulnerabilities if v["severity"] == "high"]),
            "medium_severity": len([v for v in vulnerabilities if v["severity"] == "medium"]),
            "low_severity": len([v for v in vulnerabilities if v["severity"] == "low"])
        }
    
    async def _scan_container(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock container scanning"""
        image = params["image"]
        severity_threshold = params.get("severity_threshold", "medium")
        
        # Mock container scan results
        layers = [
            {
                "layer_id": "sha256:abc123",
                "vulnerabilities": 2,
                "size": "50MB"
            },
            {
                "layer_id": "sha256:def456",
                "vulnerabilities": 0,
                "size": "25MB"
            }
        ]
        
        return {
            "image": image,
            "severity_threshold": severity_threshold,
            "total_vulnerabilities": 2,
            "layers": layers,
            "base_image": "ubuntu:20.04",
            "scan_time": time.time(),
            "passed": False
        }
    
    async def _scan_code(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock static code analysis"""
        source_path = params["source_path"]
        language = params.get("language", "auto-detect")
        
        # Mock code analysis results
        issues = [
            {
                "type": "security",
                "severity": "high",
                "rule": "hardcoded-credentials",
                "file": "config.py",
                "line": 42,
                "message": "Hardcoded password detected"
            },
            {
                "type": "quality",
                "severity": "medium",
                "rule": "complexity",
                "file": "main.py",
                "line": 100,
                "message": "Function complexity too high"
            }
        ]
        
        return {
            "source_path": source_path,
            "language": language,
            "issues": issues,
            "total_issues": len(issues),
            "security_issues": len([i for i in issues if i["type"] == "security"]),
            "quality_issues": len([i for i in issues if i["type"] == "quality"]),
            "files_scanned": 25,
            "lines_of_code": 2500
        }


class MockPrometheusServer(BaseMockMCPServer):
    """Mock Prometheus monitoring server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="prometheus-monitoring",
            description="Prometheus metrics and monitoring",
            server_type=MockServerType.MONITORING,
            tools=[
                MockToolDefinition(
                    name="prometheus_query",
                    description="Execute PromQL query",
                    parameters=[
                        {"name": "query", "type": "string", "description": "PromQL query"},
                        {"name": "time", "type": "string", "description": "Query time"}
                    ],
                    required_params=["query"]
                ),
                MockToolDefinition(
                    name="prometheus_query_range",
                    description="Execute range PromQL query",
                    parameters=[
                        {"name": "query", "type": "string", "description": "PromQL query"},
                        {"name": "start", "type": "string", "description": "Start time"},
                        {"name": "end", "type": "string", "description": "End time"},
                        {"name": "step", "type": "string", "description": "Step interval"}
                    ],
                    required_params=["query", "start", "end"]
                )
            ]
        )
        super().__init__(config)
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Prometheus tools"""
        if tool_name == "prometheus_query":
            return await self._prometheus_query(parameters)
        elif tool_name == "prometheus_query_range":
            return await self._prometheus_query_range(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _prometheus_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Prometheus instant query"""
        query = params["query"]
        query_time = params.get("time", str(int(time.time())))
        
        # Basic PromQL validation
        if any(dangerous in query for dangerous in ["file(", "exec(", "system("]):
            raise Exception("Dangerous PromQL function detected")
        
        # Mock metrics based on query
        if "cpu" in query.lower():
            metric_name = "cpu_usage_percent"
            value = "75.2"
        elif "memory" in query.lower():
            metric_name = "memory_usage_bytes"
            value = "2147483648"
        elif "http" in query.lower():
            metric_name = "http_requests_total"
            value = "1024"
        else:
            metric_name = "mock_metric"
            value = "42"
        
        return {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {
                            "__name__": metric_name,
                            "instance": "localhost:9090",
                            "job": "mock-job"
                        },
                        "value": [int(query_time), value]
                    }
                ]
            }
        }
    
    async def _prometheus_query_range(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock Prometheus range query"""
        query = params["query"]
        start = params["start"]
        end = params["end"]
        step = params.get("step", "15s")
        
        # Generate mock time series data
        start_time = int(start) if start.isdigit() else int(time.time()) - 3600
        end_time = int(end) if end.isdigit() else int(time.time())
        step_seconds = 15  # Mock 15 second step
        
        values = []
        current_time = start_time
        base_value = 50
        
        while current_time <= end_time:
            # Generate mock oscillating values
            import math
            variation = math.sin(current_time / 300) * 20  # 5-minute cycle
            value = base_value + variation
            values.append([current_time, str(round(value, 2))])
            current_time += step_seconds
        
        return {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {
                            "__name__": "mock_metric",
                            "instance": "localhost:9090"
                        },
                        "values": values
                    }
                ]
            }
        }


class MockBraveSearchServer(BaseMockMCPServer):
    """Mock Brave search server"""
    
    def __init__(self):
        config = MockServerConfig(
            name="brave",
            description="Web search capabilities",
            server_type=MockServerType.SEARCH,
            tools=[
                MockToolDefinition(
                    name="brave_web_search",
                    description="Search the web",
                    parameters=[
                        {"name": "query", "type": "string", "description": "Search query"},
                        {"name": "count", "type": "number", "description": "Number of results"},
                        {"name": "offset", "type": "number", "description": "Result offset"}
                    ],
                    required_params=["query"]
                ),
                MockToolDefinition(
                    name="brave_news_search",
                    description="Search news",
                    parameters=[
                        {"name": "query", "type": "string", "description": "Search query"},
                        {"name": "count", "type": "number", "description": "Number of results"}
                    ],
                    required_params=["query"]
                )
            ]
        )
        super().__init__(config)
    
    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute search tools"""
        if tool_name == "brave_web_search":
            return await self._brave_web_search(parameters)
        elif tool_name == "brave_news_search":
            return await self._brave_news_search(parameters)
        else:
            return await super()._execute_tool(tool_name, parameters)
    
    async def _brave_web_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock web search"""
        query = params["query"]
        count = params.get("count", 10)
        offset = params.get("offset", 0)
        
        # Input sanitization
        sanitized_query = re.sub(r'<[^>]+>', '', query)  # Remove HTML tags
        
        # Generate mock search results
        results = []
        for i in range(min(count, 10)):
            results.append({
                "title": f"Mock result {i+1} for: {sanitized_query}",
                "url": f"https://example{i+1}.com/mock-result",
                "snippet": f"This is a mock search result snippet for {sanitized_query}. It contains relevant information about the search query.",
                "rank": i + 1 + offset
            })
        
        return {
            "query": sanitized_query,
            "results": results,
            "total_results": count,
            "offset": offset,
            "search_time_ms": 120
        }
    
    async def _brave_news_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock news search"""
        query = params["query"]
        count = params.get("count", 10)
        
        # Input sanitization
        sanitized_query = re.sub(r'<[^>]+>', '', query)
        
        # Generate mock news results
        results = []
        for i in range(min(count, 10)):
            results.append({
                "title": f"Mock news: {sanitized_query} - Breaking News {i+1}",
                "url": f"https://news{i+1}.com/mock-article",
                "snippet": f"Latest news about {sanitized_query}. This is a mock news article snippet.",
                "published_date": time.time() - (i * 3600),  # Hours ago
                "source": f"Mock News {i+1}"
            })
        
        return {
            "query": sanitized_query,
            "results": results,
            "total_results": count,
            "search_time_ms": 95
        }


# Factory function to create mock servers
def create_mock_server(server_name: str) -> BaseMockMCPServer:
    """Factory function to create mock servers by name"""
    server_classes = {
        "desktop-commander": MockDesktopCommanderServer,
        "docker": MockDockerServer,
        "kubernetes": MockKubernetesServer,
        "security-scanner": MockSecurityScannerServer,
        "prometheus-monitoring": MockPrometheusServer,
        "brave": MockBraveSearchServer
    }
    
    if server_name not in server_classes:
        raise ValueError(f"Unknown server: {server_name}")
    
    return server_classes[server_name]()


# Utility functions for testing
def create_all_mock_servers() -> Dict[str, BaseMockMCPServer]:
    """Create all available mock servers"""
    return {
        name: create_mock_server(name)
        for name in [
            "desktop-commander",
            "docker", 
            "kubernetes",
            "security-scanner",
            "prometheus-monitoring",
            "brave"
        ]
    }


async def test_all_servers():
    """Test function to verify all mock servers work"""
    servers = create_all_mock_servers()
    
    for name, server in servers.items():
        print(f"\nTesting {name}...")
        
        # Test server info
        info = server.get_server_info()
        print(f"  Server: {info['name']} v{info['version']}")
        
        # Test tool listing
        tools = server.get_tools()
        print(f"  Tools: {[tool['name'] for tool in tools]}")
        
        # Test a tool if available
        if tools:
            tool = tools[0]
            try:
                # Create minimal valid parameters
                params = {}
                for param in tool.get('parameters', []):
                    if param['name'] in getattr(server.tools[tool['name']], 'required_params', []):
                        if param['type'] == 'string':
                            params[param['name']] = 'test'
                        elif param['type'] == 'number':
                            params[param['name']] = 1
                        elif param['type'] == 'object':
                            params[param['name']] = {'test': 'value'}
                        elif param['type'] == 'array':
                            params[param['name']] = ['test']
                
                result = await server.call_tool(tool['name'], params)
                print(f"  Test call successful: {result['success']}")
                
            except Exception as e:
                print(f"  Test call failed: {e}")
        
        # Cleanup
        server.cleanup()


if __name__ == "__main__":
    # Run tests when script is executed directly
    asyncio.run(test_all_servers())