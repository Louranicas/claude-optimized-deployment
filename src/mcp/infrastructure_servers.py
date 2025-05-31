"""
Infrastructure MCP servers for CODE project deployment automation.

Implements Docker, Kubernetes, Azure DevOps, and system automation MCP servers
that integrate with the existing MCP framework.
"""

from __future__ import annotations
import os
import asyncio
import subprocess
import json
import tempfile
import logging
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.core.circuit_breaker import CircuitBreakerConfig, get_circuit_breaker_manager
from src.mcp.servers import MCPServer
from src.core.exceptions import (
    InfrastructureError,
    CommandExecutionError,
    DockerError,
    KubernetesError,
    TimeoutError as DeploymentTimeoutError,
    ValidationError,
    handle_error
)

logger = logging.getLogger(__name__)


class DesktopCommanderMCPServer(MCPServer):
    """
    Desktop Commander MCP Server for CODE project.
    
    Provides terminal command execution and file management capabilities
    for infrastructure deployment automation.
    """
    
    def __init__(self):
        """Initialize Desktop Commander MCP Server."""
        self.working_directory = Path.cwd()
        self.command_history: List[Dict[str, Any]] = []
        self._circuit_breaker_manager = None
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Desktop Commander server information."""
        return MCPServerInfo(
            name="desktop-commander",
            version="1.0.0",
            description="Terminal command execution and file management for infrastructure deployment",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "command_execution": True,
                    "file_operations": True,
                    "directory_management": True,
                    "infrastructure_commands": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Desktop Commander tools."""
        return [
            MCPTool(
                name="execute_command",
                description="Execute terminal commands for infrastructure deployment",
                parameters=[
                    MCPToolParameter(
                        name="command",
                        type="string",
                        description="Terminal command to execute",
                        required=True
                    ),
                    MCPToolParameter(
                        name="working_directory",
                        type="string",
                        description="Working directory for command execution",
                        required=False
                    ),
                    MCPToolParameter(
                        name="timeout",
                        type="integer",
                        description="Command timeout in seconds",
                        required=False,
                        default=300
                    )
                ]
            ),
            MCPTool(
                name="read_file",
                description="Read file contents for infrastructure configuration",
                parameters=[
                    MCPToolParameter(
                        name="file_path",
                        type="string",
                        description="Path to file to read",
                        required=True
                    ),
                    MCPToolParameter(
                        name="encoding",
                        type="string",
                        description="File encoding",
                        required=False,
                        default="utf-8"
                    )
                ]
            ),
            MCPTool(
                name="write_file",
                description="Write content to file for infrastructure as code",
                parameters=[
                    MCPToolParameter(
                        name="file_path",
                        type="string",
                        description="Path to file to write",
                        required=True
                    ),
                    MCPToolParameter(
                        name="content",
                        type="string",
                        description="File content to write",
                        required=True
                    ),
                    MCPToolParameter(
                        name="create_dirs",
                        type="boolean",
                        description="Create parent directories if needed",
                        required=False,
                        default=True
                    )
                ]
            ),
            MCPTool(
                name="list_directory",
                description="List directory contents for infrastructure exploration",
                parameters=[
                    MCPToolParameter(
                        name="directory_path",
                        type="string",
                        description="Directory path to list",
                        required=True
                    ),
                    MCPToolParameter(
                        name="show_hidden",
                        type="boolean",
                        description="Show hidden files",
                        required=False,
                        default=False
                    )
                ]
            ),
            MCPTool(
                name="make_command",
                description="Execute Make commands for CODE project automation",
                parameters=[
                    MCPToolParameter(
                        name="target",
                        type="string",
                        description="Make target to execute (e.g., 'deploy', 'test', 'quality')",
                        required=True
                    ),
                    MCPToolParameter(
                        name="args",
                        type="string",
                        description="Additional arguments for make command",
                        required=False
                    )
                ]
            )
        ]
    
    async def _get_circuit_breaker_manager(self):
        """Get or create circuit breaker manager."""
        if self._circuit_breaker_manager is None:
            self._circuit_breaker_manager = get_circuit_breaker_manager()
        return self._circuit_breaker_manager
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute Desktop Commander tool with circuit breaker protection."""
        # Get circuit breaker for this tool
        manager = await self._get_circuit_breaker_manager()
        breaker = await manager.get_or_create(
            f"desktop_commander_{tool_name}",
            CircuitBreakerConfig(
                failure_threshold=5,
                timeout=120,
                failure_rate_threshold=0.6,
                minimum_calls=3,
                fallback=lambda: self._create_fallback_response(tool_name, arguments)
            )
        )
        
        # Execute tool with circuit breaker protection
        return await breaker.call(self._execute_tool, tool_name, arguments)
    
    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Internal tool execution method."""
        try:
            if tool_name == "execute_command":
                return await self._execute_command(**arguments)
            elif tool_name == "read_file":
                return await self._read_file(**arguments)
            elif tool_name == "write_file":
                return await self._write_file(**arguments)
            elif tool_name == "list_directory":
                return await self._list_directory(**arguments)
            elif tool_name == "make_command":
                return await self._make_command(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling Desktop Commander tool {tool_name}: {e}")
            raise
    
    def _create_fallback_response(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback response when circuit is open."""
        return {
            "status": "error",
            "message": f"Desktop Commander service is temporarily unavailable. Tool '{tool_name}' cannot be executed right now due to circuit breaker protection.",
            "tool": tool_name,
            "fallback": True,
            "retry_after": "Please try again in a few minutes"
        }
    
    async def _execute_command(
        self,
        command: str,
        working_directory: Optional[str] = None,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """Execute a terminal command."""
        work_dir = Path(working_directory) if working_directory else self.working_directory
        
        logger.info(f"Executing command: {command} in {work_dir}")
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            result = {
                "command": command,
                "working_directory": str(work_dir),
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
            
            # Record in history
            self.command_history.append(result)
            
            return result
            
        except asyncio.TimeoutError:
            raise DeploymentTimeoutError(
                f"Command timed out after {timeout} seconds",
                timeout_seconds=timeout,
                operation="execute_command",
                context={"command": command, "working_directory": str(work_dir)}
            )
        except Exception as e:
            raise CommandExecutionError(
                f"Command execution failed: {str(e)}",
                command=command,
                exit_code=process.returncode if 'process' in locals() else None,
                stderr=stderr.decode('utf-8') if 'stderr' in locals() else None,
                cause=e
            )
    
    async def _read_file(self, file_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """Read file contents."""
        try:
            path = Path(file_path)
            if not path.exists():
                raise InfrastructureError(
                    f"File not found: {file_path}",
                    context={"file_path": file_path, "operation": "read_file"}
                )
            
            content = path.read_text(encoding=encoding)
            
            return {
                "file_path": str(path.absolute()),
                "content": content,
                "size": len(content),
                "encoding": encoding
            }
        except InfrastructureError:
            raise
        except Exception as e:
            raise InfrastructureError(
                f"Failed to read file: {str(e)}",
                context={"file_path": file_path},
                cause=e
            )
    
    async def _write_file(
        self,
        file_path: str,
        content: str,
        create_dirs: bool = True
    ) -> Dict[str, Any]:
        """Write content to file."""
        try:
            path = Path(file_path)
            
            if create_dirs:
                path.parent.mkdir(parents=True, exist_ok=True)
            
            path.write_text(content, encoding="utf-8")
            
            return {
                "file_path": str(path.absolute()),
                "size": len(content),
                "created_dirs": create_dirs and not path.parent.exists()
            }
        except Exception as e:
            raise InfrastructureError(
                f"Failed to write file: {str(e)}",
                context={"file_path": file_path, "content_size": len(content)},
                cause=e
            )
    
    async def _list_directory(
        self,
        directory_path: str,
        show_hidden: bool = False
    ) -> Dict[str, Any]:
        """List directory contents."""
        try:
            path = Path(directory_path)
            if not path.exists():
                raise InfrastructureError(
                    f"Directory not found: {directory_path}",
                    context={"directory_path": directory_path}
                )
            
            if not path.is_dir():
                raise ValidationError(
                    f"Path is not a directory: {directory_path}",
                    field="directory_path",
                    value=directory_path
                )
            
            items = []
            for item in path.iterdir():
                if not show_hidden and item.name.startswith('.'):
                    continue
                
                items.append({
                    "name": item.name,
                    "path": str(item.absolute()),
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else None
                })
            
            return {
                "directory_path": str(path.absolute()),
                "items": sorted(items, key=lambda x: (x["type"], x["name"])),
                "total_items": len(items)
            }
        except (InfrastructureError, ValidationError):
            raise
        except Exception as e:
            raise InfrastructureError(
                f"Failed to list directory: {str(e)}",
                context={"directory_path": directory_path},
                cause=e
            )
    
    async def _make_command(self, target: str, args: Optional[str] = None) -> Dict[str, Any]:
        """Execute Make commands for CODE project."""
        command = f"make {target}"
        if args:
            command += f" {args}"
        
        return await self._execute_command(command, str(self.working_directory))


class DockerMCPServer(MCPServer):
    """
    Docker MCP Server for CODE project.
    
    Provides Docker container management capabilities for infrastructure deployment.
    """
    
    def __init__(self):
        """Initialize Docker MCP Server."""
        self.docker_available = None
    
    async def _check_docker(self) -> bool:
        """Check if Docker is available."""
        if self.docker_available is None:
            try:
                process = await asyncio.create_subprocess_shell(
                    "docker --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                self.docker_available = process.returncode == 0
            except Exception:
                self.docker_available = False
        
        return self.docker_available
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Docker server information."""
        return MCPServerInfo(
            name="docker",
            version="1.0.0",
            description="Docker container management for CODE project deployment",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "container_management": True,
                    "image_operations": True,
                    "docker_compose": True,
                    "secure_execution": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Docker tools."""
        return [
            MCPTool(
                name="docker_run",
                description="Run a Docker container for secure code execution",
                parameters=[
                    MCPToolParameter(
                        name="image",
                        type="string",
                        description="Docker image to run",
                        required=True
                    ),
                    MCPToolParameter(
                        name="command",
                        type="string",
                        description="Command to execute in container",
                        required=False
                    ),
                    MCPToolParameter(
                        name="volumes",
                        type="array",
                        description="Volume mounts (host:container format)",
                        required=False
                    ),
                    MCPToolParameter(
                        name="environment",
                        type="object",
                        description="Environment variables",
                        required=False
                    ),
                    MCPToolParameter(
                        name="ports",
                        type="array",
                        description="Port mappings (host:container format)",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="docker_build",
                description="Build Docker image from Dockerfile",
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
                        description="Tag for the built image",
                        required=True
                    ),
                    MCPToolParameter(
                        name="build_context",
                        type="string",
                        description="Build context directory",
                        required=False,
                        default="."
                    )
                ]
            ),
            MCPTool(
                name="docker_compose",
                description="Execute docker-compose commands for CODE project",
                parameters=[
                    MCPToolParameter(
                        name="action",
                        type="string",
                        description="Docker compose action (up, down, build, logs)",
                        required=True,
                        enum=["up", "down", "build", "logs", "ps", "pull"]
                    ),
                    MCPToolParameter(
                        name="compose_file",
                        type="string",
                        description="Path to docker-compose.yml",
                        required=False,
                        default="docker-compose.yml"
                    ),
                    MCPToolParameter(
                        name="services",
                        type="array",
                        description="Specific services to target",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="docker_ps",
                description="List running Docker containers",
                parameters=[
                    MCPToolParameter(
                        name="all",
                        type="boolean",
                        description="Show all containers (including stopped)",
                        required=False,
                        default=False
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a Docker tool."""
        if not await self._check_docker():
            raise DockerError(
                "Docker is not available on this system",
                context={"tool_name": tool_name}
            )
        
        try:
            if tool_name == "docker_run":
                return await self._docker_run(**arguments)
            elif tool_name == "docker_build":
                return await self._docker_build(**arguments)
            elif tool_name == "docker_compose":
                return await self._docker_compose(**arguments)
            elif tool_name == "docker_ps":
                return await self._docker_ps(**arguments)
            else:
                from src.core.exceptions import MCPToolNotFoundError
                raise MCPToolNotFoundError(
                    tool_name,
                    "docker",
                    available_tools=["docker_run", "docker_build", "docker_compose", "docker_ps"]
                )
        except DockerError:
            raise
        except Exception as e:
            error = DockerError(
                f"Error calling Docker tool {tool_name}",
                context={"tool_name": tool_name, "arguments": arguments},
                cause=e
            )
            handle_error(error, logger)
            raise error
    
    async def _docker_run(
        self,
        image: str,
        command: Optional[str] = None,
        volumes: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
        ports: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run a Docker container."""
        cmd_parts = ["docker", "run", "--rm"]
        
        # Add volumes
        if volumes:
            for volume in volumes:
                cmd_parts.extend(["-v", volume])
        
        # Add environment variables
        if environment:
            for key, value in environment.items():
                cmd_parts.extend(["-e", f"{key}={value}"])
        
        # Add port mappings
        if ports:
            for port in ports:
                cmd_parts.extend(["-p", port])
        
        # Add image
        cmd_parts.append(image)
        
        # Add command
        if command:
            cmd_parts.extend(command.split())
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise DockerError(
                f"Docker run failed: {str(e)}",
                image=image,
                context={
                    "command": cmd,
                    "exit_code": process.returncode if 'process' in locals() else None,
                    "stderr": stderr.decode('utf-8') if 'stderr' in locals() else None
                },
                cause=e
            )
    
    async def _docker_build(
        self,
        dockerfile_path: str,
        image_tag: str,
        build_context: str = "."
    ) -> Dict[str, Any]:
        """Build Docker image."""
        cmd = f"docker build -f {dockerfile_path} -t {image_tag} {build_context}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "image_tag": image_tag,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise DockerError(
                f"Docker build failed: {str(e)}",
                image=image_tag,
                context={
                    "dockerfile_path": dockerfile_path,
                    "build_context": build_context,
                    "exit_code": process.returncode if 'process' in locals() else None,
                    "stderr": stderr.decode('utf-8') if 'stderr' in locals() else None
                },
                cause=e
            )
    
    async def _docker_compose(
        self,
        action: str,
        compose_file: str = "docker-compose.yml",
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Execute docker-compose commands."""
        cmd_parts = ["docker-compose", "-f", compose_file, action]
        
        if services:
            cmd_parts.extend(services)
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "action": action,
                "compose_file": compose_file,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise DockerError(
                f"Docker compose {action} failed: {str(e)}",
                context={
                    "action": action,
                    "compose_file": compose_file,
                    "services": services,
                    "exit_code": process.returncode if 'process' in locals() else None,
                    "stderr": stderr.decode('utf-8') if 'stderr' in locals() else None
                },
                cause=e
            )
    
    async def _docker_ps(self, all: bool = False) -> Dict[str, Any]:
        """List Docker containers."""
        cmd = "docker ps --format json"
        if all:
            cmd += " -a"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise DockerError(
                    f"Docker ps failed: {stderr.decode('utf-8')}",
                    context={"exit_code": process.returncode}
                )
            
            # Parse JSON output
            containers = []
            for line in stdout.decode('utf-8').strip().split('\n'):
                if line:
                    containers.append(json.loads(line))
            
            return {
                "containers": containers,
                "total": len(containers)
            }
        except DockerError:
            raise
        except Exception as e:
            raise DockerError(
                f"Docker ps failed: {str(e)}",
                cause=e
            )


class KubernetesMCPServer(MCPServer):
    """
    Kubernetes MCP Server for CODE project.
    
    Provides Kubernetes cluster management capabilities for deployment orchestration.
    """
    
    def __init__(self):
        """Initialize Kubernetes MCP Server."""
        self.kubectl_available = None
    
    async def _check_kubectl(self) -> bool:
        """Check if kubectl is available."""
        if self.kubectl_available is None:
            try:
                process = await asyncio.create_subprocess_shell(
                    "kubectl version --client",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                self.kubectl_available = process.returncode == 0
            except Exception:
                self.kubectl_available = False
        
        return self.kubectl_available
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Kubernetes server information."""
        return MCPServerInfo(
            name="kubernetes",
            version="1.0.0",
            description="Kubernetes cluster management for CODE project deployment",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "cluster_management": True,
                    "deployment_automation": True,
                    "service_management": True,
                    "health_monitoring": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Kubernetes tools."""
        return [
            MCPTool(
                name="kubectl_apply",
                description="Apply Kubernetes manifests for deployment",
                parameters=[
                    MCPToolParameter(
                        name="manifest_path",
                        type="string",
                        description="Path to Kubernetes manifest file or directory",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Kubernetes namespace",
                        required=False,
                        default="default"
                    )
                ]
            ),
            MCPTool(
                name="kubectl_get",
                description="Get Kubernetes resources",
                parameters=[
                    MCPToolParameter(
                        name="resource_type",
                        type="string",
                        description="Resource type (pods, services, deployments, etc.)",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Kubernetes namespace",
                        required=False,
                        default="default"
                    ),
                    MCPToolParameter(
                        name="resource_name",
                        type="string",
                        description="Specific resource name",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="kubectl_delete",
                description="Delete Kubernetes resources",
                parameters=[
                    MCPToolParameter(
                        name="resource_type",
                        type="string",
                        description="Resource type to delete",
                        required=True
                    ),
                    MCPToolParameter(
                        name="resource_name",
                        type="string",
                        description="Resource name to delete",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Kubernetes namespace",
                        required=False,
                        default="default"
                    )
                ]
            ),
            MCPTool(
                name="kubectl_logs",
                description="Get logs from Kubernetes pods",
                parameters=[
                    MCPToolParameter(
                        name="pod_name",
                        type="string",
                        description="Pod name to get logs from",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Kubernetes namespace",
                        required=False,
                        default="default"
                    ),
                    MCPToolParameter(
                        name="container",
                        type="string",
                        description="Container name within pod",
                        required=False
                    ),
                    MCPToolParameter(
                        name="tail",
                        type="integer",
                        description="Number of lines to tail",
                        required=False,
                        default=100
                    )
                ]
            ),
            MCPTool(
                name="kubectl_describe",
                description="Describe Kubernetes resources for debugging",
                parameters=[
                    MCPToolParameter(
                        name="resource_type",
                        type="string",
                        description="Resource type to describe",
                        required=True
                    ),
                    MCPToolParameter(
                        name="resource_name",
                        type="string",
                        description="Resource name to describe",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Kubernetes namespace",
                        required=False,
                        default="default"
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a Kubernetes tool."""
        if not await self._check_kubectl():
            raise KubernetesError(
                "kubectl is not available on this system",
                context={"tool_name": tool_name}
            )
        
        try:
            if tool_name == "kubectl_apply":
                return await self._kubectl_apply(**arguments)
            elif tool_name == "kubectl_get":
                return await self._kubectl_get(**arguments)
            elif tool_name == "kubectl_delete":
                return await self._kubectl_delete(**arguments)
            elif tool_name == "kubectl_logs":
                return await self._kubectl_logs(**arguments)
            elif tool_name == "kubectl_describe":
                return await self._kubectl_describe(**arguments)
            else:
                from src.core.exceptions import MCPToolNotFoundError
                raise MCPToolNotFoundError(
                    tool_name,
                    "kubernetes",
                    available_tools=["kubectl_apply", "kubectl_get", "kubectl_delete", "kubectl_logs", "kubectl_describe"]
                )
        except KubernetesError:
            raise
        except Exception as e:
            error = KubernetesError(
                f"Error calling Kubernetes tool {tool_name}",
                context={"tool_name": tool_name, "arguments": arguments},
                cause=e
            )
            handle_error(error, logger)
            raise error
    
    async def _kubectl_apply(
        self,
        manifest_path: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """Apply Kubernetes manifests."""
        cmd = f"kubectl apply -f {manifest_path} -n {namespace}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "manifest_path": manifest_path,
                "namespace": namespace,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise KubernetesError(
                f"kubectl apply failed: {str(e)}",
                namespace=namespace,
                resource=manifest_path,
                context={
                    "command": cmd,
                    "exit_code": process.returncode if 'process' in locals() else None,
                    "stderr": stderr.decode('utf-8') if 'stderr' in locals() else None
                },
                cause=e
            )
    
    async def _kubectl_get(
        self,
        resource_type: str,
        namespace: str = "default",
        resource_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get Kubernetes resources."""
        cmd_parts = ["kubectl", "get", resource_type, "-n", namespace, "-o", "json"]
        
        if resource_name:
            cmd_parts.insert(-2, resource_name)  # Insert before -o json
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "command": cmd,
                "resource_type": resource_type,
                "namespace": namespace,
                "exit_code": process.returncode,
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
            
            if process.returncode == 0:
                try:
                    result["resources"] = json.loads(stdout.decode('utf-8'))
                except json.JSONDecodeError:
                    result["stdout"] = stdout.decode('utf-8')
            else:
                result["stdout"] = stdout.decode('utf-8')
            
            return result
        except Exception as e:
            raise MCPError(-32000, f"kubectl get failed: {str(e)}")
    
    async def _kubectl_delete(
        self,
        resource_type: str,
        resource_name: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """Delete Kubernetes resources."""
        cmd = f"kubectl delete {resource_type} {resource_name} -n {namespace}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "namespace": namespace,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise MCPError(-32000, f"kubectl delete failed: {str(e)}")
    
    async def _kubectl_logs(
        self,
        pod_name: str,
        namespace: str = "default",
        container: Optional[str] = None,
        tail: int = 100
    ) -> Dict[str, Any]:
        """Get pod logs."""
        cmd_parts = ["kubectl", "logs", pod_name, "-n", namespace, "--tail", str(tail)]
        
        if container:
            cmd_parts.extend(["-c", container])
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "pod_name": pod_name,
                "namespace": namespace,
                "container": container,
                "exit_code": process.returncode,
                "logs": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise MCPError(-32000, f"kubectl logs failed: {str(e)}")
    
    async def _kubectl_describe(
        self,
        resource_type: str,
        resource_name: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """Describe Kubernetes resources."""
        cmd = f"kubectl describe {resource_type} {resource_name} -n {namespace}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": cmd,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "namespace": namespace,
                "exit_code": process.returncode,
                "description": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise MCPError(-32000, f"kubectl describe failed: {str(e)}")