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
import shlex
import re
from typing import Dict, Any, List, Optional, Union, Set
from pathlib import Path

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError, MCPServer
from src.core.circuit_breaker import CircuitBreakerConfig, get_circuit_breaker_manager
from src.core.exceptions import (
    InfrastructureError,
    CommandExecutionError,
    DockerError,
    KubernetesError,
    TimeoutError as DeploymentTimeoutError,
    ValidationError,
    handle_error
)
from src.core.path_validation import validate_file_path

logger = logging.getLogger(__name__)

# Command whitelist for security
ALLOWED_COMMANDS: Set[str] = {
    # Version control
    "git", "gh",
    # Python tools
    "python", "python3", "pip", "pip3", "pytest", "mypy", "black", "flake8", "ruff",
    # Node.js tools
    "node", "npm", "yarn", "npx",
    # Build tools
    "make", "cmake", "cargo",
    # Container tools
    "docker", "docker-compose", "kubectl", "helm",
    # System info (read-only)
    "ls", "pwd", "echo", "date", "whoami", "hostname", "uname",
    # File operations (restricted)
    "cat", "head", "tail", "grep", "find", "wc",
    # Process management (restricted)
    "ps", "top", "htop",
    # Network tools (restricted)
    "curl", "wget", "ping", "netstat",
    # Archive tools
    "tar", "zip", "unzip", "gzip", "gunzip",
    # Environment
    "env", "export",
}

# Dangerous patterns to detect command injection attempts
INJECTION_PATTERNS = [
    # Command chaining
    re.compile(r'[;&|]{2,}'),  # Multiple command separators
    re.compile(r'(?<!\\)[;&|](?!&)'),  # Unescaped command separators
    # Command substitution
    re.compile(r'\$\([^)]+\)'),  # $()
    re.compile(r'`[^`]+`'),  # Backticks
    re.compile(r'\$\{[^}]+\}'),  # ${} 
    # Redirection abuse
    re.compile(r'>\s*/dev/(tcp|udp)'),  # Network redirection
    re.compile(r'<\s*/dev/(tcp|udp)'),  # Network input
    # Path traversal
    re.compile(r'\.\.(/|\\){2,}'),  # Multiple parent directory references
    # Shell functions
    re.compile(r'function\s+\w+'),
    re.compile(r'\w+\s*\(\s*\)\s*\{'),
    # Dangerous commands even if in whitelist
    re.compile(r'(rm|rmdir|mv|cp)\s+(-rf?|-fr?)\s'),  # Destructive operations
    re.compile(r':(bomb|fork)'),  # Fork bombs
    # Script execution
    re.compile(r'(sh|bash|zsh|csh|ksh|fish)\s+-c'),  # Shell execution
    re.compile(r'(python|perl|ruby|php)\s+-e'),  # Script execution
    # System modification
    re.compile(r'(chmod|chown)\s+(-R\s+)?[0-7]{3,4}'),  # Permission changes
    re.compile(r'/etc/(passwd|shadow|sudoers)'),  # System files
    # Environment manipulation
    re.compile(r'LD_PRELOAD='),
    re.compile(r'PATH='),
]

# Maximum output size (10MB)
MAX_OUTPUT_SIZE = 10 * 1024 * 1024

# Maximum command length
MAX_COMMAND_LENGTH = 4096

# Docker image name validation
DOCKER_IMAGE_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?(/[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)*(:([a-zA-Z0-9._-]+))?$')

# Kubernetes resource name validation
K8S_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')
K8S_NAMESPACE_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')

# Docker command validation
DOCKER_SAFE_ARGS = {
    'docker_run': ['--rm', '--name', '-v', '-e', '-p', '--network', '--memory', '--cpus', '--user'],
    'docker_build': ['-f', '-t', '--build-arg', '--target', '--cache-from'],
    'docker_compose': ['-f', '--project-name', '--profile']
}

# Kubernetes safe resource types
K8S_SAFE_RESOURCES = {
    'pods', 'services', 'deployments', 'configmaps', 'secrets', 'ingress',
    'replicasets', 'daemonsets', 'statefulsets', 'jobs', 'cronjobs',
    'persistentvolumes', 'persistentvolumeclaims', 'nodes', 'namespaces'
}


class DesktopCommanderMCPServer(MCPServer):
    """
    Desktop Commander MCP Server for CODE project.
    
    Provides terminal command execution and file management capabilities
    for infrastructure deployment automation.
    """
    
    def __init__(self, permission_checker: Optional[Any] = None):
        """Initialize Desktop Commander MCP Server."""
        super().__init__(name="desktop-commander", version="1.0.0", permission_checker=permission_checker)
        self.working_directory = Path.cwd()
        self.command_history: List[Dict[str, Any]] = []
        self._circuit_breaker_manager = None
        
        # Update capabilities
        self.capabilities = MCPCapabilities(
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
        
        # Set up tool-specific permissions
        self.tool_permissions = {
            "execute_command": "mcp.desktop.command:execute",
            "read_file": "mcp.desktop.file:read",
            "write_file": "mcp.desktop.file:write",
            "list_directory": "mcp.desktop.directory:list",
            "create_directory": "mcp.desktop.directory:create",
            "delete_file": "mcp.desktop.file:delete"
        }
        
        # Register resource permissions if permission checker available
        if self.permission_checker:
            self.register_resource_permissions()
    
    def _get_all_tools(self) -> List[MCPTool]:
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
    
    async def _call_tool_impl(self, tool_name: str, arguments: Dict[str, Any], 
                             user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Execute Desktop Commander tool with circuit breaker protection and authentication."""
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
        return await breaker.call(self._execute_tool, tool_name, arguments, user, context)
    
    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any], 
                           user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Internal tool execution method with user context."""
        try:
            # Log user action for security auditing
            logger.info(f"User {user.username} executing {tool_name} on Desktop Commander")
            
            if tool_name == "execute_command":
                return await self._execute_command(**arguments, user=user, context=context)
            elif tool_name == "read_file":
                return await self._read_file(**arguments, user=user)
            elif tool_name == "write_file":
                return await self._write_file(**arguments, user=user)
            elif tool_name == "list_directory":
                return await self._list_directory(**arguments, user=user)
            elif tool_name == "make_command":
                return await self._make_command(**arguments, user=user)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling Desktop Commander tool {tool_name} for user {user.username}: {e}")
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
        timeout: int = 300,
        user: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a terminal command with security validation."""
        # Validate command length
        if len(command) > MAX_COMMAND_LENGTH:
            raise ValidationError(
                f"Command exceeds maximum length of {MAX_COMMAND_LENGTH} characters",
                field="command",
                value=f"{command[:50]}... (truncated)"
            )
        
        # Validate timeout
        if timeout <= 0 or timeout > 600:  # Max 10 minutes
            raise ValidationError(
                "Timeout must be between 1 and 600 seconds",
                field="timeout",
                value=timeout
            )
        
        # Check for injection patterns
        for pattern in INJECTION_PATTERNS:
            if pattern.search(command):
                raise CommandExecutionError(
                    "Command contains potentially dangerous patterns",
                    command=command,
                    exit_code=-1,
                    stderr="Security validation failed: suspicious command pattern detected"
                )
        
        # Parse command to extract the base command
        try:
            # Use shlex to safely parse the command
            parts = shlex.split(command)
            if not parts:
                raise ValidationError("Empty command", field="command", value=command)
            
            base_command = parts[0]
            
            # Check if command is in whitelist
            if base_command not in ALLOWED_COMMANDS:
                # Check if it's a path to an allowed command
                base_name = os.path.basename(base_command)
                if base_name not in ALLOWED_COMMANDS:
                    raise CommandExecutionError(
                        f"Command '{base_command}' is not in the allowed command list",
                        command=command,
                        exit_code=-1,
                        stderr=f"Security validation failed: '{base_command}' is not an allowed command"
                    )
        except ValueError as e:
            raise ValidationError(
                f"Invalid command syntax: {str(e)}",
                field="command",
                value=command
            )
        
        # Validate working directory
        work_dir = Path(working_directory) if working_directory else self.working_directory
        try:
            work_dir = work_dir.resolve()
            if not work_dir.exists():
                raise ValidationError(
                    f"Working directory does not exist: {work_dir}",
                    field="working_directory",
                    value=str(working_directory)
                )
            if not work_dir.is_dir():
                raise ValidationError(
                    f"Working directory is not a directory: {work_dir}",
                    field="working_directory", 
                    value=str(working_directory)
                )
        except Exception as e:
            raise ValidationError(
                f"Invalid working directory: {str(e)}",
                field="working_directory",
                value=str(working_directory)
            )
        
        logger.info(f"Executing validated command: {base_command} in {work_dir}")
        
        try:
            # Use subprocess.run with explicit arguments (no shell=True)
            process = await asyncio.create_subprocess_exec(
                *parts,  # Unpack the safely parsed command parts
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Limit subprocess resources
                env={**os.environ, "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
                stdin=asyncio.subprocess.DEVNULL  # No stdin access
            )
            
            # Read output with size limits
            stdout_data = b""
            stderr_data = b""
            
            try:
                # Use wait_for with timeout
                async def read_with_limit(stream, limit):
                    data = b""
                    while True:
                        chunk = await stream.read(8192)  # Read in chunks
                        if not chunk:
                            break
                        if len(data) + len(chunk) > limit:
                            data += chunk[:limit - len(data)]
                            raise CommandExecutionError(
                                f"Output exceeded maximum size of {limit} bytes",
                                command=command,
                                exit_code=-1,
                                stderr="Output size limit exceeded"
                            )
                        data += chunk
                    return data
                
                # Read both streams concurrently with timeout
                stdout_task = asyncio.create_task(read_with_limit(process.stdout, MAX_OUTPUT_SIZE))
                stderr_task = asyncio.create_task(read_with_limit(process.stderr, MAX_OUTPUT_SIZE))
                
                # Wait for process to complete with timeout
                await asyncio.wait_for(process.wait(), timeout=timeout)
                
                # Get the output
                stdout_data = await stdout_task
                stderr_data = await stderr_task
                
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
                raise DeploymentTimeoutError(
                    f"Command timed out after {timeout} seconds",
                    timeout_seconds=timeout,
                    operation="execute_command",
                    context={"command": command, "working_directory": str(work_dir)}
                )
            
            # Decode output safely
            try:
                stdout = stdout_data.decode('utf-8', errors='replace')
                stderr = stderr_data.decode('utf-8', errors='replace')
            except Exception as e:
                logger.warning(f"Failed to decode command output: {e}")
                stdout = repr(stdout_data)
                stderr = repr(stderr_data)
            
            result = {
                "command": command,
                "working_directory": str(work_dir),
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "success": process.returncode == 0
            }
            
            # Record in history (limit history size)
            self.command_history.append(result)
            if len(self.command_history) > 100:  # Keep last 100 commands
                self.command_history.pop(0)
            
            return result
            
        except (DeploymentTimeoutError, CommandExecutionError, ValidationError):
            raise
        except Exception as e:
            raise CommandExecutionError(
                f"Command execution failed: {str(e)}",
                command=command,
                exit_code=-1,
                stderr=str(e),
                cause=e
            )
    
    async def _read_file(self, file_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """Read file contents with path validation."""
        try:
            path = Path(file_path)
            
            # Resolve to absolute path and check for directory traversal
            try:
                abs_path = path.resolve()
                # Ensure the file is within the current working directory or its subdirectories
                cwd = self.working_directory.resolve()
                if not (abs_path == cwd or cwd in abs_path.parents):
                    # Allow reading from common system directories
                    allowed_dirs = [
                        Path("/etc").resolve(),
                        Path("/usr").resolve(),
                        Path("/opt").resolve(),
                        Path.home().resolve()
                    ]
                    if not any(abs_path == allowed or allowed in abs_path.parents for allowed in allowed_dirs):
                        raise ValidationError(
                            "Access denied: file is outside allowed directories",
                            field="file_path",
                            value=file_path
                        )
            except Exception as e:
                if isinstance(e, ValidationError):
                    raise
                raise ValidationError(
                    f"Invalid file path: {str(e)}",
                    field="file_path", 
                    value=file_path
                )
            
            if not abs_path.exists():
                raise InfrastructureError(
                    f"File not found: {file_path}",
                    context={"file_path": file_path, "operation": "read_file"}
                )
            
            if not abs_path.is_file():
                raise ValidationError(
                    "Path is not a file",
                    field="file_path",
                    value=file_path
                )
            
            # Check file size before reading
            file_size = abs_path.stat().st_size
            if file_size > MAX_OUTPUT_SIZE:
                raise ValidationError(
                    f"File too large: {file_size} bytes (max {MAX_OUTPUT_SIZE} bytes)",
                    field="file_path",
                    value=file_path
                )
            
            content = abs_path.read_text(encoding=encoding)
            
            return {
                "file_path": str(abs_path),
                "content": content,
                "size": len(content),
                "encoding": encoding
            }
        except (InfrastructureError, ValidationError):
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
        """Write content to file with path validation."""
        try:
            path = Path(file_path)
            
            # Validate content size
            if len(content) > MAX_OUTPUT_SIZE:
                raise ValidationError(
                    f"Content too large: {len(content)} bytes (max {MAX_OUTPUT_SIZE} bytes)",
                    field="content",
                    value=f"<{len(content)} bytes>"
                )
            
            # Resolve to absolute path and check for directory traversal
            try:
                abs_path = path.resolve()
                # Ensure the file is within the current working directory
                cwd = self.working_directory.resolve()
                if not (abs_path == cwd or cwd in abs_path.parents):
                    raise ValidationError(
                        "Access denied: file is outside working directory",
                        field="file_path",
                        value=file_path
                    )
            except Exception as e:
                if isinstance(e, ValidationError):
                    raise
                raise ValidationError(
                    f"Invalid file path: {str(e)}",
                    field="file_path",
                    value=file_path
                )
            
            # Check if we're overwriting a system file
            if abs_path.exists():
                # Prevent overwriting certain critical files
                critical_patterns = [
                    r'/etc/(passwd|shadow|sudoers|hosts)$',
                    r'\.ssh/authorized_keys$',
                    r'\.bashrc$',
                    r'\.profile$',
                    r'\.gitconfig$',
                ]
                for pattern in critical_patterns:
                    if re.search(pattern, str(abs_path)):
                        raise ValidationError(
                            "Cannot overwrite critical system file",
                            field="file_path",
                            value=file_path
                        )
            
            if create_dirs:
                abs_path.parent.mkdir(parents=True, exist_ok=True)
            elif not abs_path.parent.exists():
                raise ValidationError(
                    "Parent directory does not exist",
                    field="file_path",
                    value=file_path
                )
            
            abs_path.write_text(content, encoding="utf-8")
            
            return {
                "file_path": str(abs_path),
                "size": len(content),
                "created_dirs": create_dirs and not abs_path.parent.exists()
            }
        except (ValidationError, InfrastructureError):
            raise
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
        """List directory contents with path validation."""
        try:
            path = Path(directory_path)
            
            # Resolve to absolute path and check for directory traversal
            try:
                abs_path = path.resolve()
                # Ensure the directory is within allowed paths
                cwd = self.working_directory.resolve()
                if not (abs_path == cwd or cwd in abs_path.parents):
                    # Allow listing from common system directories
                    allowed_dirs = [
                        Path("/etc").resolve(),
                        Path("/usr").resolve(), 
                        Path("/opt").resolve(),
                        Path.home().resolve()
                    ]
                    if not any(abs_path == allowed or allowed in abs_path.parents for allowed in allowed_dirs):
                        raise ValidationError(
                            "Access denied: directory is outside allowed directories",
                            field="directory_path",
                            value=directory_path
                        )
            except Exception as e:
                if isinstance(e, ValidationError):
                    raise
                raise ValidationError(
                    f"Invalid directory path: {str(e)}",
                    field="directory_path",
                    value=directory_path
                )
            
            if not abs_path.exists():
                raise InfrastructureError(
                    f"Directory not found: {directory_path}",
                    context={"directory_path": directory_path}
                )
            
            if not abs_path.is_dir():
                raise ValidationError(
                    f"Path is not a directory: {directory_path}",
                    field="directory_path",
                    value=directory_path
                )
            
            items = []
            for item in abs_path.iterdir():
                if not show_hidden and item.name.startswith('.'):
                    continue
                
                try:
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else None
                    })
                except Exception:
                    # Skip items that fail validation
                    logger.warning(f"Skipping invalid path in directory listing: {item}")
                    continue
            
            return {
                "directory_path": str(abs_path),
                "items": sorted(items, key=lambda x: (x["type"], x["name"])),
                "total_items": len(items)
            }
        except ValidationError as e:
            raise InfrastructureError(
                f"Invalid directory path: {str(e)}",
                context={"directory_path": directory_path, "operation": "list_directory"}
            )
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
        # Validate target name
        if not re.match(r'^[\w\-\.]+$', target):
            raise ValidationError(
                "Invalid make target name",
                field="target",
                value=target
            )
        
        # Build command safely
        command = f"make {shlex.quote(target)}"
        if args:
            # Validate and quote additional arguments
            try:
                # Parse args to ensure they're valid
                arg_parts = shlex.split(args)
                # Quote each argument part
                quoted_args = ' '.join(shlex.quote(arg) for arg in arg_parts)
                command += f" {quoted_args}"
            except ValueError as e:
                raise ValidationError(
                    f"Invalid make arguments: {str(e)}",
                    field="args",
                    value=args
                )
        
        return await self._execute_command(command, str(self.working_directory))


class DockerMCPServer(MCPServer):
    """
    Docker MCP Server for CODE project.
    
    Provides Docker container management capabilities for infrastructure deployment.
    """
    
    def __init__(self, permission_checker: Optional[Any] = None):
        """Initialize Docker MCP Server."""
        super().__init__(name="docker", version="1.0.0", permission_checker=permission_checker)
        self.docker_available = None
        
        # Update capabilities
        self.capabilities = MCPCapabilities(
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
        
        # Set up tool-specific permissions
        self.tool_permissions = {
            "docker_run": "mcp.docker.container:execute",
            "docker_build": "mcp.docker.image:build",
            "docker_compose": "mcp.docker.compose:execute",
            "docker_ps": "mcp.docker.container:list"
        }
        
        # Register resource permissions if permission checker available
        if self.permission_checker:
            self.register_resource_permissions()
    
    async def _check_docker(self) -> bool:
        """Check if Docker is available."""
        if self.docker_available is None:
            try:
                process = await asyncio.create_subprocess_exec(
                    "docker", "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                self.docker_available = process.returncode == 0
            except Exception:
                self.docker_available = False
        
        return self.docker_available
    
    def _validate_docker_image(self, image: str) -> bool:
        """Validate Docker image name format."""
        if not image or len(image) > 256:
            raise ValidationError(
                "Invalid Docker image name length",
                field="image",
                value=image
            )
        
        if not DOCKER_IMAGE_PATTERN.match(image):
            raise ValidationError(
                "Invalid Docker image name format",
                field="image", 
                value=image
            )
        
        return True
    
    def _validate_docker_volume(self, volume: str) -> bool:
        """Validate Docker volume mount."""
        if ':' not in volume:
            raise ValidationError(
                "Volume must be in host:container format",
                field="volume",
                value=volume
            )
        
        parts = volume.split(':')
        if len(parts) < 2 or len(parts) > 3:
            raise ValidationError(
                "Volume format must be host:container[:options]",
                field="volume",
                value=volume
            )
        
        host_path, container_path = parts[0], parts[1]
        
        # Validate paths don't contain dangerous patterns
        dangerous_patterns = ['..', '/etc', '/boot', '/sys', '/dev', '/proc']
        for pattern in dangerous_patterns:
            if pattern in host_path or pattern in container_path:
                raise ValidationError(
                    f"Volume path contains dangerous pattern: {pattern}",
                    field="volume",
                    value=volume
                )
        
        return True
    
    def _validate_docker_port(self, port: str) -> bool:
        """Validate Docker port mapping."""
        if ':' not in port:
            # Container port only
            try:
                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    raise ValidationError(
                        "Port must be between 1 and 65535",
                        field="port",
                        value=port
                    )
            except ValueError:
                raise ValidationError(
                    "Invalid port format",
                    field="port",
                    value=port
                )
        else:
            # Host:container port mapping
            parts = port.split(':')
            if len(parts) != 2:
                raise ValidationError(
                    "Port mapping must be host:container format",
                    field="port",
                    value=port
                )
            
            try:
                host_port, container_port = int(parts[0]), int(parts[1])
                if not (1 <= host_port <= 65535) or not (1 <= container_port <= 65535):
                    raise ValidationError(
                        "Ports must be between 1 and 65535",
                        field="port",
                        value=port
                    )
            except ValueError:
                raise ValidationError(
                    "Invalid port mapping format",
                    field="port",
                    value=port
                )
        
        return True
    
    # Remove duplicate get_server_info - inherits from MCPServer now
    
    def _get_all_tools(self) -> List[MCPTool]:
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
    
    async def _call_tool_impl(self, tool_name: str, arguments: Dict[str, Any], 
                             user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a Docker tool with proper authentication."""
        if not await self._check_docker():
            raise DockerError(
                "Docker is not available on this system",
                context={"tool_name": tool_name, "user_id": user.id}
            )
        
        # Log user action for security auditing
        logger.info(f"User {user.username} executing Docker tool: {tool_name}")
        
        try:
            if tool_name == "docker_run":
                return await self._docker_run(**arguments, user=user)
            elif tool_name == "docker_build":
                return await self._docker_build(**arguments, user=user)
            elif tool_name == "docker_compose":
                return await self._docker_compose(**arguments, user=user)
            elif tool_name == "docker_ps":
                return await self._docker_ps(**arguments, user=user)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except DockerError:
            raise
        except Exception as e:
            error = DockerError(
                f"Error calling Docker tool {tool_name} for user {user.username}",
                context={"tool_name": tool_name, "arguments": arguments, "user_id": user.id},
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
        ports: Optional[List[str]] = None,
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Run a Docker container with security validation."""
        # Validate image name
        self._validate_docker_image(image)
        
        cmd_parts = ["docker", "run", "--rm"]
        
        # Add security flags
        cmd_parts.extend([
            "--security-opt", "no-new-privileges:true",  # Prevent privilege escalation
            "--read-only",  # Read-only root filesystem
            "--tmpfs", "/tmp",  # Writable /tmp
            "--user", "1000:1000"  # Non-root user
        ])
        
        # Add volumes with validation
        if volumes:
            for volume in volumes:
                self._validate_docker_volume(volume)
                cmd_parts.extend(["-v", volume])
        
        # Add environment variables with validation
        if environment:
            for key, value in environment.items():
                # Validate environment variable names
                if not re.match(r'^[A-Z_][A-Z0-9_]*$', key):
                    raise ValidationError(
                        "Invalid environment variable name",
                        field="environment",
                        value=key
                    )
                # Escape value to prevent injection
                cmd_parts.extend(["-e", f"{key}={shlex.quote(value)}"])
        
        # Add port mappings with validation
        if ports:
            for port in ports:
                self._validate_docker_port(port)
                cmd_parts.extend(["-p", port])
        
        # Add image
        cmd_parts.append(image)
        
        # Add command with validation
        if command:
            # Parse command safely and validate
            try:
                command_parts = shlex.split(command)
                # Basic validation - command should not contain dangerous patterns
                for part in command_parts:
                    for pattern in INJECTION_PATTERNS:
                        if pattern.search(part):
                            raise ValidationError(
                                "Command contains dangerous pattern",
                                field="command",
                                value=command
                            )
                # Additional validation for the base command
                if command_parts and command_parts[0] not in ALLOWED_COMMANDS:
                    base_cmd = os.path.basename(command_parts[0])
                    if base_cmd not in ALLOWED_COMMANDS:
                        raise ValidationError(
                            f"Command '{command_parts[0]}' is not allowed in container",
                            field="command",
                            value=command
                        )
                cmd_parts.extend(command_parts)
            except ValueError as e:
                raise ValidationError(
                    f"Invalid command syntax: {str(e)}",
                    field="command",
                    value=command
                )
        
        logger.info(f"Executing Docker run with validated arguments: {' '.join(cmd_parts[:5])}...")
        
        try:
            # Use subprocess.exec with explicit arguments (no shell=True)
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Limit environment
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
            )
            
            # Add timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=600  # 10 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise DockerError(
                    "Docker run timed out after 10 minutes",
                    image=image
                )
            
            return {
                "command": " ".join(cmd_parts),
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except (DockerError, ValidationError):
            raise
        except Exception as e:
            raise DockerError(
                f"Docker run failed: {str(e)}",
                image=image,
                context={
                    "command_parts": cmd_parts,
                    "exit_code": process.returncode if 'process' in locals() else None
                },
                cause=e
            )
    
    async def _docker_build(
        self,
        dockerfile_path: str,
        image_tag: str,
        build_context: str = ".",
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Build Docker image with security validation."""
        # Validate image tag
        self._validate_docker_image(image_tag)
        
        # Validate dockerfile path
        try:
            dockerfile_path_obj = Path(dockerfile_path).resolve()
            if not dockerfile_path_obj.exists():
                raise ValidationError(
                    "Dockerfile does not exist",
                    field="dockerfile_path",
                    value=dockerfile_path
                )
            if not dockerfile_path_obj.is_file():
                raise ValidationError(
                    "Dockerfile path is not a file",
                    field="dockerfile_path",
                    value=dockerfile_path
                )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(
                f"Invalid dockerfile path: {str(e)}",
                field="dockerfile_path",
                value=dockerfile_path
            )
        
        # Validate build context
        try:
            build_context_path = Path(build_context).resolve()
            if not build_context_path.exists():
                raise ValidationError(
                    "Build context does not exist",
                    field="build_context",
                    value=build_context
                )
            if not build_context_path.is_dir():
                raise ValidationError(
                    "Build context is not a directory",
                    field="build_context",
                    value=build_context
                )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(
                f"Invalid build context: {str(e)}",
                field="build_context",
                value=build_context
            )
        
        # Build command safely
        cmd_parts = [
            "docker", "build",
            "-f", str(dockerfile_path_obj),
            "-t", image_tag,
            str(build_context_path)
        ]
        
        logger.info(f"Executing Docker build with validated arguments: {' '.join(cmd_parts)}")
        
        try:
            # Use subprocess.exec with explicit arguments (no shell=True)
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
            )
            
            # Add timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1800  # 30 minute timeout for builds
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise DockerError(
                    "Docker build timed out after 30 minutes",
                    image=image_tag
                )
            
            return {
                "command": " ".join(cmd_parts),
                "image_tag": image_tag,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8'),
                "success": process.returncode == 0
            }
        except (DockerError, ValidationError):
            raise
        except Exception as e:
            raise DockerError(
                f"Docker build failed: {str(e)}",
                image=image_tag,
                context={
                    "dockerfile_path": dockerfile_path,
                    "build_context": build_context,
                    "exit_code": process.returncode if 'process' in locals() else None
                },
                cause=e
            )
    
    async def _docker_compose(
        self,
        action: str,
        compose_file: str = "docker-compose.yml",
        services: Optional[List[str]] = None,
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Execute docker-compose commands."""
        cmd_parts = ["docker-compose", "-f", compose_file, action]
        
        if services:
            cmd_parts.extend(services)
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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
    
    async def _docker_ps(self, all: bool = False, user: Optional[Any] = None) -> Dict[str, Any]:
        """List Docker containers."""
        cmd_parts = ["docker", "ps", "--format", "json"]
        if all:
            cmd_parts.append("-a")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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
    
    def __init__(self, permission_checker: Optional[Any] = None):
        """Initialize Kubernetes MCP Server."""
        super().__init__(name="kubernetes", version="1.0.0", permission_checker=permission_checker)
        self.kubectl_available = None
        
        # Update capabilities
        self.capabilities = MCPCapabilities(
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
        
        # Set up tool-specific permissions
        self.tool_permissions = {
            "kubectl_apply": "mcp.kubernetes.deployment:execute",
            "kubectl_get": "mcp.kubernetes.resource:read",
            "kubectl_delete": "mcp.kubernetes.resource:delete",
            "kubectl_logs": "mcp.kubernetes.pod:read",
            "kubectl_describe": "mcp.kubernetes.resource:read"
        }
        
        # Register resource permissions if permission checker available
        if self.permission_checker:
            self.register_resource_permissions()
    
    async def _check_kubectl(self) -> bool:
        """Check if kubectl is available."""
        if self.kubectl_available is None:
            try:
                process = await asyncio.create_subprocess_exec(
                    "kubectl", "version", "--client",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                self.kubectl_available = process.returncode == 0
            except Exception:
                self.kubectl_available = False
        
        return self.kubectl_available
    
    def _validate_k8s_resource_type(self, resource_type: str) -> bool:
        """Validate Kubernetes resource type."""
        if not resource_type or resource_type not in K8S_SAFE_RESOURCES:
            raise ValidationError(
                f"Invalid or unsafe Kubernetes resource type: {resource_type}",
                field="resource_type",
                value=resource_type
            )
        return True
    
    def _validate_k8s_name(self, name: str, field_name: str) -> bool:
        """Validate Kubernetes resource name."""
        if not name or len(name) > 253:
            raise ValidationError(
                f"Invalid Kubernetes {field_name} length",
                field=field_name,
                value=name
            )
        
        if not K8S_NAME_PATTERN.match(name):
            raise ValidationError(
                f"Invalid Kubernetes {field_name} format",
                field=field_name,
                value=name
            )
        
        return True
    
    def _validate_k8s_namespace(self, namespace: str) -> bool:
        """Validate Kubernetes namespace."""
        return self._validate_k8s_name(namespace, "namespace")
    
    # Remove duplicate get_server_info - inherits from MCPServer now
    
    def _get_all_tools(self) -> List[MCPTool]:
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
    
    async def _call_tool_impl(self, tool_name: str, arguments: Dict[str, Any], 
                             user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a Kubernetes tool with proper authentication."""
        if not await self._check_kubectl():
            raise KubernetesError(
                "kubectl is not available on this system",
                context={"tool_name": tool_name, "user_id": user.id}
            )
        
        # Log user action for security auditing
        logger.info(f"User {user.username} executing Kubernetes tool: {tool_name}")
        
        try:
            if tool_name == "kubectl_apply":
                return await self._kubectl_apply(**arguments, user=user)
            elif tool_name == "kubectl_get":
                return await self._kubectl_get(**arguments, user=user)
            elif tool_name == "kubectl_delete":
                return await self._kubectl_delete(**arguments, user=user)
            elif tool_name == "kubectl_logs":
                return await self._kubectl_logs(**arguments, user=user)
            elif tool_name == "kubectl_describe":
                return await self._kubectl_describe(**arguments, user=user)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except KubernetesError:
            raise
        except Exception as e:
            error = KubernetesError(
                f"Error calling Kubernetes tool {tool_name} for user {user.username}",
                context={"tool_name": tool_name, "arguments": arguments, "user_id": user.id},
                cause=e
            )
            handle_error(error, logger)
            raise error
    
    async def _kubectl_apply(
        self,
        manifest_path: str,
        namespace: str = "default",
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Apply Kubernetes manifests with security validation."""
        # Validate namespace
        self._validate_k8s_namespace(namespace)
        
        # Validate manifest path
        try:
            manifest_path_obj = Path(manifest_path).resolve()
            if not manifest_path_obj.exists():
                raise ValidationError(
                    "Manifest file does not exist",
                    field="manifest_path",
                    value=manifest_path
                )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(
                f"Invalid manifest path: {str(e)}",
                field="manifest_path",
                value=manifest_path
            )
        
        # Build command safely
        cmd_parts = ["kubectl", "apply", "-f", str(manifest_path_obj), "-n", namespace]
        
        logger.info(f"Executing kubectl apply with validated arguments: {' '.join(cmd_parts)}")
        
        try:
            # Use subprocess.exec with explicit arguments (no shell=True)
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": " ".join(cmd_parts),
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
                    "command": " ".join(cmd_parts),
                    "exit_code": process.returncode if 'process' in locals() else None,
                    "stderr": stderr.decode('utf-8') if 'stderr' in locals() else None
                },
                cause=e
            )
    
    async def _kubectl_get(
        self,
        resource_type: str,
        namespace: str = "default",
        resource_name: Optional[str] = None,
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Get Kubernetes resources."""
        cmd_parts = ["kubectl", "get", resource_type, "-n", namespace, "-o", "json"]
        
        if resource_name:
            cmd_parts.insert(-2, resource_name)  # Insert before -o json
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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
        namespace: str = "default",
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Delete Kubernetes resources."""
        cmd_parts = ["kubectl", "delete", resource_type, resource_name, "-n", namespace]
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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
        tail: int = 100,
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Get pod logs."""
        cmd_parts = ["kubectl", "logs", pod_name, "-n", namespace, "--tail", str(tail)]
        
        if container:
            cmd_parts.extend(["-c", container])
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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
        namespace: str = "default",
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Describe Kubernetes resources."""
        cmd_parts = ["kubectl", "describe", resource_type, resource_name, "-n", namespace]
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
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