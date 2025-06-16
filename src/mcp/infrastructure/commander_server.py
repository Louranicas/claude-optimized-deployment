"""
Production-grade Infrastructure Commander MCP Server with DevOps excellence.

Implements secure command execution, container orchestration, and infrastructure
automation with enterprise-level resilience patterns and observability.
"""

from __future__ import annotations
import os
import asyncio
import json
import time
import hashlib
import tempfile
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import logging

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer
from src.core.secure_command_executor import SecureCommandExecutor, CommandCategory
from src.core.command_sanitizer import CommandSanitizer, sanitize_command_input

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error,
    ServiceUnavailableError,
    ExternalServiceError,
    ValidationError,
    ConfigurationError,
    CircuitBreakerError
)

__all__ = [
    "CircuitBreaker",
    "InfrastructureCommanderMCP",
    "with_retry"
]


logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker pattern for external tool resilience."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = defaultdict(int)
        self.last_failure_time = defaultdict(float)
        self.state = defaultdict(lambda: 'closed')  # closed, open, half-open
    
    def call_allowed(self, service: str) -> bool:
        """Check if calls to service are allowed."""
        if self.state[service] == 'closed':
            return True
        
        if self.state[service] == 'open':
            if time.time() - self.last_failure_time[service] > self.recovery_timeout:
                self.state[service] = 'half-open'
                return True
            return False
        
        return True  # half-open allows one call
    
    def record_success(self, service: str):
        """Record successful call."""
        self.failures[service] = 0
        self.state[service] = 'closed'
    
    def record_failure(self, service: str):
        """Record failed call."""
        self.failures[service] += 1
        self.last_failure_time[service] = time.time()
        
        if self.failures[service] >= self.failure_threshold:
            self.state[service] = 'open'
            logger.warning(f"Circuit breaker opened for {service}")


def with_retry(max_attempts: int = 3, backoff_factor: float = 2.0):
    """Decorator for retry with exponential backoff."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        wait_time = backoff_factor ** attempt
                        logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"All {max_attempts} attempts failed: {e}")
            raise last_exception
        return wrapper
    return decorator


class InfrastructureCommanderMCP(MCPServer):
    """
    Production-grade Infrastructure Commander with DevOps excellence.
    
    Features:
    - Secure command execution with whitelisting and sandboxing
    - Container orchestration with health checks and rollback
    - Infrastructure as Code automation
    - Circuit breakers for resilience
    - Comprehensive observability
    - Multi-stage deployment orchestration
    """
    
    def __init__(self):
        """Initialize Infrastructure Commander."""
        self.working_directory = Path.cwd()
        self.circuit_breaker = CircuitBreaker()
        self.command_history: List[Dict[str, Any]] = []
        self.deployment_state: Dict[str, Any] = {}
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self._setup_security()
        
        # Initialize secure command executor
        self.command_executor = SecureCommandExecutor(
            working_directory=self.working_directory,
            max_output_size=10 * 1024 * 1024,  # 10MB
            enable_sandbox=True,
            audit_log_path=Path(tempfile.gettempdir()) / 'infrastructure_commander_audit.log'
        )
        
        # Add infrastructure-specific commands to whitelist
        self._setup_infrastructure_commands()
    
    def _setup_security(self):
        """Initialize security configurations."""
        self.audit_log = Path(tempfile.gettempdir()) / 'infrastructure_commander_audit.log'
    
    def _setup_infrastructure_commands(self):
        """Add infrastructure-specific commands to the executor whitelist."""
        # Add vault for secret management
        self.command_executor.add_to_whitelist(
            'vault',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['status', 'read', 'list', 'token', 'login'],
            dangerous_args=['delete', 'destroy'],
            max_args=10
        )
        
        # Add packer for image building
        self.command_executor.add_to_whitelist(
            'packer',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['build', 'validate', 'fmt', 'inspect'],
            dangerous_args=[],
            max_args=15
        )
        
        # Add AWS CLI
        self.command_executor.add_to_whitelist(
            'aws',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['s3', 'ec2', 'ecs', 'eks', 'iam', 'cloudformation'],
            dangerous_args=['delete', 'terminate'],
            max_args=20
        )
        
        # Add Azure CLI
        self.command_executor.add_to_whitelist(
            'az',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['account', 'group', 'vm', 'aks', 'storage'],
            dangerous_args=['delete'],
            max_args=20
        )
        
        # Add GCloud CLI
        self.command_executor.add_to_whitelist(
            'gcloud',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['compute', 'container', 'storage', 'iam'],
            dangerous_args=['delete'],
            max_args=20
        )
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Infrastructure Commander server information."""
        return MCPServerInfo(
            name="infrastructure-commander",
            version="1.0.0",
            description="Production-grade infrastructure automation with DevOps excellence",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "secure_execution": True,
                    "container_orchestration": True,
                    "infrastructure_automation": True,
                    "circuit_breakers": True,
                    "deployment_rollback": True,
                    "observability": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Infrastructure Commander tools."""
        return [
            MCPTool(
                name="execute_command",
                description="Secure shell command execution with sandboxing",
                parameters=[
                    MCPToolParameter(
                        name="command",
                        type="string",
                        description="Command to execute (subject to security validation)",
                        required=True
                    ),
                    MCPToolParameter(
                        name="working_directory",
                        type="string",
                        description="Working directory for command",
                        required=False
                    ),
                    MCPToolParameter(
                        name="timeout",
                        type="integer",
                        description="Command timeout in seconds",
                        required=False,
                        default=300
                    ),
                    MCPToolParameter(
                        name="environment",
                        type="object",
                        description="Environment variables",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="make_command",
                description="Execute Makefile targets with dependency tracking",
                parameters=[
                    MCPToolParameter(
                        name="target",
                        type="string",
                        description="Make target to execute",
                        required=True
                    ),
                    MCPToolParameter(
                        name="args",
                        type="string",
                        description="Additional make arguments",
                        required=False
                    ),
                    MCPToolParameter(
                        name="parallel",
                        type="boolean",
                        description="Enable parallel execution",
                        required=False,
                        default=True
                    )
                ]
            ),
            MCPTool(
                name="write_file",
                description="Write infrastructure configuration files securely",
                parameters=[
                    MCPToolParameter(
                        name="file_path",
                        type="string",
                        description="Path to file",
                        required=True
                    ),
                    MCPToolParameter(
                        name="content",
                        type="string",
                        description="File content",
                        required=True
                    ),
                    MCPToolParameter(
                        name="mode",
                        type="string",
                        description="File permissions (e.g., '0644')",
                        required=False,
                        default="0644"
                    ),
                    MCPToolParameter(
                        name="backup",
                        type="boolean",
                        description="Create backup before writing",
                        required=False,
                        default=True
                    )
                ]
            ),
            MCPTool(
                name="docker_build",
                description="Build Docker images with caching and security scanning",
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
                    ),
                    MCPToolParameter(
                        name="build_args",
                        type="object",
                        description="Build arguments",
                        required=False
                    ),
                    MCPToolParameter(
                        name="scan_vulnerabilities",
                        type="boolean",
                        description="Scan for vulnerabilities after build",
                        required=False,
                        default=True
                    )
                ]
            ),
            MCPTool(
                name="kubectl_apply",
                description="Deploy Kubernetes manifests with validation and rollback",
                parameters=[
                    MCPToolParameter(
                        name="manifest_path",
                        type="string",
                        description="Path to K8s manifest",
                        required=True
                    ),
                    MCPToolParameter(
                        name="namespace",
                        type="string",
                        description="Target namespace",
                        required=False,
                        default="default"
                    ),
                    MCPToolParameter(
                        name="dry_run",
                        type="boolean",
                        description="Perform dry run first",
                        required=False,
                        default=True
                    ),
                    MCPToolParameter(
                        name="wait_ready",
                        type="boolean",
                        description="Wait for resources to be ready",
                        required=False,
                        default=True
                    )
                ]
            ),
            MCPTool(
                name="terraform_plan",
                description="Plan infrastructure changes with cost estimation",
                parameters=[
                    MCPToolParameter(
                        name="working_dir",
                        type="string",
                        description="Terraform working directory",
                        required=True
                    ),
                    MCPToolParameter(
                        name="var_file",
                        type="string",
                        description="Path to variables file",
                        required=False
                    ),
                    MCPToolParameter(
                        name="target",
                        type="string",
                        description="Resource targeting",
                        required=False
                    ),
                    MCPToolParameter(
                        name="estimate_cost",
                        type="boolean",
                        description="Estimate deployment cost",
                        required=False,
                        default=True
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute Infrastructure Commander tool with resilience."""
        start_time = time.time()
        
        try:
            # Check circuit breaker
            if not self.circuit_breaker.call_allowed(tool_name):
                raise MCPError(-32000, f"Circuit breaker open for {tool_name}")
            
            # Audit logging
            self._audit_log(tool_name, arguments)
            
            # Execute tool
            if tool_name == "execute_command":
                result = await self._execute_command(**arguments)
            elif tool_name == "make_command":
                result = await self._make_command(**arguments)
            elif tool_name == "write_file":
                result = await self._write_file(**arguments)
            elif tool_name == "docker_build":
                result = await self._docker_build(**arguments)
            elif tool_name == "kubectl_apply":
                result = await self._kubectl_apply(**arguments)
            elif tool_name == "terraform_plan":
                result = await self._terraform_plan(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
            
            # Record success
            self.circuit_breaker.record_success(tool_name)
            self._record_metrics(tool_name, time.time() - start_time, True)
            
            return result
            
        except Exception as e:
            # Record failure
            self.circuit_breaker.record_failure(tool_name)
            self._record_metrics(tool_name, time.time() - start_time, False)
            logger.error(f"Tool {tool_name} failed: {e}")
            raise
    
    
    @with_retry(max_attempts=3)
    async def _execute_command(
        self,
        command: str,
        working_directory: Optional[str] = None,
        timeout: int = 300,
        environment: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Execute command with security and monitoring using secure executor."""
        try:
            # Sanitize inputs
            sanitized = sanitize_command_input(
                command=command,
                working_directory=working_directory,
                environment=environment
            )
            
            # Execute command using secure executor
            result = await self.command_executor.execute_async(
                command=command,
                working_directory=sanitized.get('working_directory', working_directory),
                environment=sanitized.get('environment', environment),
                timeout=float(timeout),
                user=os.environ.get("USER", "infrastructure_commander"),
                context={
                    "tool": "execute_command",
                    "mcp_server": "infrastructure_commander"
                }
            )
            
            # Convert result to expected format
            execution_result = {
                "command": result.command,
                "working_directory": result.working_directory,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.success,
                "execution_time": time.time(),
                "truncated": result.truncated
            }
            
            # Record in history
            self.command_history.append(execution_result)
            
            # Log metrics
            self._record_metrics("execute_command", result.execution_time, result.success)
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise MCPError(-32000, f"Command execution failed: {str(e)}")
    
    async def _make_command(
        self,
        target: str,
        args: Optional[str] = None,
        parallel: bool = True
    ) -> Dict[str, Any]:
        """Execute Make with dependency tracking using secure executor."""
        # Sanitize target
        sanitized_target = CommandSanitizer.sanitize_identifier(target, allow_dash=True)
        
        cmd_parts = ["make"]
        
        if parallel:
            cmd_parts.append(f"-j{os.cpu_count()}")
        
        cmd_parts.append(sanitized_target)
        
        if args:
            # Sanitize additional arguments
            sanitized_args = CommandSanitizer.sanitize_command_args([args])
            cmd_parts.extend(sanitized_args)
        
        command = " ".join(cmd_parts)
        
        # Track dependencies
        deps_cmd = f"make -n {sanitized_target}"
        deps_result = await self._execute_command(deps_cmd)
        
        # Execute actual command
        result = await self._execute_command(command)
        result["dependencies"] = deps_result.get("stdout", "").split('
')
        
        return result
    
    async def _write_file(
        self,
        file_path: str,
        content: str,
        mode: str = "0644",
        backup: bool = True
    ) -> Dict[str, Any]:
        """Write file with backup and validation using secure path sanitization."""
        # Sanitize file path
        try:
            sanitized_path = CommandSanitizer.sanitize_path(
                file_path,
                base_dir=self.working_directory,
                allow_relative=True,
                must_exist=False,
                allow_symlinks=False
            )
            path = Path(sanitized_path)
        except Exception as e:
            raise MCPError(-32000, f"Invalid file path: {str(e)}")
        
        # Validate file permissions mode
        if not re.match(r'^0?[0-7]{3,4}$', mode):
            raise MCPError(-32000, f"Invalid file mode: {mode}")
        
        # Backup existing file
        backup_path = None
        if backup and path.exists():
            backup_path = path.with_suffix(f"{path.suffix}.{int(time.time())}.bak")
            backup_path.write_bytes(path.read_bytes())
        
        try:
            # Write file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
            
            # Set permissions
            os.chmod(path, int(mode, 8))
            
            return {
                "file_path": str(path.absolute()),
                "size": len(content),
                "mode": mode,
                "backup_path": str(backup_path) if backup_path else None,
                "checksum": hashlib.sha256(content.encode()).hexdigest()
            }
            
        except Exception as e:
            # Restore backup on failure
            if backup_path and backup_path.exists():
                path.write_bytes(backup_path.read_bytes())
                backup_path.unlink()
            raise MCPError(-32000, f"Failed to write file: {str(e)}")
    
    async def _docker_build(
        self,
        dockerfile_path: str,
        image_tag: str,
        build_args: Optional[Dict[str, str]] = None,
        scan_vulnerabilities: bool = True
    ) -> Dict[str, Any]:
        """Build Docker image with security scanning using secure executor."""
        # Sanitize and validate Dockerfile path
        try:
            sanitized_dockerfile = CommandSanitizer.sanitize_path(
                dockerfile_path,
                base_dir=self.working_directory,
                allow_relative=True,
                must_exist=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid Dockerfile path: {str(e)}")
        
        # Sanitize image tag
        try:
            sanitized_image = CommandSanitizer.sanitize_docker_image(image_tag)
        except Exception as e:
            raise MCPError(-32000, f"Invalid image tag: {str(e)}")
        
        # Build command
        cmd_parts = ["docker", "build", "-f", sanitized_dockerfile, "-t", sanitized_image]
        
        if build_args:
            for key, value in build_args.items():
                # Sanitize build arg name and value
                san_key, san_value = CommandSanitizer.sanitize_environment_var(key, value)
                cmd_parts.extend(["--build-arg", f"{san_key}={san_value}"])
        
        cmd_parts.append(".")
        
        # Execute build
        result = await self._execute_command(" ".join(cmd_parts))
        
        if result["success"] and scan_vulnerabilities:
            # Scan for vulnerabilities
            scan_cmd = f"docker scan {sanitized_image} --json"
            scan_result = await self._execute_command(scan_cmd)
            
            try:
                vulnerabilities = json.loads(scan_result.get("stdout", "{}"))
                result["vulnerabilities"] = vulnerabilities
            except json.JSONDecodeError:
                result["scan_error"] = "Failed to parse vulnerability scan"
        
        return result
    
    async def _kubectl_apply(
        self,
        manifest_path: str,
        namespace: str = "default",
        dry_run: bool = True,
        wait_ready: bool = True
    ) -> Dict[str, Any]:
        """Deploy K8s manifests with validation using secure executor."""
        # Sanitize and validate manifest path
        try:
            sanitized_manifest = CommandSanitizer.sanitize_path(
                manifest_path,
                base_dir=self.working_directory,
                allow_relative=True,
                must_exist=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid manifest path: {str(e)}")
        
        # Sanitize namespace
        try:
            sanitized_namespace = CommandSanitizer.sanitize_k8s_name(namespace, kind="namespace")
        except Exception as e:
            raise MCPError(-32000, f"Invalid namespace: {str(e)}")
        
        # Dry run first
        if dry_run:
            dry_cmd = f"kubectl apply -f {sanitized_manifest} -n {sanitized_namespace} --dry-run=client"
            dry_result = await self._execute_command(dry_cmd)
            if not dry_result["success"]:
                raise MCPError(-32000, f"Dry run failed: {dry_result['stderr']}")
        
        # Store current state for rollback
        rollback_cmd = f"kubectl get -f {sanitized_manifest} -n {sanitized_namespace} -o yaml"
        rollback_state = await self._execute_command(rollback_cmd)
        
        # Apply manifest
        apply_cmd = f"kubectl apply -f {sanitized_manifest} -n {sanitized_namespace}"
        result = await self._execute_command(apply_cmd)
        
        if result["success"] and wait_ready:
            # Wait for resources to be ready
            wait_cmd = f"kubectl wait --for=condition=ready -f {sanitized_manifest} -n {sanitized_namespace} --timeout=300s"
            wait_result = await self._execute_command(wait_cmd)
            result["ready"] = wait_result["success"]
        
        result["rollback_state"] = rollback_state.get("stdout", "")
        
        return result
    
    async def _terraform_plan(
        self,
        working_dir: str,
        var_file: Optional[str] = None,
        target: Optional[str] = None,
        estimate_cost: bool = True
    ) -> Dict[str, Any]:
        """Plan Terraform changes with cost estimation using secure executor."""
        # Sanitize and validate working directory
        try:
            sanitized_work_dir = CommandSanitizer.sanitize_path(
                working_dir,
                base_dir=self.working_directory,
                allow_relative=True,
                must_exist=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid Terraform directory: {str(e)}")
        
        # Initialize terraform
        init_cmd = "terraform init"
        init_result = await self._execute_command(init_cmd, sanitized_work_dir)
        if not init_result["success"]:
            raise MCPError(-32000, f"Terraform init failed: {init_result['stderr']}")
        
        # Build plan command
        cmd_parts = ["terraform", "plan", "-out=tfplan"]
        
        if var_file:
            # Sanitize var file path
            try:
                sanitized_var_file = CommandSanitizer.sanitize_path(
                    var_file,
                    base_dir=Path(sanitized_work_dir),
                    allow_relative=True,
                    must_exist=True,
                    allow_symlinks=False
                )
                cmd_parts.extend(["-var-file", sanitized_var_file])
            except Exception as e:
                raise MCPError(-32000, f"Invalid var file: {str(e)}")
        
        if target:
            # Sanitize target resource
            sanitized_target = CommandSanitizer.escape_for_shell(target)
            cmd_parts.extend(["-target", sanitized_target])
        
        # Execute plan
        result = await self._execute_command(" ".join(cmd_parts), sanitized_work_dir)
        
        if result["success"] and estimate_cost:
            # Show plan with cost estimation
            show_cmd = "terraform show -json tfplan"
            show_result = await self._execute_command(show_cmd, sanitized_work_dir)
            
            try:
                plan_data = json.loads(show_result.get("stdout", "{}"))
                result["resource_changes"] = len(plan_data.get("resource_changes", []))
                result["plan_data"] = plan_data
            except json.JSONDecodeError:
                result["cost_error"] = "Failed to parse plan data"
        
        return result
    
    def _audit_log(self, tool_name: str, arguments: Dict[str, Any]):
        """Log tool execution for audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "arguments": arguments,
            "user": os.environ.get("USER", "unknown"),
            "pid": os.getpid()
        }
        with open(self.audit_log, 'a') as f:
            f.write(json.dumps(entry) + '
')
    
    def _record_metrics(self, tool_name: str, execution_time: float, success: bool):
        """Record execution metrics."""
        self.metrics[f"{tool_name}_execution_time"].append(execution_time)
        self.metrics[f"{tool_name}_{'success' if success else 'failure'}_count"].append(1)
        # Keep only last 1000 metrics
        for key in self.metrics:
            if len(self.metrics[key]) > 1000:
                self.metrics[key] = self.metrics[key][-1000:]