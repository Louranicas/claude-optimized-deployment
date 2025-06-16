"""
Health Validation System

Comprehensive health check and validation automation for MCP servers
with customizable checks, timeout handling, and detailed reporting.
"""

from __future__ import annotations
import asyncio
import aiohttp
import time
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import socket
import subprocess
from pathlib import Path

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError

logger = get_logger(__name__)


class HealthCheckType(Enum):
    """Types of health checks available"""
    HTTP = "http"
    TCP = "tcp"
    COMMAND = "command"
    CUSTOM = "custom"
    MCP_PROTOCOL = "mcp_protocol"
    DATABASE = "database"
    REDIS = "redis"
    FILE_SYSTEM = "file_system"


class HealthStatus(Enum):
    """Health check status values"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    WARNING = "warning"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class HealthCheckResult:
    """Result of a single health check"""
    check_name: str
    check_type: HealthCheckType
    status: HealthStatus
    duration_ms: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None


@dataclass 
class HealthCheckConfig:
    """Configuration for a health check"""
    name: str
    check_type: HealthCheckType
    config: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    retry_attempts: int = 3
    retry_delay_seconds: float = 1.0
    critical: bool = True  # Whether failure should fail overall health
    tags: List[str] = field(default_factory=list)


class HealthCheck(ABC):
    """Abstract base class for health checks"""
    
    def __init__(self, config: HealthCheckConfig):
        self.config = config
    
    @abstractmethod
    async def execute(self) -> HealthCheckResult:
        """Execute the health check and return result"""
        pass


class HTTPHealthCheck(HealthCheck):
    """HTTP-based health check"""
    
    async def execute(self) -> HealthCheckResult:
        start_time = time.time()
        
        url = self.config.config.get("url", "")
        method = self.config.config.get("method", "GET").upper()
        expected_status = self.config.config.get("expected_status", [200])
        expected_body = self.config.config.get("expected_body")
        headers = self.config.config.get("headers", {})
        
        if not url:
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.HTTP,
                status=HealthStatus.UNHEALTHY,
                duration_ms=0,
                error="URL not configured"
            )
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(method, url, headers=headers) as response:
                    duration_ms = (time.time() - start_time) * 1000
                    
                    # Check status code
                    if response.status not in expected_status:
                        return HealthCheckResult(
                            check_name=self.config.name,
                            check_type=HealthCheckType.HTTP,
                            status=HealthStatus.UNHEALTHY,
                            duration_ms=duration_ms,
                            message=f"Unexpected status code: {response.status}",
                            details={"status_code": response.status, "url": url}
                        )
                    
                    # Check response body if specified
                    if expected_body:
                        body = await response.text()
                        if expected_body not in body:
                            return HealthCheckResult(
                                check_name=self.config.name,
                                check_type=HealthCheckType.HTTP,
                                status=HealthStatus.UNHEALTHY,
                                duration_ms=duration_ms,
                                message="Expected content not found in response",
                                details={"expected": expected_body, "url": url}
                            )
                    
                    return HealthCheckResult(
                        check_name=self.config.name,
                        check_type=HealthCheckType.HTTP,
                        status=HealthStatus.HEALTHY,
                        duration_ms=duration_ms,
                        message="HTTP check successful",
                        details={"status_code": response.status, "url": url}
                    )
                    
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.HTTP,
                status=HealthStatus.TIMEOUT,
                duration_ms=duration_ms,
                message="HTTP request timed out",
                details={"url": url}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.HTTP,
                status=HealthStatus.UNHEALTHY,
                duration_ms=duration_ms,
                error=str(e),
                details={"url": url}
            )


class TCPHealthCheck(HealthCheck):
    """TCP connection health check"""
    
    async def execute(self) -> HealthCheckResult:
        start_time = time.time()
        
        host = self.config.config.get("host", "localhost")
        port = self.config.config.get("port")
        
        if not port:
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.TCP,
                status=HealthStatus.UNHEALTHY,
                duration_ms=0,
                error="Port not configured"
            )
        
        try:
            # Attempt TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.timeout_seconds
            )
            
            # Close connection immediately
            writer.close()
            await writer.wait_closed()
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.TCP,
                status=HealthStatus.HEALTHY,
                duration_ms=duration_ms,
                message="TCP connection successful",
                details={"host": host, "port": port}
            )
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.TCP,
                status=HealthStatus.TIMEOUT,
                duration_ms=duration_ms,
                message="TCP connection timed out",
                details={"host": host, "port": port}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.TCP,
                status=HealthStatus.UNHEALTHY,
                duration_ms=duration_ms,
                error=str(e),
                details={"host": host, "port": port}
            )


class CommandHealthCheck(HealthCheck):
    """Command execution health check"""
    
    async def execute(self) -> HealthCheckResult:
        start_time = time.time()
        
        command = self.config.config.get("command", [])
        expected_exit_code = self.config.config.get("expected_exit_code", 0)
        expected_output = self.config.config.get("expected_output")
        working_directory = self.config.config.get("working_directory")
        
        if not command:
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.COMMAND,
                status=HealthStatus.UNHEALTHY,
                duration_ms=0,
                error="Command not configured"
            )
        
        try:
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_directory
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout_seconds
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check exit code
            if process.returncode != expected_exit_code:
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.COMMAND,
                    status=HealthStatus.UNHEALTHY,
                    duration_ms=duration_ms,
                    message=f"Unexpected exit code: {process.returncode}",
                    details={
                        "command": " ".join(command),
                        "exit_code": process.returncode,
                        "stdout": stdout.decode() if stdout else "",
                        "stderr": stderr.decode() if stderr else ""
                    }
                )
            
            # Check output if specified
            if expected_output:
                output = stdout.decode() if stdout else ""
                if expected_output not in output:
                    return HealthCheckResult(
                        check_name=self.config.name,
                        check_type=HealthCheckType.COMMAND,
                        status=HealthStatus.UNHEALTHY,
                        duration_ms=duration_ms,
                        message="Expected output not found",
                        details={
                            "command": " ".join(command),
                            "expected": expected_output,
                            "actual": output
                        }
                    )
            
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.COMMAND,
                status=HealthStatus.HEALTHY,
                duration_ms=duration_ms,
                message="Command executed successfully",
                details={
                    "command": " ".join(command),
                    "exit_code": process.returncode
                }
            )
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.COMMAND,
                status=HealthStatus.TIMEOUT,
                duration_ms=duration_ms,
                message="Command execution timed out",
                details={"command": " ".join(command)}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.COMMAND,
                status=HealthStatus.UNHEALTHY,
                duration_ms=duration_ms,
                error=str(e),
                details={"command": " ".join(command)}
            )


class FileSystemHealthCheck(HealthCheck):
    """File system health check"""
    
    async def execute(self) -> HealthCheckResult:
        start_time = time.time()
        
        path = self.config.config.get("path", "")
        check_readable = self.config.config.get("check_readable", True)
        check_writable = self.config.config.get("check_writable", False)
        min_free_space_mb = self.config.config.get("min_free_space_mb", 0)
        
        if not path:
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.FILE_SYSTEM,
                status=HealthStatus.UNHEALTHY,
                duration_ms=0,
                error="Path not configured"
            )
        
        try:
            path_obj = Path(path)
            
            # Check if path exists
            if not path_obj.exists():
                duration_ms = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.FILE_SYSTEM,
                    status=HealthStatus.UNHEALTHY,
                    duration_ms=duration_ms,
                    message="Path does not exist",
                    details={"path": str(path_obj)}
                )
            
            # Check readable
            if check_readable and not os.access(path_obj, os.R_OK):
                duration_ms = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.FILE_SYSTEM,
                    status=HealthStatus.UNHEALTHY,
                    duration_ms=duration_ms,
                    message="Path is not readable",
                    details={"path": str(path_obj)}
                )
            
            # Check writable
            if check_writable and not os.access(path_obj, os.W_OK):
                duration_ms = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.FILE_SYSTEM,
                    status=HealthStatus.UNHEALTHY,
                    duration_ms=duration_ms,
                    message="Path is not writable",
                    details={"path": str(path_obj)}
                )
            
            # Check free space
            if min_free_space_mb > 0:
                import shutil
                free_space_bytes = shutil.disk_usage(path_obj).free
                free_space_mb = free_space_bytes / (1024 * 1024)
                
                if free_space_mb < min_free_space_mb:
                    duration_ms = (time.time() - start_time) * 1000
                    return HealthCheckResult(
                        check_name=self.config.name,
                        check_type=HealthCheckType.FILE_SYSTEM,
                        status=HealthStatus.WARNING,
                        duration_ms=duration_ms,
                        message=f"Low free space: {free_space_mb:.1f}MB < {min_free_space_mb}MB",
                        details={
                            "path": str(path_obj),
                            "free_space_mb": free_space_mb,
                            "min_required_mb": min_free_space_mb
                        }
                    )
            
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.FILE_SYSTEM,
                status=HealthStatus.HEALTHY,
                duration_ms=duration_ms,
                message="File system check successful",
                details={"path": str(path_obj)}
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.FILE_SYSTEM,
                status=HealthStatus.UNHEALTHY,
                duration_ms=duration_ms,
                error=str(e),
                details={"path": path}
            )


class CustomHealthCheck(HealthCheck):
    """Custom health check with user-defined function"""
    
    def __init__(self, config: HealthCheckConfig, check_function: Callable):
        super().__init__(config)
        self.check_function = check_function
    
    async def execute(self) -> HealthCheckResult:
        start_time = time.time()
        
        try:
            # Execute custom function
            if asyncio.iscoroutinefunction(self.check_function):
                result = await self.check_function(self.config.config)
            else:
                result = self.check_function(self.config.config)
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Handle different return types
            if isinstance(result, HealthCheckResult):
                return result
            elif isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.CUSTOM,
                    status=status,
                    duration_ms=duration_ms,
                    message="Custom check completed"
                )
            elif isinstance(result, dict):
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.CUSTOM,
                    status=HealthStatus(result.get("status", "healthy")),
                    duration_ms=duration_ms,
                    message=result.get("message", "Custom check completed"),
                    details=result.get("details", {})
                )
            else:
                return HealthCheckResult(
                    check_name=self.config.name,
                    check_type=HealthCheckType.CUSTOM,
                    status=HealthStatus.HEALTHY,
                    duration_ms=duration_ms,
                    message=str(result)
                )
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                check_name=self.config.name,
                check_type=HealthCheckType.CUSTOM,
                status=HealthStatus.UNHEALTHY,
                duration_ms=duration_ms,
                error=str(e)
            )


class HealthValidator:
    """
    Comprehensive health validation system for MCP servers
    with customizable checks, timeouts, and detailed reporting.
    """
    
    def __init__(self):
        """Initialize health validator."""
        self.health_checks: Dict[str, HealthCheck] = {}
        self.check_history: Dict[str, List[HealthCheckResult]] = {}
        self.custom_functions: Dict[str, Callable] = {}
        
        # Register built-in check types
        self.check_factories = {
            HealthCheckType.HTTP: HTTPHealthCheck,
            HealthCheckType.TCP: TCPHealthCheck, 
            HealthCheckType.COMMAND: CommandHealthCheck,
            HealthCheckType.FILE_SYSTEM: FileSystemHealthCheck
        }
    
    def register_health_check(self, config: HealthCheckConfig) -> str:
        """
        Register a new health check.
        
        Args:
            config: Health check configuration
            
        Returns:
            Check ID for reference
        """
        if config.check_type == HealthCheckType.CUSTOM:
            if config.name not in self.custom_functions:
                raise MCPError(f"Custom function not registered for check: {config.name}")
            check = CustomHealthCheck(config, self.custom_functions[config.name])
        else:
            if config.check_type not in self.check_factories:
                raise MCPError(f"Unsupported health check type: {config.check_type}")
            check = self.check_factories[config.check_type](config)
        
        self.health_checks[config.name] = check
        self.check_history[config.name] = []
        
        logger.info(f"Registered health check: {config.name} ({config.check_type.value})")
        return config.name
    
    def register_custom_function(self, name: str, function: Callable):
        """Register a custom health check function."""
        self.custom_functions[name] = function
        logger.info(f"Registered custom health check function: {name}")
    
    async def execute_health_check(self, check_name: str) -> HealthCheckResult:
        """
        Execute a single health check.
        
        Args:
            check_name: Name of the health check to execute
            
        Returns:
            Health check result
        """
        if check_name not in self.health_checks:
            raise MCPError(f"Health check not found: {check_name}")
        
        check = self.health_checks[check_name]
        
        # Execute check with retries
        last_result = None
        for attempt in range(check.config.retry_attempts):
            try:
                result = await check.execute()
                
                # Store result in history
                self.check_history[check_name].append(result)
                
                # Keep only last 100 results
                if len(self.check_history[check_name]) > 100:
                    self.check_history[check_name] = self.check_history[check_name][-100:]
                
                # Return on success or if this is the last attempt
                if result.status == HealthStatus.HEALTHY or attempt == check.config.retry_attempts - 1:
                    return result
                
                last_result = result
                
                # Wait before retry
                if attempt < check.config.retry_attempts - 1:
                    await asyncio.sleep(check.config.retry_delay_seconds)
                    
            except Exception as e:
                last_result = HealthCheckResult(
                    check_name=check_name,
                    check_type=check.config.check_type,
                    status=HealthStatus.UNHEALTHY,
                    duration_ms=0,
                    error=str(e)
                )
                
                if attempt < check.config.retry_attempts - 1:
                    await asyncio.sleep(check.config.retry_delay_seconds)
        
        return last_result or HealthCheckResult(
            check_name=check_name,
            check_type=check.config.check_type,
            status=HealthStatus.UNKNOWN,
            duration_ms=0,
            error="All retry attempts failed"
        )
    
    async def execute_all_health_checks(
        self, 
        tags: Optional[List[str]] = None,
        parallel: bool = True
    ) -> Dict[str, HealthCheckResult]:
        """
        Execute all registered health checks.
        
        Args:
            tags: Optional list of tags to filter checks
            parallel: Whether to execute checks in parallel
            
        Returns:
            Dictionary of check results by check name
        """
        # Filter checks by tags if specified
        checks_to_run = []
        for name, check in self.health_checks.items():
            if tags is None or any(tag in check.config.tags for tag in tags):
                checks_to_run.append(name)
        
        if not checks_to_run:
            logger.warning("No health checks to execute")
            return {}
        
        logger.info(f"Executing {len(checks_to_run)} health checks (parallel={parallel})")
        
        if parallel:
            # Execute all checks concurrently
            tasks = [self.execute_health_check(name) for name in checks_to_run]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            check_results = {}
            for i, result in enumerate(results):
                name = checks_to_run[i]
                if isinstance(result, Exception):
                    check_results[name] = HealthCheckResult(
                        check_name=name,
                        check_type=HealthCheckType.UNKNOWN,
                        status=HealthStatus.UNHEALTHY,
                        duration_ms=0,
                        error=str(result)
                    )
                else:
                    check_results[name] = result
        else:
            # Execute checks sequentially
            check_results = {}
            for name in checks_to_run:
                check_results[name] = await self.execute_health_check(name)
        
        return check_results
    
    def get_overall_health_status(
        self, 
        results: Dict[str, HealthCheckResult]
    ) -> HealthStatus:
        """
        Determine overall health status from individual check results.
        
        Args:
            results: Dictionary of health check results
            
        Returns:
            Overall health status
        """
        if not results:
            return HealthStatus.UNKNOWN
        
        # Count statuses
        status_counts = {}
        critical_failed = False
        
        for name, result in results.items():
            status = result.status
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # Check if critical check failed
            check = self.health_checks.get(name)
            if check and check.config.critical and status in [HealthStatus.UNHEALTHY, HealthStatus.TIMEOUT]:
                critical_failed = True
        
        # Determine overall status
        if critical_failed:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.UNHEALTHY in status_counts:
            return HealthStatus.WARNING
        elif HealthStatus.WARNING in status_counts:
            return HealthStatus.WARNING
        elif HealthStatus.TIMEOUT in status_counts:
            return HealthStatus.WARNING
        elif HealthStatus.HEALTHY in status_counts:
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN
    
    def generate_health_report(
        self, 
        results: Dict[str, HealthCheckResult]
    ) -> Dict[str, Any]:
        """
        Generate comprehensive health report.
        
        Args:
            results: Dictionary of health check results
            
        Returns:
            Detailed health report
        """
        overall_status = self.get_overall_health_status(results)
        
        # Calculate statistics
        total_checks = len(results)
        healthy_checks = len([r for r in results.values() if r.status == HealthStatus.HEALTHY])
        unhealthy_checks = len([r for r in results.values() if r.status == HealthStatus.UNHEALTHY])
        warning_checks = len([r for r in results.values() if r.status == HealthStatus.WARNING])
        timeout_checks = len([r for r in results.values() if r.status == HealthStatus.TIMEOUT])
        
        # Calculate average duration
        durations = [r.duration_ms for r in results.values() if r.duration_ms > 0]
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        report = {
            "overall_status": overall_status.value,
            "timestamp": time.time(),
            "summary": {
                "total_checks": total_checks,
                "healthy": healthy_checks,
                "unhealthy": unhealthy_checks,
                "warning": warning_checks,
                "timeout": timeout_checks,
                "success_rate": (healthy_checks / total_checks * 100) if total_checks > 0 else 0,
                "average_duration_ms": avg_duration
            },
            "details": [
                {
                    "name": result.check_name,
                    "type": result.check_type.value,
                    "status": result.status.value,
                    "duration_ms": result.duration_ms,
                    "message": result.message,
                    "error": result.error,
                    "details": result.details
                }
                for result in results.values()
            ]
        }
        
        return report
    
    def get_check_history(self, check_name: str, limit: int = 10) -> List[HealthCheckResult]:
        """Get historical results for a specific check."""
        if check_name not in self.check_history:
            return []
        
        return self.check_history[check_name][-limit:]
    
    def list_health_checks(self) -> List[Dict[str, Any]]:
        """List all registered health checks with their configurations."""
        return [
            {
                "name": check.config.name,
                "type": check.config.check_type.value,
                "timeout_seconds": check.config.timeout_seconds,
                "retry_attempts": check.config.retry_attempts,
                "critical": check.config.critical,
                "tags": check.config.tags
            }
            for check in self.health_checks.values()
        ]