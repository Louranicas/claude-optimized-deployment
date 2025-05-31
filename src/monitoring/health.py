"""
Health check endpoints and monitoring for Kubernetes probes and service health.

Provides:
- Liveness probes
- Readiness probes
- Detailed health status
- Component health checks
- Dependency health monitoring
"""

import os
import time
import asyncio
import psutil
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field


class HealthStatus(Enum):
    """Health status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0
    last_check: datetime = field(default_factory=datetime.now)


@dataclass
class HealthReport:
    """Overall health report."""
    status: HealthStatus
    checks: List[HealthCheckResult]
    timestamp: datetime = field(default_factory=datetime.now)
    version: str = ""
    environment: str = ""
    uptime_seconds: float = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "environment": self.environment,
            "uptime_seconds": self.uptime_seconds,
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "message": check.message,
                    "details": check.details,
                    "duration_ms": check.duration_ms,
                    "last_check": check.last_check.isoformat()
                }
                for check in self.checks
            ]
        }


class HealthChecker:
    """Manages health checks for the application."""
    
    def __init__(self):
        self._checks: Dict[str, Callable] = {}
        self._async_checks: Dict[str, Callable] = {}
        self._cache: Dict[str, HealthCheckResult] = {}
        self._cache_ttl = timedelta(seconds=10)
        self._start_time = time.time()
        
        # Register default health checks
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default system health checks."""
        # CPU check
        self.register_check("cpu", self._check_cpu)
        
        # Memory check
        self.register_check("memory", self._check_memory)
        
        # Disk check
        self.register_check("disk", self._check_disk)
        
        # Process check
        self.register_check("process", self._check_process)
    
    def register_check(
        self,
        name: str,
        check_func: Union[Callable[[], HealthCheckResult], Callable[[], Any]],
        is_async: bool = False
    ):
        """Register a health check function."""
        if is_async:
            self._async_checks[name] = check_func
        else:
            self._checks[name] = check_func
    
    def unregister_check(self, name: str):
        """Unregister a health check."""
        self._checks.pop(name, None)
        self._async_checks.pop(name, None)
        self._cache.pop(name, None)
    
    def _check_cpu(self) -> HealthCheckResult:
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        if cpu_percent < 80:
            status = HealthStatus.HEALTHY
            message = f"CPU usage: {cpu_percent:.1f}%"
        elif cpu_percent < 90:
            status = HealthStatus.DEGRADED
            message = f"High CPU usage: {cpu_percent:.1f}%"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"Critical CPU usage: {cpu_percent:.1f}%"
        
        return HealthCheckResult(
            name="cpu",
            status=status,
            message=message,
            details={
                "cpu_percent": cpu_percent,
                "cpu_count": psutil.cpu_count(),
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        )
    
    def _check_memory(self) -> HealthCheckResult:
        """Check memory usage."""
        memory = psutil.virtual_memory()
        
        if memory.percent < 80:
            status = HealthStatus.HEALTHY
            message = f"Memory usage: {memory.percent:.1f}%"
        elif memory.percent < 90:
            status = HealthStatus.DEGRADED
            message = f"High memory usage: {memory.percent:.1f}%"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"Critical memory usage: {memory.percent:.1f}%"
        
        return HealthCheckResult(
            name="memory",
            status=status,
            message=message,
            details={
                "total_mb": memory.total / 1024 / 1024,
                "available_mb": memory.available / 1024 / 1024,
                "used_mb": memory.used / 1024 / 1024,
                "percent": memory.percent
            }
        )
    
    def _check_disk(self) -> HealthCheckResult:
        """Check disk usage."""
        disk = psutil.disk_usage('/')
        
        if disk.percent < 80:
            status = HealthStatus.HEALTHY
            message = f"Disk usage: {disk.percent:.1f}%"
        elif disk.percent < 90:
            status = HealthStatus.DEGRADED
            message = f"High disk usage: {disk.percent:.1f}%"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"Critical disk usage: {disk.percent:.1f}%"
        
        return HealthCheckResult(
            name="disk",
            status=status,
            message=message,
            details={
                "total_gb": disk.total / 1024 / 1024 / 1024,
                "free_gb": disk.free / 1024 / 1024 / 1024,
                "used_gb": disk.used / 1024 / 1024 / 1024,
                "percent": disk.percent
            }
        )
    
    def _check_process(self) -> HealthCheckResult:
        """Check process health."""
        try:
            process = psutil.Process()
            
            return HealthCheckResult(
                name="process",
                status=HealthStatus.HEALTHY,
                message="Process is running",
                details={
                    "pid": process.pid,
                    "memory_mb": process.memory_info().rss / 1024 / 1024,
                    "cpu_percent": process.cpu_percent(),
                    "num_threads": process.num_threads(),
                    "open_files": len(process.open_files())
                }
            )
        except Exception as e:
            return HealthCheckResult(
                name="process",
                status=HealthStatus.UNHEALTHY,
                message=f"Process check failed: {str(e)}"
            )
    
    def _execute_check(self, name: str, check_func: Callable) -> HealthCheckResult:
        """Execute a single health check."""
        start_time = time.time()
        
        try:
            # If the function returns a HealthCheckResult, use it
            result = check_func()
            if isinstance(result, HealthCheckResult):
                result.duration_ms = (time.time() - start_time) * 1000
                return result
            
            # Otherwise, assume it returns a boolean
            if result:
                return HealthCheckResult(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message="Check passed",
                    duration_ms=(time.time() - start_time) * 1000
                )
            else:
                return HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message="Check failed",
                    duration_ms=(time.time() - start_time) * 1000
                )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check error: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000
            )
    
    async def _execute_async_check(self, name: str, check_func: Callable) -> HealthCheckResult:
        """Execute an async health check."""
        start_time = time.time()
        
        try:
            result = await check_func()
            if isinstance(result, HealthCheckResult):
                result.duration_ms = (time.time() - start_time) * 1000
                return result
            
            if result:
                return HealthCheckResult(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message="Check passed",
                    duration_ms=(time.time() - start_time) * 1000
                )
            else:
                return HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message="Check failed",
                    duration_ms=(time.time() - start_time) * 1000
                )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check error: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def check_health(self, use_cache: bool = True) -> HealthReport:
        """Run all health checks synchronously."""
        results = []
        
        # Run sync checks
        for name, check_func in self._checks.items():
            if use_cache and name in self._cache:
                cached = self._cache[name]
                if datetime.now() - cached.last_check < self._cache_ttl:
                    results.append(cached)
                    continue
            
            result = self._execute_check(name, check_func)
            self._cache[name] = result
            results.append(result)
        
        # Determine overall status
        if any(r.status == HealthStatus.UNHEALTHY for r in results):
            overall_status = HealthStatus.UNHEALTHY
        elif any(r.status == HealthStatus.DEGRADED for r in results):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        return HealthReport(
            status=overall_status,
            checks=results,
            version=os.getenv('APP_VERSION', 'unknown'),
            environment=os.getenv('ENVIRONMENT', 'development'),
            uptime_seconds=time.time() - self._start_time
        )
    
    async def check_health_async(self, use_cache: bool = True) -> HealthReport:
        """Run all health checks asynchronously."""
        tasks = []
        results = []
        
        # Run sync checks
        for name, check_func in self._checks.items():
            if use_cache and name in self._cache:
                cached = self._cache[name]
                if datetime.now() - cached.last_check < self._cache_ttl:
                    results.append(cached)
                    continue
            
            result = self._execute_check(name, check_func)
            self._cache[name] = result
            results.append(result)
        
        # Run async checks
        for name, check_func in self._async_checks.items():
            if use_cache and name in self._cache:
                cached = self._cache[name]
                if datetime.now() - cached.last_check < self._cache_ttl:
                    results.append(cached)
                    continue
            
            tasks.append(self._execute_async_check(name, check_func))
        
        if tasks:
            async_results = await asyncio.gather(*tasks)
            for i, (name, _) in enumerate(self._async_checks.items()):
                self._cache[name] = async_results[i]
                results.append(async_results[i])
        
        # Determine overall status
        if any(r.status == HealthStatus.UNHEALTHY for r in results):
            overall_status = HealthStatus.UNHEALTHY
        elif any(r.status == HealthStatus.DEGRADED for r in results):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        return HealthReport(
            status=overall_status,
            checks=results,
            version=os.getenv('APP_VERSION', 'unknown'),
            environment=os.getenv('ENVIRONMENT', 'development'),
            uptime_seconds=time.time() - self._start_time
        )
    
    def liveness_probe(self) -> bool:
        """
        Kubernetes liveness probe.
        Returns True if the application is alive and should not be restarted.
        """
        # Basic check - is the process responsive?
        try:
            process = psutil.Process()
            return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except:
            return False
    
    def readiness_probe(self) -> bool:
        """
        Kubernetes readiness probe.
        Returns True if the application is ready to serve traffic.
        """
        report = self.check_health(use_cache=True)
        return report.status != HealthStatus.UNHEALTHY


# Global health checker instance
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def register_health_check(name: str, check_func: Callable, is_async: bool = False):
    """Register a health check with the global health checker."""
    get_health_checker().register_check(name, check_func, is_async)


# Convenience decorators
def health_check(name: Optional[str] = None):
    """Decorator to register a function as a health check."""
    def decorator(func: Callable) -> Callable:
        check_name = name or func.__name__
        is_async = asyncio.iscoroutinefunction(func)
        register_health_check(check_name, func, is_async)
        return func
    return decorator