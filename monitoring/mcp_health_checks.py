#!/usr/bin/env python3
"""
MCP Server Health Check System
Implements comprehensive health checks for all MCP servers including liveness,
readiness, dependency checks, and performance metrics.
"""

import asyncio
import json
import logging
import time
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import psutil
import httpx
import websockets
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway
import structlog

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

@dataclass
class HealthCheckResult:
    """Result of a health check operation"""
    service_name: str
    status: HealthStatus
    timestamp: datetime
    response_time_ms: float
    details: Dict[str, Any]
    errors: List[str]
    metrics: Dict[str, float]

@dataclass
class DependencyCheck:
    """Configuration for dependency health checks"""
    name: str
    check_type: str  # "http", "tcp", "process", "file"
    target: str
    timeout_seconds: float = 5.0
    expected_response: Optional[str] = None
    critical: bool = True

class MCPHealthChecker:
    """Comprehensive health checker for MCP servers"""
    
    def __init__(self, config_path: str = None):
        self.logger = structlog.get_logger("mcp_health_checker")
        self.config = self._load_config(config_path)
        self.metrics_registry = CollectorRegistry()
        self._setup_metrics()
        self.last_check_results: Dict[str, HealthCheckResult] = {}
        
    def _setup_metrics(self):
        """Setup Prometheus metrics"""
        self.health_status_gauge = Gauge(
            'mcp_server_health_status',
            'Health status of MCP servers (0=unhealthy, 1=degraded, 2=healthy)',
            ['server_name', 'check_type'],
            registry=self.metrics_registry
        )
        
        self.response_time_histogram = Histogram(
            'mcp_server_response_time_seconds',
            'Response time for MCP server health checks',
            ['server_name', 'check_type'],
            registry=self.metrics_registry
        )
        
        self.check_counter = Counter(
            'mcp_server_health_checks_total',
            'Total number of health checks performed',
            ['server_name', 'status'],
            registry=self.metrics_registry
        )
        
        self.dependency_status_gauge = Gauge(
            'mcp_server_dependency_status',
            'Status of MCP server dependencies',
            ['server_name', 'dependency_name'],
            registry=self.metrics_registry
        )
        
        self.error_counter = Counter(
            'mcp_server_health_check_errors_total',
            'Total number of health check errors',
            ['server_name', 'error_type'],
            registry=self.metrics_registry
        )

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load MCP server configuration"""
        default_config = {
            "servers": {
                "desktop-commander": {
                    "port": 8001,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "system_resources", "check_type": "process", "target": "node", "critical": True},
                        {"name": "temp_directory", "check_type": "file", "target": "/tmp", "critical": True}
                    ]
                },
                "filesystem": {
                    "port": 8002,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics", 
                    "dependencies": [
                        {"name": "root_filesystem", "check_type": "file", "target": "/", "critical": True},
                        {"name": "working_directory", "check_type": "file", "target": ".", "critical": True}
                    ]
                },
                "postgres": {
                    "port": 8003,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "postgres_connection", "check_type": "tcp", "target": "localhost:5432", "critical": True},
                        {"name": "postgres_process", "check_type": "process", "target": "postgres", "critical": True}
                    ]
                },
                "github": {
                    "port": 8004,
                    "health_endpoint": "/health", 
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "github_api", "check_type": "http", "target": "https://api.github.com", "critical": True},
                        {"name": "network_connectivity", "check_type": "http", "target": "https://github.com", "critical": True}
                    ]
                },
                "memory": {
                    "port": 8005,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "memory_storage", "check_type": "file", "target": "./memory_data", "critical": False},
                        {"name": "system_memory", "check_type": "process", "target": "node", "critical": True}
                    ]
                },
                "brave-search": {
                    "port": 8006,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "brave_api", "check_type": "http", "target": "https://api.search.brave.com", "critical": True},
                        {"name": "api_key_configured", "check_type": "env", "target": "BRAVE_API_KEY", "critical": True}
                    ]
                },
                "slack": {
                    "port": 8007,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "slack_api", "check_type": "http", "target": "https://slack.com/api", "critical": True},
                        {"name": "slack_token", "check_type": "env", "target": "SLACK_BOT_TOKEN", "critical": True}
                    ]
                },
                "puppeteer": {
                    "port": 8008,
                    "health_endpoint": "/health",
                    "metrics_endpoint": "/metrics",
                    "dependencies": [
                        {"name": "chrome_binary", "check_type": "process", "target": "chromium", "critical": True},
                        {"name": "display_server", "check_type": "env", "target": "DISPLAY", "critical": False}
                    ]
                }
            },
            "check_intervals": {
                "liveness": 30,
                "readiness": 60, 
                "dependency": 120
            },
            "thresholds": {
                "response_time_warning_ms": 5000,
                "response_time_critical_ms": 10000,
                "failure_count_threshold": 3
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.warning("Failed to load config file, using defaults", error=str(e))
                
        return default_config

    async def perform_liveness_check(self, server_name: str) -> HealthCheckResult:
        """Perform liveness check - basic server responsiveness"""
        start_time = time.time()
        server_config = self.config["servers"].get(server_name, {})
        port = server_config.get("port")
        endpoint = server_config.get("health_endpoint", "/health")
        
        errors = []
        details = {"check_type": "liveness"}
        metrics = {}
        
        try:
            if not port:
                raise ValueError(f"No port configured for server {server_name}")
                
            url = f"http://localhost:{port}{endpoint}"
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    status = HealthStatus.HEALTHY
                    details.update({
                        "status_code": response.status_code,
                        "response_body": response.text[:500]  # Limit response size
                    })
                else:
                    status = HealthStatus.UNHEALTHY
                    errors.append(f"HTTP {response.status_code}: {response.text[:200]}")
                    
                metrics.update({
                    "response_time_ms": response_time,
                    "status_code": response.status_code
                })
                
        except Exception as e:
            status = HealthStatus.UNHEALTHY
            response_time = (time.time() - start_time) * 1000
            errors.append(f"Liveness check failed: {str(e)}")
            metrics["response_time_ms"] = response_time
            
        result = HealthCheckResult(
            service_name=server_name,
            status=status,
            timestamp=datetime.utcnow(),
            response_time_ms=metrics.get("response_time_ms", 0),
            details=details,
            errors=errors,
            metrics=metrics
        )
        
        self._update_metrics(result, "liveness")
        return result

    async def perform_readiness_check(self, server_name: str) -> HealthCheckResult:
        """Perform readiness check - server ready to handle traffic"""
        start_time = time.time()
        server_config = self.config["servers"].get(server_name, {})
        
        errors = []
        details = {"check_type": "readiness"}
        metrics = {}
        
        try:
            # First check liveness
            liveness_result = await self.perform_liveness_check(server_name)
            if liveness_result.status != HealthStatus.HEALTHY:
                return HealthCheckResult(
                    service_name=server_name,
                    status=HealthStatus.UNHEALTHY,
                    timestamp=datetime.utcnow(),
                    response_time_ms=liveness_result.response_time_ms,
                    details={"check_type": "readiness", "liveness_failed": True},
                    errors=["Liveness check failed"] + liveness_result.errors,
                    metrics=liveness_result.metrics
                )
            
            # Check dependencies
            dependency_results = await self.check_dependencies(server_name)
            critical_failures = [
                dep for dep in dependency_results 
                if dep["critical"] and dep["status"] != "healthy"
            ]
            
            if critical_failures:
                status = HealthStatus.UNHEALTHY
                errors.extend([f"Critical dependency failed: {dep['name']}" for dep in critical_failures])
            elif any(dep["status"] != "healthy" for dep in dependency_results):
                status = HealthStatus.DEGRADED
                errors.extend([f"Non-critical dependency degraded: {dep['name']}" 
                             for dep in dependency_results if dep["status"] != "healthy"])
            else:
                status = HealthStatus.HEALTHY
                
            details.update({
                "dependencies_checked": len(dependency_results),
                "critical_failures": len(critical_failures),
                "dependency_details": dependency_results
            })
            
            response_time = (time.time() - start_time) * 1000
            metrics["response_time_ms"] = response_time
            
        except Exception as e:
            status = HealthStatus.UNHEALTHY
            response_time = (time.time() - start_time) * 1000
            errors.append(f"Readiness check failed: {str(e)}")
            metrics["response_time_ms"] = response_time
            
        result = HealthCheckResult(
            service_name=server_name,
            status=status,
            timestamp=datetime.utcnow(),
            response_time_ms=metrics.get("response_time_ms", 0),
            details=details,
            errors=errors,
            metrics=metrics
        )
        
        self._update_metrics(result, "readiness")
        return result

    async def check_dependencies(self, server_name: str) -> List[Dict[str, Any]]:
        """Check all dependencies for a server"""
        server_config = self.config["servers"].get(server_name, {})
        dependencies = server_config.get("dependencies", [])
        
        results = []
        for dep_config in dependencies:
            dep = DependencyCheck(**dep_config)
            result = await self._check_single_dependency(dep)
            results.append({
                "name": dep.name,
                "type": dep.check_type,
                "status": result["status"],
                "critical": dep.critical,
                "details": result["details"],
                "error": result.get("error")
            })
            
            # Update dependency metrics
            status_value = 1 if result["status"] == "healthy" else 0
            self.dependency_status_gauge.labels(
                server_name=server_name,
                dependency_name=dep.name
            ).set(status_value)
            
        return results

    async def _check_single_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check a single dependency"""
        try:
            if dep.check_type == "http":
                return await self._check_http_dependency(dep)
            elif dep.check_type == "tcp":
                return await self._check_tcp_dependency(dep)
            elif dep.check_type == "process":
                return self._check_process_dependency(dep)
            elif dep.check_type == "file":
                return self._check_file_dependency(dep)
            elif dep.check_type == "env":
                return self._check_env_dependency(dep)
            else:
                return {
                    "status": "unhealthy",
                    "details": {"error": f"Unknown check type: {dep.check_type}"},
                    "error": f"Unknown check type: {dep.check_type}"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e), "traceback": traceback.format_exc()},
                "error": str(e)
            }

    async def _check_http_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check HTTP dependency"""
        try:
            async with httpx.AsyncClient(timeout=dep.timeout_seconds) as client:
                response = await client.get(dep.target)
                if response.status_code < 400:
                    return {
                        "status": "healthy",
                        "details": {
                            "status_code": response.status_code,
                            "response_time_ms": response.elapsed.total_seconds() * 1000
                        }
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "details": {"status_code": response.status_code},
                        "error": f"HTTP {response.status_code}"
                    }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e)},
                "error": str(e)
            }

    async def _check_tcp_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check TCP dependency"""
        try:
            host, port = dep.target.split(":")
            port = int(port)
            
            # Create connection with timeout
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=dep.timeout_seconds)
            writer.close()
            await writer.wait_closed()
            
            return {
                "status": "healthy",
                "details": {"host": host, "port": port}
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e)},
                "error": str(e)
            }

    def _check_process_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check process dependency"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if dep.target.lower() in proc.info['name'].lower():
                        processes.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            if processes:
                return {
                    "status": "healthy",
                    "details": {"processes_found": len(processes), "processes": processes[:5]}  # Limit to 5
                }
            else:
                return {
                    "status": "unhealthy",
                    "details": {"processes_found": 0},
                    "error": f"No processes found matching '{dep.target}'"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e)},
                "error": str(e)
            }

    def _check_file_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check file/directory dependency"""
        try:
            import os
            path = dep.target
            
            if os.path.exists(path):
                stat = os.stat(path)
                return {
                    "status": "healthy",
                    "details": {
                        "path": path,
                        "size": stat.st_size if os.path.isfile(path) else None,
                        "is_directory": os.path.isdir(path),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }
                }
            else:
                return {
                    "status": "unhealthy",
                    "details": {"path": path, "exists": False},
                    "error": f"Path does not exist: {path}"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e)},
                "error": str(e)
            }

    def _check_env_dependency(self, dep: DependencyCheck) -> Dict[str, Any]:
        """Check environment variable dependency"""
        try:
            import os
            value = os.environ.get(dep.target)
            
            if value:
                return {
                    "status": "healthy", 
                    "details": {
                        "variable": dep.target,
                        "has_value": True,
                        "value_length": len(value)
                    }
                }
            else:
                return {
                    "status": "unhealthy",
                    "details": {"variable": dep.target, "has_value": False},
                    "error": f"Environment variable not set: {dep.target}"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": {"error": str(e)},
                "error": str(e)
            }

    def _update_metrics(self, result: HealthCheckResult, check_type: str):
        """Update Prometheus metrics based on check result"""
        # Health status metric
        status_value = {
            HealthStatus.HEALTHY: 2,
            HealthStatus.DEGRADED: 1,
            HealthStatus.UNHEALTHY: 0,
            HealthStatus.UNKNOWN: -1
        }.get(result.status, -1)
        
        self.health_status_gauge.labels(
            server_name=result.service_name,
            check_type=check_type
        ).set(status_value)
        
        # Response time metric
        self.response_time_histogram.labels(
            server_name=result.service_name,
            check_type=check_type
        ).observe(result.response_time_ms / 1000)  # Convert to seconds
        
        # Check counter
        self.check_counter.labels(
            server_name=result.service_name,
            status=result.status.value
        ).inc()
        
        # Error counter
        if result.errors:
            for error in result.errors:
                error_type = error.split(":")[0] if ":" in error else "general"
                self.error_counter.labels(
                    server_name=result.service_name,
                    error_type=error_type
                ).inc()

    async def check_all_servers(self, check_type: str = "readiness") -> Dict[str, HealthCheckResult]:
        """Check all configured servers"""
        results = {}
        
        tasks = []
        for server_name in self.config["servers"].keys():
            if check_type == "liveness":
                task = self.perform_liveness_check(server_name)
            elif check_type == "readiness":
                task = self.perform_readiness_check(server_name)
            else:
                continue
            tasks.append((server_name, task))
        
        # Execute all checks concurrently
        completed_tasks = await asyncio.gather(
            *[task for _, task in tasks],
            return_exceptions=True
        )
        
        for (server_name, _), result in zip(tasks, completed_tasks):
            if isinstance(result, Exception):
                results[server_name] = HealthCheckResult(
                    service_name=server_name,
                    status=HealthStatus.UNHEALTHY,
                    timestamp=datetime.utcnow(),
                    response_time_ms=0,
                    details={"check_type": check_type},
                    errors=[f"Check failed with exception: {str(result)}"],
                    metrics={}
                )
            else:
                results[server_name] = result
                
        self.last_check_results = results
        return results

    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall health status of all servers"""
        if not self.last_check_results:
            return {
                "status": "unknown",
                "message": "No health checks performed yet",
                "servers": {},
                "summary": {
                    "total": 0,
                    "healthy": 0,
                    "degraded": 0,
                    "unhealthy": 0,
                    "unknown": 0
                }
            }
        
        summary = {"healthy": 0, "degraded": 0, "unhealthy": 0, "unknown": 0}
        server_statuses = {}
        
        for server_name, result in self.last_check_results.items():
            status = result.status.value
            summary[status] += 1
            server_statuses[server_name] = {
                "status": status,
                "timestamp": result.timestamp.isoformat(),
                "response_time_ms": result.response_time_ms,
                "errors": result.errors
            }
        
        total = len(self.last_check_results)
        if summary["unhealthy"] > 0:
            overall_status = "unhealthy"
        elif summary["degraded"] > 0:
            overall_status = "degraded"
        elif summary["healthy"] == total:
            overall_status = "healthy"
        else:
            overall_status = "unknown"
        
        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "servers": server_statuses,
            "summary": {
                "total": total,
                **summary
            }
        }

    async def push_metrics(self, gateway_url: str = "localhost:9091"):
        """Push metrics to Prometheus gateway"""
        try:
            push_to_gateway(
                gateway_url,
                job='mcp_health_checks',
                registry=self.metrics_registry
            )
            self.logger.info("Metrics pushed to gateway", gateway=gateway_url)
        except Exception as e:
            self.logger.error("Failed to push metrics", error=str(e))

    async def run_continuous_monitoring(self, interval_seconds: int = 60):
        """Run continuous health monitoring"""
        self.logger.info("Starting continuous monitoring", interval=interval_seconds)
        
        while True:
            try:
                start_time = time.time()
                
                # Perform readiness checks
                results = await self.check_all_servers("readiness")
                
                # Log results
                overall = self.get_overall_health()
                self.logger.info(
                    "Health check completed",
                    overall_status=overall["status"],
                    total_servers=overall["summary"]["total"],
                    healthy=overall["summary"]["healthy"],
                    degraded=overall["summary"]["degraded"],
                    unhealthy=overall["summary"]["unhealthy"],
                    duration_ms=(time.time() - start_time) * 1000
                )
                
                # Push metrics
                await self.push_metrics()
                
                # Wait for next interval
                await asyncio.sleep(interval_seconds)
                
            except Exception as e:
                self.logger.error("Error in continuous monitoring", error=str(e))
                await asyncio.sleep(interval_seconds)

# CLI interface
async def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Server Health Checker")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--check-type", choices=["liveness", "readiness"], default="readiness")
    parser.add_argument("--server", help="Check specific server only")
    parser.add_argument("--continuous", action="store_true", help="Run continuous monitoring")
    parser.add_argument("--interval", type=int, default=60, help="Monitoring interval in seconds")
    parser.add_argument("--output", choices=["json", "text"], default="text")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    checker = MCPHealthChecker(args.config)
    
    if args.continuous:
        await checker.run_continuous_monitoring(args.interval)
    else:
        if args.server:
            if args.check_type == "liveness":
                result = await checker.perform_liveness_check(args.server)
            else:
                result = await checker.perform_readiness_check(args.server)
            
            if args.output == "json":
                print(json.dumps(asdict(result), default=str, indent=2))
            else:
                print(f"Server: {result.service_name}")
                print(f"Status: {result.status.value}")
                print(f"Response Time: {result.response_time_ms:.2f}ms")
                if result.errors:
                    print(f"Errors: {', '.join(result.errors)}")
        else:
            results = await checker.check_all_servers(args.check_type)
            overall = checker.get_overall_health()
            
            if args.output == "json":
                print(json.dumps(overall, indent=2))
            else:
                print(f"Overall Status: {overall['status']}")
                print(f"Total Servers: {overall['summary']['total']}")
                print(f"Healthy: {overall['summary']['healthy']}")
                print(f"Degraded: {overall['summary']['degraded']}")
                print(f"Unhealthy: {overall['summary']['unhealthy']}")
                print("\nServer Details:")
                for server, details in overall['servers'].items():
                    print(f"  {server}: {details['status']} ({details['response_time_ms']:.2f}ms)")
                    if details['errors']:
                        print(f"    Errors: {', '.join(details['errors'])}")

if __name__ == "__main__":
    asyncio.run(main())