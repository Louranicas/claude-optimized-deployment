#!/usr/bin/env python3
"""
MCP Health Check and Monitoring Validation Module

Comprehensive health monitoring framework for MCP server deployment validation.
Agent 5: Advanced health monitoring with real-time validation, SLA monitoring, and alerting.
"""

import asyncio
import time
import json
import logging
import psutil
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
import sys
import statistics
from enum import Enum
import threading
import queue

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.mcp.manager import get_mcp_manager
from src.mcp.servers import MCPServerRegistry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthCheckType(Enum):
    """Health check types."""
    AVAILABILITY = "availability"
    PERFORMANCE = "performance"
    RESOURCE_USAGE = "resource_usage"
    CONNECTIVITY = "connectivity"
    FUNCTIONAL = "functional"
    DEPENDENCY = "dependency"
    SECURITY = "security"
    DATA_INTEGRITY = "data_integrity"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class HealthMetric:
    """Individual health metric."""
    metric_name: str
    value: float
    unit: str
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    status: HealthStatus = HealthStatus.HEALTHY
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HealthCheckResult:
    """Health check result."""
    check_id: str
    check_name: str
    check_type: HealthCheckType
    status: HealthStatus
    duration_ms: float
    metrics: List[HealthMetric] = field(default_factory=list)
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Alert:
    """Health monitoring alert."""
    alert_id: str
    severity: AlertSeverity
    title: str
    description: str
    component: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    resolved: bool = False
    resolution_time: Optional[str] = None


@dataclass
class SLATarget:
    """Service Level Agreement target."""
    metric_name: str
    target_value: float
    comparison: str  # ">=", "<=", "==", "!=", ">", "<"
    measurement_period: str  # "1m", "5m", "1h", "1d"
    description: str


@dataclass
class SLAReport:
    """SLA compliance report."""
    sla_id: str
    period_start: str
    period_end: str
    targets: List[SLATarget]
    compliance_percentage: float
    violations: List[Dict[str, Any]] = field(default_factory=list)
    metrics_summary: Dict[str, Any] = field(default_factory=dict)


class MCPHealthMonitor:
    """
    Comprehensive MCP Health Monitoring Framework.
    
    Provides real-time health monitoring capabilities:
    - Server availability monitoring
    - Performance metrics tracking
    - Resource usage monitoring
    - SLA compliance monitoring
    - Real-time alerting
    - Health dashboards
    - Trend analysis
    """
    
    def __init__(self):
        self.manager = get_mcp_manager()
        self.registry = MCPServerRegistry()
        self.session_id = f"health_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_thread = None
        self.metrics_history: List[Dict[str, Any]] = []
        self.alerts: List[Alert] = []
        self.health_checks: List[HealthCheckResult] = []
        
        # Configuration
        self.config = {
            "check_interval_seconds": 30,
            "metric_retention_hours": 24,
            "alert_cooldown_minutes": 5,
            "performance_thresholds": {
                "response_time_ms": {"warning": 5000, "critical": 10000},
                "error_rate_percent": {"warning": 5, "critical": 10},
                "memory_usage_percent": {"warning": 80, "critical": 95},
                "cpu_usage_percent": {"warning": 70, "critical": 90}
            }
        }
        
        # SLA targets
        self.sla_targets = [
            SLATarget(
                metric_name="availability_percent",
                target_value=99.9,
                comparison=">=",
                measurement_period="1h",
                description="Service availability should be >= 99.9%"
            ),
            SLATarget(
                metric_name="avg_response_time_ms",
                target_value=2000,
                comparison="<=",
                measurement_period="5m",
                description="Average response time should be <= 2000ms"
            ),
            SLATarget(
                metric_name="error_rate_percent",
                target_value=1.0,
                comparison="<=",
                measurement_period="5m",
                description="Error rate should be <= 1%"
            )
        ]
        
        # Alert handlers
        self.alert_handlers: List[Callable[[Alert], None]] = []
        
    async def initialize(self):
        """Initialize health monitoring."""
        logger.info("Initializing MCP Health Monitoring Framework...")
        await self.manager.initialize()
        
        # Create monitoring context
        self.monitor_context_id = f"health_context_{self.session_id}"
        self.monitor_context = self.manager.create_context(self.monitor_context_id)
        
        # Enable all servers for monitoring
        for server_name in self.registry.list_servers():
            self.manager.enable_server(self.monitor_context_id, server_name)
        
        logger.info(f"Health monitoring initialized for {len(self.registry.list_servers())} servers")
    
    async def start_continuous_monitoring(self, duration_minutes: Optional[int] = None):
        """
        Start continuous health monitoring.
        
        Args:
            duration_minutes: Optional duration to monitor (None for indefinite)
        """
        logger.info("Starting continuous health monitoring...")
        self.monitoring_active = True
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(duration_minutes,)
        )
        self.monitoring_thread.start()
        
        # Start alert processing
        asyncio.create_task(self._alert_processor())
        
        logger.info("Continuous monitoring started")
    
    def _monitoring_worker(self, duration_minutes: Optional[int]):
        """Background monitoring worker."""
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60) if duration_minutes else None
        
        while self.monitoring_active and (end_time is None or time.time() < end_time):
            try:
                # Run health checks
                asyncio.run(self._run_periodic_health_checks())
                
                # Cleanup old metrics
                self._cleanup_old_metrics()
                
                # Sleep until next check
                time.sleep(self.config["check_interval_seconds"])
                
            except Exception as e:
                logger.error(f"Monitoring worker error: {e}")
                time.sleep(30)  # Error backoff
        
        logger.info("Monitoring worker stopped")
    
    async def _run_periodic_health_checks(self):
        """Run periodic health checks."""
        try:
            # Server availability checks
            await self._check_server_availability()
            
            # Performance checks
            await self._check_performance_metrics()
            
            # Resource usage checks
            await self._check_resource_usage()
            
            # Connectivity checks
            await self._check_connectivity()
            
            # Functional checks
            await self._check_functional_health()
            
            # Update SLA compliance
            await self._update_sla_compliance()
            
        except Exception as e:
            logger.error(f"Periodic health check error: {e}")
    
    async def _check_server_availability(self):
        """Check server availability."""
        for server_name in self.registry.list_servers():
            start_time = time.time()
            check_id = f"availability_{server_name}_{int(time.time())}"
            
            try:
                server = self.registry.get(server_name)
                if server:
                    # Test basic server info retrieval
                    server_info = server.get_server_info()
                    available = server_info is not None
                    
                    duration_ms = (time.time() - start_time) * 1000
                    
                    # Create availability metric
                    availability_metric = HealthMetric(
                        metric_name="availability",
                        value=100.0 if available else 0.0,
                        unit="percent",
                        threshold_warning=99.0,
                        threshold_critical=95.0,
                        status=HealthStatus.HEALTHY if available else HealthStatus.CRITICAL
                    )
                    
                    # Create health check result
                    result = HealthCheckResult(
                        check_id=check_id,
                        check_name=f"Server Availability - {server_name}",
                        check_type=HealthCheckType.AVAILABILITY,
                        status=HealthStatus.HEALTHY if available else HealthStatus.CRITICAL,
                        duration_ms=duration_ms,
                        metrics=[availability_metric],
                        message="Server available" if available else "Server unavailable",
                        details={"server_name": server_name, "available": available}
                    )
                    
                    self.health_checks.append(result)
                    
                    # Generate alert if unavailable
                    if not available:
                        await self._generate_alert(
                            AlertSeverity.CRITICAL,
                            f"Server Unavailable: {server_name}",
                            f"Server {server_name} is not responding to availability checks",
                            server_name,
                            "availability",
                            0.0,
                            99.0
                        )
                    
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                result = HealthCheckResult(
                    check_id=check_id,
                    check_name=f"Server Availability - {server_name}",
                    check_type=HealthCheckType.AVAILABILITY,
                    status=HealthStatus.CRITICAL,
                    duration_ms=duration_ms,
                    message=f"Availability check failed: {str(e)}",
                    details={"server_name": server_name, "error": str(e)}
                )
                
                self.health_checks.append(result)
                logger.error(f"Availability check failed for {server_name}: {e}")
    
    async def _check_performance_metrics(self):
        """Check performance metrics."""
        # Test representative operations
        performance_tests = [
            ("desktop-commander", "execute_command", {"command": "echo 'health check'", "description": "Health check"}),
        ]
        
        for server_name, tool_name, params in performance_tests:
            if server_name not in self.registry.list_servers():
                continue
                
            response_times = []
            success_count = 0
            error_count = 0
            
            # Run multiple operations to get average
            for i in range(3):
                start_time = time.time()
                
                try:
                    result = await self.manager.call_tool(
                        f"{server_name}.{tool_name}",
                        params,
                        self.monitor_context_id
                    )
                    
                    duration_ms = (time.time() - start_time) * 1000
                    response_times.append(duration_ms)
                    success_count += 1
                    
                except Exception as e:
                    error_count += 1
                    logger.debug(f"Performance test error: {e}")
            
            # Calculate metrics
            if response_times:
                avg_response_time = statistics.mean(response_times)
                max_response_time = max(response_times)
                min_response_time = min(response_times)
            else:
                avg_response_time = max_response_time = min_response_time = 0
            
            total_ops = success_count + error_count
            error_rate = (error_count / total_ops * 100) if total_ops > 0 else 0
            
            # Determine status
            perf_thresholds = self.config["performance_thresholds"]
            
            response_status = HealthStatus.HEALTHY
            if avg_response_time > perf_thresholds["response_time_ms"]["critical"]:
                response_status = HealthStatus.CRITICAL
            elif avg_response_time > perf_thresholds["response_time_ms"]["warning"]:
                response_status = HealthStatus.WARNING
            
            error_status = HealthStatus.HEALTHY
            if error_rate > perf_thresholds["error_rate_percent"]["critical"]:
                error_status = HealthStatus.CRITICAL
            elif error_rate > perf_thresholds["error_rate_percent"]["warning"]:
                error_status = HealthStatus.WARNING
            
            overall_status = max(response_status, error_status, key=lambda x: ["healthy", "warning", "critical"].index(x.value))
            
            # Create metrics
            metrics = [
                HealthMetric(
                    metric_name="avg_response_time_ms",
                    value=avg_response_time,
                    unit="milliseconds",
                    threshold_warning=perf_thresholds["response_time_ms"]["warning"],
                    threshold_critical=perf_thresholds["response_time_ms"]["critical"],
                    status=response_status
                ),
                HealthMetric(
                    metric_name="error_rate_percent",
                    value=error_rate,
                    unit="percent",
                    threshold_warning=perf_thresholds["error_rate_percent"]["warning"],
                    threshold_critical=perf_thresholds["error_rate_percent"]["critical"],
                    status=error_status
                )
            ]
            
            # Create health check result
            result = HealthCheckResult(
                check_id=f"performance_{server_name}_{int(time.time())}",
                check_name=f"Performance Metrics - {server_name}",
                check_type=HealthCheckType.PERFORMANCE,
                status=overall_status,
                duration_ms=sum(response_times) if response_times else 0,
                metrics=metrics,
                message=f"Avg response: {avg_response_time:.1f}ms, Error rate: {error_rate:.1f}%",
                details={
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "success_count": success_count,
                    "error_count": error_count,
                    "response_times": response_times
                }
            )
            
            self.health_checks.append(result)
            
            # Generate alerts if thresholds exceeded
            if response_status == HealthStatus.CRITICAL:
                await self._generate_alert(
                    AlertSeverity.CRITICAL,
                    f"High Response Time: {server_name}",
                    f"Average response time ({avg_response_time:.1f}ms) exceeds critical threshold",
                    server_name,
                    "avg_response_time_ms",
                    avg_response_time,
                    perf_thresholds["response_time_ms"]["critical"]
                )
            elif response_status == HealthStatus.WARNING:
                await self._generate_alert(
                    AlertSeverity.WARNING,
                    f"Elevated Response Time: {server_name}",
                    f"Average response time ({avg_response_time:.1f}ms) exceeds warning threshold",
                    server_name,
                    "avg_response_time_ms",
                    avg_response_time,
                    perf_thresholds["response_time_ms"]["warning"]
                )
            
            if error_status == HealthStatus.CRITICAL:
                await self._generate_alert(
                    AlertSeverity.CRITICAL,
                    f"High Error Rate: {server_name}",
                    f"Error rate ({error_rate:.1f}%) exceeds critical threshold",
                    server_name,
                    "error_rate_percent",
                    error_rate,
                    perf_thresholds["error_rate_percent"]["critical"]
                )
    
    async def _check_resource_usage(self):
        """Check system resource usage."""
        try:
            # Get process information
            process = psutil.Process()
            
            # Memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = process.memory_percent()
            
            # CPU usage
            cpu_percent = process.cpu_percent(interval=1)
            
            # System-wide metrics
            system_memory = psutil.virtual_memory()
            system_cpu = psutil.cpu_percent(interval=1)
            
            # Determine status
            resource_thresholds = self.config["performance_thresholds"]
            
            memory_status = HealthStatus.HEALTHY
            if memory_percent > resource_thresholds["memory_usage_percent"]["critical"]:
                memory_status = HealthStatus.CRITICAL
            elif memory_percent > resource_thresholds["memory_usage_percent"]["warning"]:
                memory_status = HealthStatus.WARNING
            
            cpu_status = HealthStatus.HEALTHY
            if cpu_percent > resource_thresholds["cpu_usage_percent"]["critical"]:
                cpu_status = HealthStatus.CRITICAL
            elif cpu_percent > resource_thresholds["cpu_usage_percent"]["warning"]:
                cpu_status = HealthStatus.WARNING
            
            overall_status = max(memory_status, cpu_status, key=lambda x: ["healthy", "warning", "critical"].index(x.value))
            
            # Create metrics
            metrics = [
                HealthMetric(
                    metric_name="memory_usage_mb",
                    value=memory_mb,
                    unit="megabytes",
                    status=memory_status
                ),
                HealthMetric(
                    metric_name="memory_usage_percent",
                    value=memory_percent,
                    unit="percent",
                    threshold_warning=resource_thresholds["memory_usage_percent"]["warning"],
                    threshold_critical=resource_thresholds["memory_usage_percent"]["critical"],
                    status=memory_status
                ),
                HealthMetric(
                    metric_name="cpu_usage_percent",
                    value=cpu_percent,
                    unit="percent",
                    threshold_warning=resource_thresholds["cpu_usage_percent"]["warning"],
                    threshold_critical=resource_thresholds["cpu_usage_percent"]["critical"],
                    status=cpu_status
                ),
                HealthMetric(
                    metric_name="system_memory_percent",
                    value=system_memory.percent,
                    unit="percent"
                ),
                HealthMetric(
                    metric_name="system_cpu_percent",
                    value=system_cpu,
                    unit="percent"
                )
            ]
            
            # Create health check result
            result = HealthCheckResult(
                check_id=f"resource_usage_{int(time.time())}",
                check_name="Resource Usage Monitoring",
                check_type=HealthCheckType.RESOURCE_USAGE,
                status=overall_status,
                duration_ms=1000,  # CPU check interval
                metrics=metrics,
                message=f"Memory: {memory_percent:.1f}%, CPU: {cpu_percent:.1f}%",
                details={
                    "process_memory_mb": memory_mb,
                    "system_memory_total_gb": system_memory.total / 1024 / 1024 / 1024,
                    "system_memory_available_gb": system_memory.available / 1024 / 1024 / 1024
                }
            )
            
            self.health_checks.append(result)
            
            # Store metrics for trending
            self.metrics_history.append({
                "timestamp": datetime.now().isoformat(),
                "memory_usage_percent": memory_percent,
                "cpu_usage_percent": cpu_percent,
                "memory_usage_mb": memory_mb
            })
            
            # Generate alerts if thresholds exceeded
            if memory_status == HealthStatus.CRITICAL:
                await self._generate_alert(
                    AlertSeverity.CRITICAL,
                    "High Memory Usage",
                    f"Memory usage ({memory_percent:.1f}%) exceeds critical threshold",
                    "system",
                    "memory_usage_percent",
                    memory_percent,
                    resource_thresholds["memory_usage_percent"]["critical"]
                )
            
            if cpu_status == HealthStatus.CRITICAL:
                await self._generate_alert(
                    AlertSeverity.CRITICAL,
                    "High CPU Usage",
                    f"CPU usage ({cpu_percent:.1f}%) exceeds critical threshold",
                    "system",
                    "cpu_usage_percent",
                    cpu_percent,
                    resource_thresholds["cpu_usage_percent"]["critical"]
                )
            
        except Exception as e:
            logger.error(f"Resource usage check error: {e}")
    
    async def _check_connectivity(self):
        """Check connectivity to external services."""
        connectivity_tests = [
            ("brave_search", "https://api.search.brave.com", "Brave Search API"),
        ]
        
        for test_name, url, description in connectivity_tests:
            start_time = time.time()
            
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    async with session.get(url) as response:
                        duration_ms = (time.time() - start_time) * 1000
                        connected = response.status < 500
                        
                        status = HealthStatus.HEALTHY if connected else HealthStatus.CRITICAL
                        
                        metric = HealthMetric(
                            metric_name="connectivity",
                            value=1.0 if connected else 0.0,
                            unit="boolean",
                            status=status
                        )
                        
                        result = HealthCheckResult(
                            check_id=f"connectivity_{test_name}_{int(time.time())}",
                            check_name=f"Connectivity - {description}",
                            check_type=HealthCheckType.CONNECTIVITY,
                            status=status,
                            duration_ms=duration_ms,
                            metrics=[metric],
                            message=f"Connected to {description}" if connected else f"Failed to connect to {description}",
                            details={
                                "url": url,
                                "status_code": response.status,
                                "connected": connected
                            }
                        )
                        
                        self.health_checks.append(result)
                        
                        if not connected:
                            await self._generate_alert(
                                AlertSeverity.WARNING,
                                f"Connectivity Issue: {description}",
                                f"Failed to connect to {description} ({url})",
                                test_name,
                                "connectivity",
                                0.0,
                                1.0
                            )
                        
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                result = HealthCheckResult(
                    check_id=f"connectivity_{test_name}_{int(time.time())}",
                    check_name=f"Connectivity - {description}",
                    check_type=HealthCheckType.CONNECTIVITY,
                    status=HealthStatus.CRITICAL,
                    duration_ms=duration_ms,
                    message=f"Connectivity test failed: {str(e)}",
                    details={"url": url, "error": str(e)}
                )
                
                self.health_checks.append(result)
                logger.debug(f"Connectivity test failed for {test_name}: {e}")
    
    async def _check_functional_health(self):
        """Check functional health with basic operations."""
        functional_tests = [
            ("desktop-commander", "execute_command", {"command": "echo 'functional test'", "description": "Functional health check"}),
        ]
        
        for server_name, tool_name, params in functional_tests:
            if server_name not in self.registry.list_servers():
                continue
                
            start_time = time.time()
            
            try:
                result = await self.manager.call_tool(
                    f"{server_name}.{tool_name}",
                    params,
                    self.monitor_context_id
                )
                
                duration_ms = (time.time() - start_time) * 1000
                functional = result is not None
                
                status = HealthStatus.HEALTHY if functional else HealthStatus.CRITICAL
                
                metric = HealthMetric(
                    metric_name="functional_health",
                    value=1.0 if functional else 0.0,
                    unit="boolean",
                    status=status
                )
                
                health_result = HealthCheckResult(
                    check_id=f"functional_{server_name}_{int(time.time())}",
                    check_name=f"Functional Health - {server_name}",
                    check_type=HealthCheckType.FUNCTIONAL,
                    status=status,
                    duration_ms=duration_ms,
                    metrics=[metric],
                    message=f"Functional test passed" if functional else f"Functional test failed",
                    details={
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "functional": functional
                    }
                )
                
                self.health_checks.append(health_result)
                
                if not functional:
                    await self._generate_alert(
                        AlertSeverity.CRITICAL,
                        f"Functional Test Failed: {server_name}",
                        f"Functional test failed for {server_name}.{tool_name}",
                        server_name,
                        "functional_health",
                        0.0,
                        1.0
                    )
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                health_result = HealthCheckResult(
                    check_id=f"functional_{server_name}_{int(time.time())}",
                    check_name=f"Functional Health - {server_name}",
                    check_type=HealthCheckType.FUNCTIONAL,
                    status=HealthStatus.CRITICAL,
                    duration_ms=duration_ms,
                    message=f"Functional test error: {str(e)}",
                    details={"server_name": server_name, "error": str(e)}
                )
                
                self.health_checks.append(health_result)
                logger.debug(f"Functional test failed for {server_name}: {e}")
    
    async def _update_sla_compliance(self):
        """Update SLA compliance tracking."""
        if not self.metrics_history:
            return
        
        current_time = datetime.now()
        
        for sla_target in self.sla_targets:
            # Get metrics for the measurement period
            period_metrics = self._get_metrics_for_period(
                sla_target.metric_name,
                sla_target.measurement_period
            )
            
            if not period_metrics:
                continue
            
            # Calculate compliance
            compliant_count = 0
            total_count = len(period_metrics)
            
            for metric_value in period_metrics:
                if self._evaluate_sla_compliance(metric_value, sla_target):
                    compliant_count += 1
            
            compliance_percentage = (compliant_count / total_count) * 100 if total_count > 0 else 100
            
            # Check if SLA is violated
            if compliance_percentage < 99.0:  # SLA violation threshold
                await self._generate_alert(
                    AlertSeverity.WARNING,
                    f"SLA Violation: {sla_target.metric_name}",
                    f"SLA compliance ({compliance_percentage:.1f}%) below target for {sla_target.description}",
                    "sla",
                    sla_target.metric_name,
                    compliance_percentage,
                    99.0
                )
    
    def _get_metrics_for_period(self, metric_name: str, period: str) -> List[float]:
        """Get metrics for a specific time period."""
        # Parse period (simplified implementation)
        period_minutes = {
            "1m": 1,
            "5m": 5,
            "1h": 60,
            "1d": 1440
        }.get(period, 5)
        
        cutoff_time = datetime.now() - timedelta(minutes=period_minutes)
        
        metrics = []
        for entry in self.metrics_history:
            entry_time = datetime.fromisoformat(entry["timestamp"])
            if entry_time >= cutoff_time and metric_name in entry:
                metrics.append(entry[metric_name])
        
        return metrics
    
    def _evaluate_sla_compliance(self, value: float, target: SLATarget) -> bool:
        """Evaluate if a value meets SLA target."""
        if target.comparison == ">=":
            return value >= target.target_value
        elif target.comparison == "<=":
            return value <= target.target_value
        elif target.comparison == "==":
            return value == target.target_value
        elif target.comparison == "!=":
            return value != target.target_value
        elif target.comparison == ">":
            return value > target.target_value
        elif target.comparison == "<":
            return value < target.target_value
        else:
            return True
    
    async def _generate_alert(
        self,
        severity: AlertSeverity,
        title: str,
        description: str,
        component: str,
        metric_name: str,
        current_value: float,
        threshold_value: float
    ):
        """Generate monitoring alert."""
        alert_id = f"alert_{int(time.time())}_{hash(title) % 10000}"
        
        # Check if similar alert already exists (cooldown)
        recent_alerts = [
            alert for alert in self.alerts
            if alert.component == component
            and alert.metric_name == metric_name
            and not alert.resolved
            and (datetime.now() - datetime.fromisoformat(alert.timestamp)).total_seconds() < (self.config["alert_cooldown_minutes"] * 60)
        ]
        
        if recent_alerts:
            return  # Skip duplicate alerts within cooldown period
        
        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            description=description,
            component=component,
            metric_name=metric_name,
            current_value=current_value,
            threshold_value=threshold_value
        )
        
        self.alerts.append(alert)
        
        # Notify alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {e}")
        
        logger.warning(f"ALERT [{severity.value.upper()}] {title}: {description}")
    
    async def _alert_processor(self):
        """Process and manage alerts."""
        while self.monitoring_active:
            try:
                # Auto-resolve alerts that are no longer triggered
                current_time = datetime.now()
                for alert in self.alerts:
                    if not alert.resolved:
                        # Check if alert condition is still true
                        if await self._should_resolve_alert(alert):
                            alert.resolved = True
                            alert.resolution_time = current_time.isoformat()
                            logger.info(f"Alert resolved: {alert.title}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Alert processor error: {e}")
                await asyncio.sleep(60)
    
    async def _should_resolve_alert(self, alert: Alert) -> bool:
        """Check if alert should be auto-resolved."""
        # Get recent metrics for the alert's metric
        recent_metrics = self._get_metrics_for_period(alert.metric_name, "5m")
        
        if not recent_metrics:
            return False
        
        # Check if recent values are within acceptable range
        avg_recent = statistics.mean(recent_metrics)
        
        if alert.severity == AlertSeverity.CRITICAL:
            # For critical alerts, be more conservative
            return avg_recent < alert.threshold_value * 0.8
        elif alert.severity == AlertSeverity.WARNING:
            return avg_recent < alert.threshold_value
        
        return False
    
    def _cleanup_old_metrics(self):
        """Clean up old metrics to prevent memory growth."""
        cutoff_time = datetime.now() - timedelta(hours=self.config["metric_retention_hours"])
        
        self.metrics_history = [
            entry for entry in self.metrics_history
            if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
        ]
        
        # Clean up old health checks
        self.health_checks = [
            check for check in self.health_checks
            if datetime.fromisoformat(check.timestamp) >= cutoff_time
        ]
    
    def add_alert_handler(self, handler: Callable[[Alert], None]):
        """Add custom alert handler."""
        self.alert_handlers.append(handler)
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get current health summary."""
        if not self.health_checks:
            return {"status": "unknown", "message": "No health checks available"}
        
        recent_checks = [
            check for check in self.health_checks
            if (datetime.now() - datetime.fromisoformat(check.timestamp)).total_seconds() < 300  # Last 5 minutes
        ]
        
        if not recent_checks:
            return {"status": "stale", "message": "No recent health checks"}
        
        # Determine overall status
        critical_checks = [check for check in recent_checks if check.status == HealthStatus.CRITICAL]
        warning_checks = [check for check in recent_checks if check.status == HealthStatus.WARNING]
        
        if critical_checks:
            overall_status = "critical"
        elif warning_checks:
            overall_status = "warning"
        else:
            overall_status = "healthy"
        
        # Get recent metrics summary
        recent_metrics = {}
        if self.metrics_history:
            latest_metrics = self.metrics_history[-1]
            recent_metrics = {
                "memory_usage_percent": latest_metrics.get("memory_usage_percent", 0),
                "cpu_usage_percent": latest_metrics.get("cpu_usage_percent", 0),
                "timestamp": latest_metrics.get("timestamp")
            }
        
        # Get active alerts
        active_alerts = [alert for alert in self.alerts if not alert.resolved]
        
        return {
            "overall_status": overall_status,
            "total_checks": len(recent_checks),
            "critical_checks": len(critical_checks),
            "warning_checks": len(warning_checks),
            "healthy_checks": len([check for check in recent_checks if check.status == HealthStatus.HEALTHY]),
            "active_alerts": len(active_alerts),
            "recent_metrics": recent_metrics,
            "last_check_time": max(check.timestamp for check in recent_checks) if recent_checks else None
        }
    
    async def generate_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report."""
        summary = self.get_health_summary()
        
        # SLA compliance
        sla_compliance = {}
        for target in self.sla_targets:
            period_metrics = self._get_metrics_for_period(target.metric_name, target.measurement_period)
            if period_metrics:
                avg_value = statistics.mean(period_metrics)
                compliant = self._evaluate_sla_compliance(avg_value, target)
                sla_compliance[target.metric_name] = {
                    "target": target.target_value,
                    "current": avg_value,
                    "compliant": compliant,
                    "description": target.description
                }
        
        # Trend analysis
        trends = {}
        if len(self.metrics_history) > 10:
            recent_metrics = self.metrics_history[-10:]
            older_metrics = self.metrics_history[-20:-10] if len(self.metrics_history) > 20 else []
            
            for metric_name in ["memory_usage_percent", "cpu_usage_percent"]:
                recent_avg = statistics.mean([m.get(metric_name, 0) for m in recent_metrics])
                older_avg = statistics.mean([m.get(metric_name, 0) for m in older_metrics]) if older_metrics else recent_avg
                
                trend = "stable"
                if recent_avg > older_avg * 1.1:
                    trend = "increasing"
                elif recent_avg < older_avg * 0.9:
                    trend = "decreasing"
                
                trends[metric_name] = {
                    "current_avg": recent_avg,
                    "previous_avg": older_avg,
                    "trend": trend
                }
        
        # Alert summary
        alert_summary = {
            "total_alerts": len(self.alerts),
            "active_alerts": len([a for a in self.alerts if not a.resolved]),
            "critical_alerts": len([a for a in self.alerts if a.severity == AlertSeverity.CRITICAL and not a.resolved]),
            "warning_alerts": len([a for a in self.alerts if a.severity == AlertSeverity.WARNING and not a.resolved]),
            "recent_alerts": [asdict(a) for a in self.alerts[-5:]]  # Last 5 alerts
        }
        
        return {
            "report_id": f"health_report_{self.session_id}",
            "generated_at": datetime.now().isoformat(),
            "monitoring_duration_hours": len(self.metrics_history) * (self.config["check_interval_seconds"] / 3600),
            "summary": summary,
            "sla_compliance": sla_compliance,
            "trends": trends,
            "alerts": alert_summary,
            "health_checks_summary": {
                "total_checks": len(self.health_checks),
                "by_type": {
                    check_type.value: len([c for c in self.health_checks if c.check_type == check_type])
                    for check_type in HealthCheckType
                },
                "by_status": {
                    status.value: len([c for c in self.health_checks if c.status == status])
                    for status in HealthStatus
                }
            }
        }
    
    async def stop_monitoring(self):
        """Stop continuous monitoring."""
        logger.info("Stopping health monitoring...")
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        logger.info("Health monitoring stopped")
    
    async def cleanup(self):
        """Cleanup health monitoring resources."""
        await self.stop_monitoring()
        
        if self.manager:
            await self.manager.cleanup()
        
        logger.info("Health monitoring cleanup completed")


def console_alert_handler(alert: Alert):
    """Simple console alert handler."""
    print(f"\n🚨 ALERT [{alert.severity.value.upper()}] - {alert.title}")
    print(f"   Component: {alert.component}")
    print(f"   Metric: {alert.metric_name}")
    print(f"   Current: {alert.current_value}, Threshold: {alert.threshold_value}")
    print(f"   Description: {alert.description}")
    print(f"   Time: {alert.timestamp}")


async def main():
    """Run MCP health monitoring demonstration."""
    print("💓 MCP Health Monitoring and Validation Suite")
    print("=" * 60)
    print("Agent 5: Real-time health monitoring with SLA tracking and alerting")
    print()
    
    monitor = MCPHealthMonitor()
    
    try:
        await monitor.initialize()
        
        # Add console alert handler
        monitor.add_alert_handler(console_alert_handler)
        
        # Start monitoring
        print("🚀 Starting health monitoring (60 seconds)...")
        await monitor.start_continuous_monitoring(duration_minutes=1)
        
        # Wait for monitoring to complete
        await asyncio.sleep(65)
        
        # Generate health report
        print("\n📊 Generating health report...")
        report = await monitor.generate_health_report()
        
        # Display summary
        print("\n" + "=" * 60)
        print("💓 HEALTH MONITORING COMPLETE")
        print("=" * 60)
        
        summary = report["summary"]
        print(f"Overall Status: {summary['overall_status'].upper()}")
        print(f"Total Checks: {summary['total_checks']}")
        print(f"Critical Issues: {summary['critical_checks']}")
        print(f"Warnings: {summary['warning_checks']}")
        print(f"Healthy: {summary['healthy_checks']}")
        print(f"Active Alerts: {summary['active_alerts']}")
        
        print(f"\nMonitoring Duration: {report['monitoring_duration_hours']:.2f} hours")
        
        if report.get("sla_compliance"):
            print(f"\n📈 SLA Compliance:")
            for metric, data in report["sla_compliance"].items():
                status = "✅ COMPLIANT" if data["compliant"] else "❌ VIOLATION"
                print(f"  {metric}: {status} (Current: {data['current']:.1f}, Target: {data['target']})")
        
        if report.get("trends"):
            print(f"\n📊 Resource Trends:")
            for metric, trend_data in report["trends"].items():
                trend_icon = {"increasing": "📈", "decreasing": "📉", "stable": "➡️"}.get(trend_data["trend"], "❓")
                print(f"  {metric}: {trend_icon} {trend_data['trend']} (Current: {trend_data['current_avg']:.1f}%)")
        
        print(f"\n🔔 Alert Summary:")
        alert_info = report["alerts"]
        print(f"  Total Alerts: {alert_info['total_alerts']}")
        print(f"  Active: {alert_info['active_alerts']} (Critical: {alert_info['critical_alerts']}, Warning: {alert_info['warning_alerts']})")
        
        print("\n✅ Health monitoring demonstration completed!")
        
        # Save report
        results_dir = Path("health_monitoring_results")
        results_dir.mkdir(exist_ok=True)
        
        report_path = results_dir / f"health_report_{monitor.session_id}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Detailed report saved to: {report_path}")
        
        return report
        
    except Exception as e:
        print(f"\n❌ Health monitoring failed: {e}")
        import traceback
        traceback.print_exc()
        return None
        
    finally:
        await monitor.cleanup()


if __name__ == "__main__":
    asyncio.run(main())