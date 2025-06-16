"""
Enhanced MCP Observability and Monitoring Implementation

Provides comprehensive monitoring and observability for MCP server operations
including real-time dashboards, alerting, log aggregation, and performance analysis.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import statistics

from .metrics import get_metrics_collector, MetricsCollector
from .health import get_health_checker, HealthCheckResult, HealthStatus
from .alerts import get_alert_manager, Alert, AlertSeverity, AlertRule
from .tracing import get_tracer, trace_span
from ..mcp.manager import get_mcp_manager

__all__ = [
    "MCPObservability",
    "ServerMetrics",
    "PerformanceProfile",
    "AlertRule",
    "get_mcp_observability"
]

logger = logging.getLogger(__name__)

@dataclass
class ServerMetrics:
    """Comprehensive metrics for an MCP server."""
    server_name: str
    status: str
    uptime_seconds: float
    request_count: int
    error_count: int
    avg_response_time: float
    p95_response_time: float
    p99_response_time: float
    memory_usage_bytes: int
    cpu_usage_percent: float
    active_connections: int
    tools_available: int
    tools_called: int
    last_updated: datetime

@dataclass
class PerformanceProfile:
    """Performance analysis profile for MCP operations."""
    operation_type: str
    total_calls: int
    successful_calls: int
    failed_calls: int
    avg_duration: float
    min_duration: float
    max_duration: float
    p50_duration: float
    p95_duration: float
    p99_duration: float
    error_rate: float
    throughput_per_second: float
    patterns: Dict[str, Any]

class AlertType(Enum):
    """Types of alerts for MCP monitoring."""
    SERVER_DOWN = "server_down"
    HIGH_ERROR_RATE = "high_error_rate"
    HIGH_LATENCY = "high_latency"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SECURITY_INCIDENT = "security_incident"
    INTEGRATION_FAILURE = "integration_failure"
    SLA_BREACH = "sla_breach"
    ANOMALY_DETECTED = "anomaly_detected"

class MCPObservability:
    """Comprehensive MCP observability and monitoring system."""
    
    def __init__(self):
        self.metrics_collector = get_metrics_collector()
        self.health_checker = get_health_checker()
        self.alert_manager = get_alert_manager()
        self.tracer = get_tracer()
        self.mcp_manager = None
        
        # Metrics storage
        self.server_metrics: Dict[str, ServerMetrics] = {}
        self.performance_profiles: Dict[str, PerformanceProfile] = {}
        self.response_times: Dict[str, List[float]] = {}
        
        # Monitoring configuration
        self.monitoring_interval = 30  # seconds
        self.retention_period = timedelta(days=7)
        self.anomaly_threshold = 2.0  # standard deviations
        
        # Alert thresholds
        self.alert_thresholds = {
            AlertType.HIGH_ERROR_RATE: 0.05,  # 5%
            AlertType.HIGH_LATENCY: 5.0,      # 5 seconds
            AlertType.RESOURCE_EXHAUSTION: 0.9,  # 90%
        }
        
        self._monitoring_tasks: List[asyncio.Task] = []
        self._is_monitoring = False
        
    async def initialize(self):
        """Initialize the observability system."""
        self.mcp_manager = await get_mcp_manager()
        await self.mcp_manager.initialize()
        
        # Register custom health checks
        await self._register_health_checks()
        
        # Register alert rules
        await self._register_alert_rules()
        
        # Start monitoring tasks
        await self._start_monitoring()
        
        logger.info("MCP Observability system initialized")
    
    async def _register_health_checks(self):
        """Register comprehensive health checks for MCP servers."""
        
        async def check_server_health(server_name: str) -> HealthCheckResult:
            """Check health of a specific MCP server."""
            try:
                if not self.mcp_manager:
                    return HealthCheckResult(
                        name=f"mcp_server_{server_name}",
                        status=HealthStatus.UNHEALTHY,
                        message="MCP manager not initialized"
                    )
                
                # Get server from registry
                server = self.mcp_manager.registry.servers.get(server_name)
                if not server:
                    return HealthCheckResult(
                        name=f"mcp_server_{server_name}",
                        status=HealthStatus.UNHEALTHY,
                        message=f"Server {server_name} not found in registry"
                    )
                
                # Check server connectivity
                start_time = time.time()
                try:
                    server_info = await server.get_server_info()
                    response_time = time.time() - start_time
                    
                    if server_info:
                        # Update metrics
                        await self._update_server_metrics(server_name, {
                            "status": "healthy",
                            "response_time": response_time,
                            "last_check": datetime.now()
                        })
                        
                        return HealthCheckResult(
                            name=f"mcp_server_{server_name}",
                            status=HealthStatus.HEALTHY,
                            message=f"Server {server_name} is healthy",
                            details={
                                "response_time": response_time,
                                "server_info": server_info
                            }
                        )
                    else:
                        return HealthCheckResult(
                            name=f"mcp_server_{server_name}",
                            status=HealthStatus.DEGRADED,
                            message=f"Server {server_name} responded but with no info"
                        )
                        
                except Exception as e:
                    await self._update_server_metrics(server_name, {
                        "status": "unhealthy",
                        "last_error": str(e),
                        "last_check": datetime.now()
                    })
                    
                    return HealthCheckResult(
                        name=f"mcp_server_{server_name}",
                        status=HealthStatus.UNHEALTHY,
                        message=f"Server {server_name} check failed: {str(e)}"
                    )
                    
            except Exception as e:
                logger.error(f"Health check error for {server_name}: {e}")
                return HealthCheckResult(
                    name=f"mcp_server_{server_name}",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check error: {str(e)}"
                )
        
        # Register health checks for all servers
        if self.mcp_manager:
            for server_name in self.mcp_manager.registry.servers.keys():
                self.health_checker.register_check(
                    f"mcp_server_{server_name}",
                    lambda name=server_name: check_server_health(name),
                    is_async=True
                )
    
    async def _register_alert_rules(self):
        """Register comprehensive alert rules for MCP monitoring."""
        
        # Server down alert
        server_down_rule = AlertRule(
            name="MCP_Server_Down",
            description="MCP server is not responding",
            severity=AlertSeverity.CRITICAL,
            condition="health_check_status{type=\"mcp_server\"} != 1",
            duration=timedelta(minutes=2),
            annotations={
                "summary": "MCP Server {{ $labels.server }} is down",
                "description": "MCP server {{ $labels.server }} has been unresponsive for more than 2 minutes"
            }
        )
        
        # High error rate alert
        high_error_rate_rule = AlertRule(
            name="MCP_High_Error_Rate",
            description="High error rate in MCP operations",
            severity=AlertSeverity.HIGH,
            condition="rate(mcp_tool_calls_total{status=\"error\"}[5m]) / rate(mcp_tool_calls_total[5m]) > 0.05",
            duration=timedelta(minutes=5),
            annotations={
                "summary": "High error rate in MCP server {{ $labels.server }}",
                "description": "Error rate is {{ $value | humanizePercentage }} over the last 5 minutes"
            }
        )
        
        # High latency alert
        high_latency_rule = AlertRule(
            name="MCP_High_Latency",
            description="High latency in MCP operations",
            severity=AlertSeverity.MEDIUM,
            condition="histogram_quantile(0.95, rate(mcp_tool_duration_seconds_bucket[5m])) > 5",
            duration=timedelta(minutes=10),
            annotations={
                "summary": "High latency in MCP server {{ $labels.server }}",
                "description": "95th percentile latency is {{ $value }}s over the last 5 minutes"
            }
        )
        
        # Security incident alert
        security_incident_rule = AlertRule(
            name="MCP_Security_Incident",
            description="Security incident detected in MCP operations",
            severity=AlertSeverity.CRITICAL,
            condition="rate(security_events_total{type=\"mcp\"}[1m]) > 0",
            duration=timedelta(seconds=30),
            annotations={
                "summary": "Security incident detected in MCP operations",
                "description": "{{ $value }} security events detected in the last minute"
            }
        )
        
        # Register all alert rules
        for rule in [server_down_rule, high_error_rate_rule, high_latency_rule, security_incident_rule]:
            self.alert_manager.register_rule(rule)
    
    async def _start_monitoring(self):
        """Start continuous monitoring tasks."""
        if self._is_monitoring:
            return
            
        self._is_monitoring = True
        
        # Start monitoring tasks
        self._monitoring_tasks = [
            asyncio.create_task(self._monitor_server_metrics()),
            asyncio.create_task(self._monitor_performance_profiles()),
            asyncio.create_task(self._monitor_anomalies()),
            asyncio.create_task(self._cleanup_old_data()),
        ]
        
        logger.info("Started MCP monitoring tasks")
    
    async def _monitor_server_metrics(self):
        """Continuously monitor server metrics."""
        while self._is_monitoring:
            try:
                if self.mcp_manager:
                    for server_name, server in self.mcp_manager.registry.servers.items():
                        await self._collect_server_metrics(server_name, server)
                
                await asyncio.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in server metrics monitoring: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def _collect_server_metrics(self, server_name: str, server):
        """Collect comprehensive metrics for a server."""
        try:
            start_time = time.time()
            
            # Get server info
            server_info = await server.get_server_info()
            response_time = time.time() - start_time
            
            # Get or create metrics record
            if server_name not in self.server_metrics:
                self.server_metrics[server_name] = ServerMetrics(
                    server_name=server_name,
                    status="unknown",
                    uptime_seconds=0,
                    request_count=0,
                    error_count=0,
                    avg_response_time=0,
                    p95_response_time=0,
                    p99_response_time=0,
                    memory_usage_bytes=0,
                    cpu_usage_percent=0,
                    active_connections=0,
                    tools_available=0,
                    tools_called=0,
                    last_updated=datetime.now()
                )
            
            metrics = self.server_metrics[server_name]
            
            # Update response times
            if server_name not in self.response_times:
                self.response_times[server_name] = []
            
            self.response_times[server_name].append(response_time)
            
            # Keep only recent response times (last 1000 measurements)
            if len(self.response_times[server_name]) > 1000:
                self.response_times[server_name] = self.response_times[server_name][-1000:]
            
            # Calculate percentiles
            if self.response_times[server_name]:
                metrics.avg_response_time = statistics.mean(self.response_times[server_name])
                sorted_times = sorted(self.response_times[server_name])
                metrics.p95_response_time = sorted_times[int(len(sorted_times) * 0.95)]
                metrics.p99_response_time = sorted_times[int(len(sorted_times) * 0.99)]
            
            # Update basic metrics
            metrics.status = "healthy" if server_info else "degraded"
            metrics.last_updated = datetime.now()
            
            if server_info:
                # Extract tools information
                tools_info = server_info.get("tools", [])
                metrics.tools_available = len(tools_info)
            
            # Record Prometheus metrics
            self.metrics_collector.business_operations_total.labels(
                operation="mcp_health_check",
                server=server_name,
                status=metrics.status
            ).inc()
            
            # Record response time
            self.metrics_collector.business_operation_duration_seconds.labels(
                operation="mcp_health_check",
                server=server_name
            ).observe(response_time)
            
        except Exception as e:
            logger.error(f"Error collecting metrics for {server_name}: {e}")
            
            # Update error metrics
            if server_name in self.server_metrics:
                self.server_metrics[server_name].error_count += 1
                self.server_metrics[server_name].status = "error"
                self.server_metrics[server_name].last_updated = datetime.now()
    
    async def _monitor_performance_profiles(self):
        """Monitor and analyze performance patterns."""
        while self._is_monitoring:
            try:
                await self._analyze_performance_patterns()
                await asyncio.sleep(300)  # Every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in performance monitoring: {e}")
                await asyncio.sleep(300)
    
    async def _analyze_performance_patterns(self):
        """Analyze performance patterns and update profiles."""
        for server_name, response_times in self.response_times.items():
            if not response_times:
                continue
                
            try:
                # Calculate performance metrics
                total_calls = len(response_times)
                avg_duration = statistics.mean(response_times)
                min_duration = min(response_times)
                max_duration = max(response_times)
                
                sorted_times = sorted(response_times)
                p50_duration = sorted_times[int(len(sorted_times) * 0.5)]
                p95_duration = sorted_times[int(len(sorted_times) * 0.95)]
                p99_duration = sorted_times[int(len(sorted_times) * 0.99)]
                
                # Detect patterns
                patterns = await self._detect_patterns(response_times)
                
                # Update performance profile
                profile = PerformanceProfile(
                    operation_type=f"mcp_server_{server_name}",
                    total_calls=total_calls,
                    successful_calls=total_calls,  # Simplified for now
                    failed_calls=0,
                    avg_duration=avg_duration,
                    min_duration=min_duration,
                    max_duration=max_duration,
                    p50_duration=p50_duration,
                    p95_duration=p95_duration,
                    p99_duration=p99_duration,
                    error_rate=0.0,  # Simplified for now
                    throughput_per_second=total_calls / 1800,  # Last 30 minutes
                    patterns=patterns
                )
                
                self.performance_profiles[server_name] = profile
                
                # Check for performance alerts
                await self._check_performance_alerts(server_name, profile)
                
            except Exception as e:
                logger.error(f"Error analyzing performance for {server_name}: {e}")
    
    async def _detect_patterns(self, response_times: List[float]) -> Dict[str, Any]:
        """Detect patterns in response times."""
        patterns = {}
        
        try:
            if len(response_times) < 10:
                return patterns
            
            # Trend analysis
            recent_times = response_times[-50:]  # Last 50 measurements
            older_times = response_times[-100:-50] if len(response_times) >= 100 else []
            
            if older_times:
                recent_avg = statistics.mean(recent_times)
                older_avg = statistics.mean(older_times)
                trend = (recent_avg - older_avg) / older_avg * 100
                patterns["trend_percentage"] = trend
                patterns["trend_direction"] = "increasing" if trend > 5 else "decreasing" if trend < -5 else "stable"
            
            # Variance analysis
            variance = statistics.variance(response_times)
            std_dev = statistics.stdev(response_times)
            patterns["variance"] = variance
            patterns["standard_deviation"] = std_dev
            patterns["stability"] = "stable" if std_dev < 0.5 else "variable" if std_dev < 2.0 else "unstable"
            
            # Outlier detection
            mean_time = statistics.mean(response_times)
            outliers = [t for t in response_times if abs(t - mean_time) > (self.anomaly_threshold * std_dev)]
            patterns["outlier_count"] = len(outliers)
            patterns["outlier_percentage"] = len(outliers) / len(response_times) * 100
            
        except Exception as e:
            logger.error(f"Error detecting patterns: {e}")
            
        return patterns
    
    async def _check_performance_alerts(self, server_name: str, profile: PerformanceProfile):
        """Check if performance metrics trigger alerts."""
        try:
            # High latency alert
            if profile.p95_duration > self.alert_thresholds[AlertType.HIGH_LATENCY]:
                await self._trigger_alert(
                    AlertType.HIGH_LATENCY,
                    f"High latency detected in {server_name}",
                    {
                        "server": server_name,
                        "p95_latency": profile.p95_duration,
                        "threshold": self.alert_thresholds[AlertType.HIGH_LATENCY]
                    }
                )
            
            # Performance degradation alert
            if "trend_percentage" in profile.patterns:
                trend = profile.patterns["trend_percentage"]
                if trend > 50:  # 50% increase in response time
                    await self._trigger_alert(
                        AlertType.ANOMALY_DETECTED,
                        f"Performance degradation detected in {server_name}",
                        {
                            "server": server_name,
                            "trend_percentage": trend,
                            "stability": profile.patterns.get("stability", "unknown")
                        }
                    )
            
        except Exception as e:
            logger.error(f"Error checking performance alerts for {server_name}: {e}")
    
    async def _trigger_alert(self, alert_type: AlertType, message: str, details: Dict[str, Any]):
        """Trigger a custom alert."""
        try:
            # Create a mock alert rule for custom alerts
            alert_rule = AlertRule(
                name=f"Custom_{alert_type.value}",
                description=message,
                severity=AlertSeverity.MEDIUM,
                condition="custom_condition",
                duration=timedelta(seconds=0),
                annotations={
                    "summary": message,
                    "description": json.dumps(details)
                }
            )
            
            # Check the alert
            self.alert_manager.check_alert(
                alert_rule,
                value=1.0,
                labels=details
            )
            
        except Exception as e:
            logger.error(f"Error triggering alert: {e}")
    
    async def _monitor_anomalies(self):
        """Monitor for anomalies in MCP operations."""
        while self._is_monitoring:
            try:
                await self._detect_anomalies()
                await asyncio.sleep(120)  # Every 2 minutes
                
            except Exception as e:
                logger.error(f"Error in anomaly monitoring: {e}")
                await asyncio.sleep(120)
    
    async def _detect_anomalies(self):
        """Detect anomalies in server behavior."""
        for server_name, metrics in self.server_metrics.items():
            try:
                # Check for status changes
                if metrics.status == "error" and server_name in self.response_times:
                    recent_errors = sum(1 for _ in self.response_times[server_name][-10:])
                    if recent_errors > 5:  # More than 5 errors in last 10 attempts
                        await self._trigger_alert(
                            AlertType.SERVER_DOWN,
                            f"Server {server_name} is experiencing frequent errors",
                            {"server": server_name, "recent_errors": recent_errors}
                        )
                
                # Check for unusual response time patterns
                if server_name in self.response_times and len(self.response_times[server_name]) > 20:
                    times = self.response_times[server_name]
                    mean_time = statistics.mean(times)
                    std_dev = statistics.stdev(times)
                    
                    # Check if recent measurements are anomalous
                    recent_times = times[-5:]
                    anomalous_count = sum(
                        1 for t in recent_times 
                        if abs(t - mean_time) > (self.anomaly_threshold * std_dev)
                    )
                    
                    if anomalous_count >= 3:  # 3 out of 5 recent measurements are anomalous
                        await self._trigger_alert(
                            AlertType.ANOMALY_DETECTED,
                            f"Anomalous response times detected in {server_name}",
                            {
                                "server": server_name,
                                "anomalous_count": anomalous_count,
                                "mean_time": mean_time,
                                "std_dev": std_dev
                            }
                        )
                
            except Exception as e:
                logger.error(f"Error detecting anomalies for {server_name}: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old monitoring data."""
        while self._is_monitoring:
            try:
                cutoff_time = datetime.now() - self.retention_period
                
                # Clean up old metrics
                for server_name in list(self.server_metrics.keys()):
                    metrics = self.server_metrics[server_name]
                    if metrics.last_updated < cutoff_time:
                        del self.server_metrics[server_name]
                        if server_name in self.response_times:
                            del self.response_times[server_name]
                        if server_name in self.performance_profiles:
                            del self.performance_profiles[server_name]
                
                logger.info("Cleaned up old monitoring data")
                await asyncio.sleep(3600)  # Every hour
                
            except Exception as e:
                logger.error(f"Error cleaning up old data: {e}")
                await asyncio.sleep(3600)
    
    async def _update_server_metrics(self, server_name: str, updates: Dict[str, Any]):
        """Update server metrics with new data."""
        if server_name not in self.server_metrics:
            return
            
        metrics = self.server_metrics[server_name]
        for key, value in updates.items():
            if hasattr(metrics, key):
                setattr(metrics, key, value)
    
    async def get_server_metrics(self, server_name: Optional[str] = None) -> Union[ServerMetrics, Dict[str, ServerMetrics]]:
        """Get server metrics."""
        if server_name:
            return self.server_metrics.get(server_name)
        return self.server_metrics.copy()
    
    async def get_performance_profile(self, server_name: str) -> Optional[PerformanceProfile]:
        """Get performance profile for a server."""
        return self.performance_profiles.get(server_name)
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for monitoring dashboards."""
        try:
            dashboard_data = {
                "timestamp": datetime.now().isoformat(),
                "servers": {},
                "overall_health": "healthy",
                "total_servers": len(self.server_metrics),
                "healthy_servers": 0,
                "degraded_servers": 0,
                "unhealthy_servers": 0,
                "performance_summary": {},
                "alerts": []
            }
            
            # Collect server data
            for server_name, metrics in self.server_metrics.items():
                dashboard_data["servers"][server_name] = asdict(metrics)
                
                # Count server states
                if metrics.status == "healthy":
                    dashboard_data["healthy_servers"] += 1
                elif metrics.status == "degraded":
                    dashboard_data["degraded_servers"] += 1
                else:
                    dashboard_data["unhealthy_servers"] += 1
            
            # Determine overall health
            total = dashboard_data["total_servers"]
            healthy = dashboard_data["healthy_servers"]
            
            if total == 0:
                dashboard_data["overall_health"] = "unknown"
            elif healthy == total:
                dashboard_data["overall_health"] = "healthy"
            elif healthy >= total * 0.8:
                dashboard_data["overall_health"] = "degraded"
            else:
                dashboard_data["overall_health"] = "unhealthy"
            
            # Add performance summaries
            for server_name, profile in self.performance_profiles.items():
                dashboard_data["performance_summary"][server_name] = asdict(profile)
            
            # Add active alerts
            active_alerts = await self.alert_manager.get_active_alerts()
            dashboard_data["alerts"] = [
                {
                    "name": alert.rule.name,
                    "severity": alert.rule.severity.value,
                    "message": alert.annotations.get("summary", "No summary"),
                    "started_at": alert.started_at.isoformat()
                }
                for alert in active_alerts
            ]
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating dashboard data: {e}")
            return {"error": str(e)}
    
    async def export_metrics(self, format: str = "prometheus") -> str:
        """Export metrics in various formats."""
        try:
            if format == "prometheus":
                return self.metrics_collector.get_metrics().decode('utf-8')
            elif format == "json":
                data = await self.get_dashboard_data()
                return json.dumps(data, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")
            return f"Error: {str(e)}"
    
    async def shutdown(self):
        """Shutdown the observability system."""
        self._is_monitoring = False
        
        # Cancel monitoring tasks
        for task in self._monitoring_tasks:
            task.cancel()
            
        try:
            await asyncio.gather(*self._monitoring_tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Error shutting down monitoring tasks: {e}")
            
        logger.info("MCP Observability system shut down")


# Global instance
_mcp_observability: Optional[MCPObservability] = None


async def get_mcp_observability() -> MCPObservability:
    """Get the global MCP observability instance."""
    global _mcp_observability
    if _mcp_observability is None:
        _mcp_observability = MCPObservability()
        await _mcp_observability.initialize()
    return _mcp_observability