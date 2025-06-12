"""
Node Health Monitoring - Comprehensive monitoring and alerting for distributed test nodes.
Monitors node health, performance, and availability with automated failover capabilities.
"""

import asyncio
import json
import logging
import time
import uuid
import psutil
import socket
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable
import aiohttp
import websockets
from concurrent.futures import ThreadPoolExecutor
import statistics

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Node health status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class MetricType(Enum):
    """Metric type enumeration"""
    GAUGE = "gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class HealthMetric:
    """Individual health metric"""
    name: str
    value: float
    unit: str
    metric_type: MetricType
    timestamp: datetime
    labels: Dict[str, str] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None


@dataclass
class HealthCheck:
    """Health check definition"""
    check_id: str
    name: str
    description: str
    check_function: Callable
    interval: timedelta
    timeout: timedelta
    enabled: bool = True
    dependencies: List[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class Alert:
    """Alert definition"""
    alert_id: str
    node_id: str
    metric_name: str
    severity: AlertSeverity
    message: str
    current_value: float
    threshold: float
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class NodeHealth:
    """Node health summary"""
    node_id: str
    overall_status: HealthStatus
    last_updated: datetime
    uptime: timedelta
    metrics: Dict[str, HealthMetric]
    active_alerts: List[Alert]
    health_score: float  # 0-100
    availability: float  # percentage
    last_seen: datetime


class HealthThresholds:
    """Default health thresholds"""
    
    CPU_WARNING = 80.0
    CPU_CRITICAL = 95.0
    MEMORY_WARNING = 85.0
    MEMORY_CRITICAL = 95.0
    DISK_WARNING = 80.0
    DISK_CRITICAL = 95.0
    LOAD_WARNING = 5.0
    LOAD_CRITICAL = 10.0
    RESPONSE_TIME_WARNING = 5.0  # seconds
    RESPONSE_TIME_CRITICAL = 10.0  # seconds
    ERROR_RATE_WARNING = 5.0  # percentage
    ERROR_RATE_CRITICAL = 10.0  # percentage


class NodeMonitor:
    """Individual node monitoring agent"""
    
    def __init__(self, node_id: str, reporting_interval: float = 30.0):
        self.node_id = node_id
        self.reporting_interval = reporting_interval
        self.health_checks: Dict[str, HealthCheck] = {}
        self.current_metrics: Dict[str, HealthMetric] = {}
        self.alerts: Dict[str, Alert] = {}
        self.running = False
        self.start_time = datetime.now()
        
        # Network info
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        
        # Monitoring state
        self.last_health_check = datetime.now()
        self.health_check_failures = 0
        self.max_consecutive_failures = 3
        
        # Register default health checks
        self._register_default_health_checks()

    def _get_ip_address(self) -> str:
        """Get node IP address"""
        try:
            # Connect to a dummy address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _register_default_health_checks(self):
        """Register default health checks"""
        # CPU health check
        self.register_health_check(HealthCheck(
            check_id="cpu_usage",
            name="CPU Usage",
            description="Monitor CPU utilization",
            check_function=self._check_cpu_usage,
            interval=timedelta(seconds=30),
            timeout=timedelta(seconds=5)
        ))
        
        # Memory health check
        self.register_health_check(HealthCheck(
            check_id="memory_usage",
            name="Memory Usage",
            description="Monitor memory utilization",
            check_function=self._check_memory_usage,
            interval=timedelta(seconds=30),
            timeout=timedelta(seconds=5)
        ))
        
        # Disk health check
        self.register_health_check(HealthCheck(
            check_id="disk_usage",
            name="Disk Usage",
            description="Monitor disk space utilization",
            check_function=self._check_disk_usage,
            interval=timedelta(seconds=60),
            timeout=timedelta(seconds=10)
        ))
        
        # Network connectivity check
        self.register_health_check(HealthCheck(
            check_id="network_connectivity",
            name="Network Connectivity",
            description="Check network connectivity",
            check_function=self._check_network_connectivity,
            interval=timedelta(seconds=60),
            timeout=timedelta(seconds=10)
        ))
        
        # Process count check
        self.register_health_check(HealthCheck(
            check_id="process_count",
            name="Process Count",
            description="Monitor system process count",
            check_function=self._check_process_count,
            interval=timedelta(seconds=60),
            timeout=timedelta(seconds=5)
        ))

    def register_health_check(self, health_check: HealthCheck):
        """Register a health check"""
        self.health_checks[health_check.check_id] = health_check
        logger.info(f"Registered health check: {health_check.name}")

    def unregister_health_check(self, check_id: str):
        """Unregister a health check"""
        if check_id in self.health_checks:
            del self.health_checks[check_id]
            logger.info(f"Unregistered health check: {check_id}")

    async def start_monitoring(self):
        """Start monitoring process"""
        self.running = True
        logger.info(f"Starting monitoring for node {self.node_id}")
        
        # Start health check tasks
        tasks = []
        for health_check in self.health_checks.values():
            if health_check.enabled:
                task = asyncio.create_task(self._run_health_check(health_check))
                tasks.append(task)
        
        # Start metrics collection
        metrics_task = asyncio.create_task(self._collect_system_metrics())
        tasks.append(metrics_task)
        
        # Start alert processing
        alert_task = asyncio.create_task(self._process_alerts())
        tasks.append(alert_task)
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
        finally:
            self.running = False

    async def stop_monitoring(self):
        """Stop monitoring process"""
        self.running = False
        logger.info(f"Stopping monitoring for node {self.node_id}")

    async def _run_health_check(self, health_check: HealthCheck):
        """Run individual health check"""
        while self.running:
            try:
                if health_check.enabled:
                    # Execute health check with timeout
                    try:
                        result = await asyncio.wait_for(
                            health_check.check_function(),
                            timeout=health_check.timeout.total_seconds()
                        )
                        
                        if result:
                            self.health_check_failures = 0
                        else:
                            self.health_check_failures += 1
                            
                    except asyncio.TimeoutError:
                        logger.warning(f"Health check {health_check.name} timed out")
                        self.health_check_failures += 1
                    except Exception as e:
                        logger.error(f"Health check {health_check.name} failed: {e}")
                        self.health_check_failures += 1
                
                await asyncio.sleep(health_check.interval.total_seconds())
                
            except Exception as e:
                logger.error(f"Error in health check loop {health_check.name}: {e}")
                await asyncio.sleep(health_check.interval.total_seconds())

    async def _check_cpu_usage(self) -> bool:
        """Check CPU usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            
            metric = HealthMetric(
                name="cpu_usage_percent",
                value=cpu_percent,
                unit="percent",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now(),
                threshold_warning=HealthThresholds.CPU_WARNING,
                threshold_critical=HealthThresholds.CPU_CRITICAL
            )
            
            self.current_metrics["cpu_usage_percent"] = metric
            await self._evaluate_metric_thresholds(metric)
            
            return cpu_percent < HealthThresholds.CPU_CRITICAL
            
        except Exception as e:
            logger.error(f"Error checking CPU usage: {e}")
            return False

    async def _check_memory_usage(self) -> bool:
        """Check memory usage"""
        try:
            memory = psutil.virtual_memory()
            
            metric = HealthMetric(
                name="memory_usage_percent",
                value=memory.percent,
                unit="percent",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now(),
                threshold_warning=HealthThresholds.MEMORY_WARNING,
                threshold_critical=HealthThresholds.MEMORY_CRITICAL
            )
            
            self.current_metrics["memory_usage_percent"] = metric
            await self._evaluate_metric_thresholds(metric)
            
            return memory.percent < HealthThresholds.MEMORY_CRITICAL
            
        except Exception as e:
            logger.error(f"Error checking memory usage: {e}")
            return False

    async def _check_disk_usage(self) -> bool:
        """Check disk usage"""
        try:
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            metric = HealthMetric(
                name="disk_usage_percent",
                value=disk_percent,
                unit="percent",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now(),
                threshold_warning=HealthThresholds.DISK_WARNING,
                threshold_critical=HealthThresholds.DISK_CRITICAL
            )
            
            self.current_metrics["disk_usage_percent"] = metric
            await self._evaluate_metric_thresholds(metric)
            
            return disk_percent < HealthThresholds.DISK_CRITICAL
            
        except Exception as e:
            logger.error(f"Error checking disk usage: {e}")
            return False

    async def _check_network_connectivity(self) -> bool:
        """Check network connectivity"""
        try:
            # Try to connect to a well-known service
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.get('http://httpbin.org/ip', timeout=aiohttp.ClientTimeout(total=5)) as response:
                    response_time = time.time() - start_time
                    
                    # Record response time metric
                    metric = HealthMetric(
                        name="network_response_time",
                        value=response_time,
                        unit="seconds",
                        metric_type=MetricType.GAUGE,
                        timestamp=datetime.now(),
                        threshold_warning=HealthThresholds.RESPONSE_TIME_WARNING,
                        threshold_critical=HealthThresholds.RESPONSE_TIME_CRITICAL
                    )
                    
                    self.current_metrics["network_response_time"] = metric
                    await self._evaluate_metric_thresholds(metric)
                    
                    return response.status == 200 and response_time < HealthThresholds.RESPONSE_TIME_CRITICAL
                    
        except Exception as e:
            logger.debug(f"Network connectivity check failed: {e}")
            
            # Record failed connectivity
            metric = HealthMetric(
                name="network_response_time",
                value=999.0,  # High value to indicate failure
                unit="seconds",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now(),
                threshold_warning=HealthThresholds.RESPONSE_TIME_WARNING,
                threshold_critical=HealthThresholds.RESPONSE_TIME_CRITICAL
            )
            
            self.current_metrics["network_response_time"] = metric
            await self._evaluate_metric_thresholds(metric)
            
            return False

    async def _check_process_count(self) -> bool:
        """Check system process count"""
        try:
            process_count = len(psutil.pids())
            
            metric = HealthMetric(
                name="process_count",
                value=float(process_count),
                unit="count",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now()
            )
            
            self.current_metrics["process_count"] = metric
            
            # Generally process count under 1000 is considered normal
            return process_count < 1000
            
        except Exception as e:
            logger.error(f"Error checking process count: {e}")
            return False

    async def _collect_system_metrics(self):
        """Collect additional system metrics"""
        while self.running:
            try:
                # Load average
                if hasattr(psutil, 'getloadavg'):
                    load_avg = psutil.getloadavg()[0]
                    
                    metric = HealthMetric(
                        name="load_average",
                        value=load_avg,
                        unit="load",
                        metric_type=MetricType.GAUGE,
                        timestamp=datetime.now(),
                        threshold_warning=HealthThresholds.LOAD_WARNING,
                        threshold_critical=HealthThresholds.LOAD_CRITICAL
                    )
                    
                    self.current_metrics["load_average"] = metric
                    await self._evaluate_metric_thresholds(metric)
                
                # Network I/O
                net_io = psutil.net_io_counters()
                
                # Bytes sent metric
                metric = HealthMetric(
                    name="network_bytes_sent",
                    value=float(net_io.bytes_sent),
                    unit="bytes",
                    metric_type=MetricType.COUNTER,
                    timestamp=datetime.now()
                )
                self.current_metrics["network_bytes_sent"] = metric
                
                # Bytes received metric
                metric = HealthMetric(
                    name="network_bytes_received",
                    value=float(net_io.bytes_recv),
                    unit="bytes",
                    metric_type=MetricType.COUNTER,
                    timestamp=datetime.now()
                )
                self.current_metrics["network_bytes_received"] = metric
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    # Disk read bytes
                    metric = HealthMetric(
                        name="disk_read_bytes",
                        value=float(disk_io.read_bytes),
                        unit="bytes",
                        metric_type=MetricType.COUNTER,
                        timestamp=datetime.now()
                    )
                    self.current_metrics["disk_read_bytes"] = metric
                    
                    # Disk write bytes
                    metric = HealthMetric(
                        name="disk_write_bytes",
                        value=float(disk_io.write_bytes),
                        unit="bytes",
                        metric_type=MetricType.COUNTER,
                        timestamp=datetime.now()
                    )
                    self.current_metrics["disk_write_bytes"] = metric
                
                # Temperature (if available)
                try:
                    temperatures = psutil.sensors_temperatures()
                    if temperatures:
                        for sensor_name, sensor_list in temperatures.items():
                            for sensor in sensor_list:
                                if sensor.current:
                                    metric = HealthMetric(
                                        name=f"temperature_{sensor_name}",
                                        value=sensor.current,
                                        unit="celsius",
                                        metric_type=MetricType.GAUGE,
                                        timestamp=datetime.now(),
                                        threshold_warning=70.0,
                                        threshold_critical=85.0
                                    )
                                    self.current_metrics[f"temperature_{sensor_name}"] = metric
                                    await self._evaluate_metric_thresholds(metric)
                except:
                    pass  # Temperature sensors not available
                
                await asyncio.sleep(self.reporting_interval)
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(self.reporting_interval)

    async def _evaluate_metric_thresholds(self, metric: HealthMetric):
        """Evaluate metric against thresholds and generate alerts"""
        if not metric.threshold_warning and not metric.threshold_critical:
            return
        
        # Check critical threshold
        if (metric.threshold_critical and 
            metric.value >= metric.threshold_critical):
            
            await self._create_alert(
                metric.name,
                AlertSeverity.CRITICAL,
                f"{metric.name} is critically high: {metric.value} {metric.unit}",
                metric.value,
                metric.threshold_critical
            )
        
        # Check warning threshold
        elif (metric.threshold_warning and 
              metric.value >= metric.threshold_warning):
            
            await self._create_alert(
                metric.name,
                AlertSeverity.WARNING,
                f"{metric.name} is high: {metric.value} {metric.unit}",
                metric.value,
                metric.threshold_warning
            )
        
        else:
            # Resolve existing alerts for this metric
            await self._resolve_alerts_for_metric(metric.name)

    async def _create_alert(self, metric_name: str, severity: AlertSeverity, 
                           message: str, current_value: float, threshold: float):
        """Create or update an alert"""
        alert_key = f"{metric_name}_{severity.value}"
        
        if alert_key not in self.alerts:
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                node_id=self.node_id,
                metric_name=metric_name,
                severity=severity,
                message=message,
                current_value=current_value,
                threshold=threshold,
                triggered_at=datetime.now()
            )
            
            self.alerts[alert_key] = alert
            logger.warning(f"Alert triggered: {message}")
        else:
            # Update existing alert
            existing_alert = self.alerts[alert_key]
            existing_alert.current_value = current_value
            existing_alert.message = message

    async def _resolve_alerts_for_metric(self, metric_name: str):
        """Resolve alerts for a specific metric"""
        resolved_alerts = []
        
        for alert_key, alert in self.alerts.items():
            if alert.metric_name == metric_name and not alert.resolved_at:
                alert.resolved_at = datetime.now()
                resolved_alerts.append(alert_key)
                logger.info(f"Alert resolved: {alert.message}")
        
        # Remove resolved alerts
        for alert_key in resolved_alerts:
            del self.alerts[alert_key]

    async def _process_alerts(self):
        """Process and manage alerts"""
        while self.running:
            try:
                # Clean up old resolved alerts
                current_time = datetime.now()
                old_alerts = []
                
                for alert_key, alert in self.alerts.items():
                    if (alert.resolved_at and 
                        current_time - alert.resolved_at > timedelta(hours=24)):
                        old_alerts.append(alert_key)
                
                for alert_key in old_alerts:
                    del self.alerts[alert_key]
                
                await asyncio.sleep(300)  # Process alerts every 5 minutes
                
            except Exception as e:
                logger.error(f"Error processing alerts: {e}")
                await asyncio.sleep(300)

    def get_health_summary(self) -> NodeHealth:
        """Get current health summary"""
        # Calculate overall health status
        overall_status = self._calculate_overall_status()
        
        # Calculate health score
        health_score = self._calculate_health_score()
        
        # Calculate uptime
        uptime = datetime.now() - self.start_time
        
        # Calculate availability (simplified)
        availability = max(0, 100.0 - (self.health_check_failures * 10))
        
        active_alerts = [alert for alert in self.alerts.values() if not alert.resolved_at]
        
        return NodeHealth(
            node_id=self.node_id,
            overall_status=overall_status,
            last_updated=datetime.now(),
            uptime=uptime,
            metrics=self.current_metrics.copy(),
            active_alerts=active_alerts,
            health_score=health_score,
            availability=availability,
            last_seen=datetime.now()
        )

    def _calculate_overall_status(self) -> HealthStatus:
        """Calculate overall health status"""
        if self.health_check_failures >= self.max_consecutive_failures:
            return HealthStatus.FAILED
        
        # Check for critical alerts
        critical_alerts = [alert for alert in self.alerts.values() 
                          if alert.severity == AlertSeverity.CRITICAL and not alert.resolved_at]
        
        if critical_alerts:
            return HealthStatus.CRITICAL
        
        # Check for warning alerts
        warning_alerts = [alert for alert in self.alerts.values() 
                         if alert.severity == AlertSeverity.WARNING and not alert.resolved_at]
        
        if warning_alerts:
            return HealthStatus.WARNING
        
        return HealthStatus.HEALTHY

    def _calculate_health_score(self) -> float:
        """Calculate health score (0-100)"""
        score = 100.0
        
        # Deduct points for failures
        score -= self.health_check_failures * 10
        
        # Deduct points for active alerts
        for alert in self.alerts.values():
            if not alert.resolved_at:
                if alert.severity == AlertSeverity.CRITICAL:
                    score -= 30
                elif alert.severity == AlertSeverity.WARNING:
                    score -= 15
                elif alert.severity == AlertSeverity.INFO:
                    score -= 5
        
        # Deduct points for high resource usage
        cpu_metric = self.current_metrics.get("cpu_usage_percent")
        if cpu_metric and cpu_metric.value > 80:
            score -= (cpu_metric.value - 80) * 0.5
        
        memory_metric = self.current_metrics.get("memory_usage_percent")
        if memory_metric and memory_metric.value > 80:
            score -= (memory_metric.value - 80) * 0.5
        
        return max(0.0, min(100.0, score))

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str):
        """Acknowledge an alert"""
        for alert in self.alerts.values():
            if alert.alert_id == alert_id:
                alert.acknowledged_at = datetime.now()
                alert.acknowledged_by = acknowledged_by
                logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                break

    def get_metrics_for_export(self) -> Dict[str, Any]:
        """Get metrics in exportable format"""
        metrics_export = {}
        
        for metric_name, metric in self.current_metrics.items():
            metrics_export[metric_name] = {
                "value": metric.value,
                "unit": metric.unit,
                "type": metric.metric_type.value,
                "timestamp": metric.timestamp.isoformat(),
                "labels": metric.labels or {},
                "node_id": self.node_id,
                "hostname": self.hostname,
                "ip_address": self.ip_address
            }
        
        return metrics_export


class ClusterMonitor:
    """Cluster-wide monitoring coordinator"""
    
    def __init__(self, cluster_id: str):
        self.cluster_id = cluster_id
        self.node_monitors: Dict[str, NodeMonitor] = {}
        self.cluster_health: Dict[str, NodeHealth] = {}
        self.running = False
        
        # Cluster-level thresholds
        self.min_healthy_nodes_percent = 80.0
        self.alert_handlers: List[Callable] = []

    def add_node(self, node_monitor: NodeMonitor):
        """Add node to cluster monitoring"""
        self.node_monitors[node_monitor.node_id] = node_monitor
        logger.info(f"Added node {node_monitor.node_id} to cluster monitoring")

    def remove_node(self, node_id: str):
        """Remove node from cluster monitoring"""
        if node_id in self.node_monitors:
            del self.node_monitors[node_id]
            
        if node_id in self.cluster_health:
            del self.cluster_health[node_id]
            
        logger.info(f"Removed node {node_id} from cluster monitoring")

    async def start_cluster_monitoring(self):
        """Start cluster monitoring"""
        self.running = True
        logger.info(f"Starting cluster monitoring for {self.cluster_id}")
        
        # Start individual node monitoring
        node_tasks = []
        for node_monitor in self.node_monitors.values():
            task = asyncio.create_task(node_monitor.start_monitoring())
            node_tasks.append(task)
        
        # Start cluster health collection
        cluster_task = asyncio.create_task(self._collect_cluster_health())
        
        try:
            await asyncio.gather(*node_tasks, cluster_task)
        except Exception as e:
            logger.error(f"Error in cluster monitoring: {e}")
        finally:
            self.running = False

    async def stop_cluster_monitoring(self):
        """Stop cluster monitoring"""
        self.running = False
        
        # Stop all node monitors
        for node_monitor in self.node_monitors.values():
            await node_monitor.stop_monitoring()
        
        logger.info(f"Stopped cluster monitoring for {self.cluster_id}")

    async def _collect_cluster_health(self):
        """Collect health information from all nodes"""
        while self.running:
            try:
                # Collect health from all nodes
                for node_id, node_monitor in self.node_monitors.items():
                    node_health = node_monitor.get_health_summary()
                    self.cluster_health[node_id] = node_health
                
                # Evaluate cluster health
                await self._evaluate_cluster_health()
                
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                logger.error(f"Error collecting cluster health: {e}")
                await asyncio.sleep(30)

    async def _evaluate_cluster_health(self):
        """Evaluate overall cluster health"""
        if not self.cluster_health:
            return
        
        total_nodes = len(self.cluster_health)
        healthy_nodes = len([
            health for health in self.cluster_health.values()
            if health.overall_status in [HealthStatus.HEALTHY, HealthStatus.WARNING]
        ])
        
        healthy_percent = (healthy_nodes / total_nodes) * 100
        
        # Check cluster health threshold
        if healthy_percent < self.min_healthy_nodes_percent:
            await self._trigger_cluster_alert(
                AlertSeverity.CRITICAL,
                f"Cluster health degraded: only {healthy_percent:.1f}% of nodes are healthy"
            )

    async def _trigger_cluster_alert(self, severity: AlertSeverity, message: str):
        """Trigger cluster-level alert"""
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            node_id=self.cluster_id,
            metric_name="cluster_health",
            severity=severity,
            message=message,
            current_value=0.0,
            threshold=self.min_healthy_nodes_percent,
            triggered_at=datetime.now()
        )
        
        # Notify alert handlers
        for handler in self.alert_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")

    def add_alert_handler(self, handler: Callable):
        """Add cluster alert handler"""
        self.alert_handlers.append(handler)

    def get_cluster_summary(self) -> Dict[str, Any]:
        """Get cluster health summary"""
        if not self.cluster_health:
            return {"error": "No health data available"}
        
        total_nodes = len(self.cluster_health)
        status_counts = {}
        
        # Count nodes by status
        for health in self.cluster_health.values():
            status = health.overall_status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Calculate aggregate metrics
        avg_health_score = statistics.mean([
            health.health_score for health in self.cluster_health.values()
        ])
        
        avg_availability = statistics.mean([
            health.availability for health in self.cluster_health.values()
        ])
        
        # Count total alerts
        total_alerts = sum([
            len(health.active_alerts) for health in self.cluster_health.values()
        ])
        
        return {
            "cluster_id": self.cluster_id,
            "total_nodes": total_nodes,
            "status_counts": status_counts,
            "average_health_score": avg_health_score,
            "average_availability": avg_availability,
            "total_active_alerts": total_alerts,
            "healthy_percent": (status_counts.get("healthy", 0) / total_nodes) * 100,
            "timestamp": datetime.now().isoformat()
        }

    def get_node_health(self, node_id: str) -> Optional[NodeHealth]:
        """Get health information for specific node"""
        return self.cluster_health.get(node_id)

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics from all nodes"""
        all_metrics = {}
        
        for node_id, node_monitor in self.node_monitors.items():
            all_metrics[node_id] = node_monitor.get_metrics_for_export()
        
        return all_metrics


if __name__ == "__main__":
    async def main():
        # Example usage
        cluster_monitor = ClusterMonitor("test_cluster")
        
        # Create node monitors
        node1_monitor = NodeMonitor("node_1")
        node2_monitor = NodeMonitor("node_2")
        
        cluster_monitor.add_node(node1_monitor)
        cluster_monitor.add_node(node2_monitor)
        
        # Add alert handler
        async def alert_handler(alert: Alert):
            print(f"CLUSTER ALERT: {alert.message}")
        
        cluster_monitor.add_alert_handler(alert_handler)
        
        try:
            # Start monitoring
            await cluster_monitor.start_cluster_monitoring()
        except KeyboardInterrupt:
            await cluster_monitor.stop_cluster_monitoring()
    
    asyncio.run(main())