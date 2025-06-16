"""
MCP Performance Monitoring System
Agent 7: Real-time performance monitoring and analytics for MCP operations.

This module provides comprehensive monitoring, alerting, and analytics for MCP
server performance, including real-time metrics, trend analysis, and optimization insights.
"""

import asyncio
import time
import logging
import statistics
from typing import Dict, Any, List, Optional, Union, Callable, TypeVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import threading
import json
import os
from contextlib import asynccontextmanager

from ..monitoring.metrics import get_metrics_collector, MetricsCollector
from ..core.circuit_breaker import get_circuit_breaker_manager
from .performance import PerformanceMetrics, PerformanceConfig

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Alert:
    """Performance alert."""
    id: str
    level: AlertLevel
    title: str
    description: str
    metric_name: str
    threshold_value: float
    current_value: float
    created_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    
    def is_resolved(self) -> bool:
        """Check if alert is resolved."""
        return self.resolved_at is not None


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration."""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    comparison: str = "gt"  # gt, lt, eq
    window_seconds: float = 60.0
    min_samples: int = 5


@dataclass
class MCPOperationMetrics:
    """Metrics for a specific MCP operation."""
    server_name: str
    tool_name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_duration_ms: float = 0.0
    min_duration_ms: float = float('inf')
    max_duration_ms: float = 0.0
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    error_types: Dict[str, int] = field(default_factory=dict)
    last_call: Optional[datetime] = None
    first_call: Optional[datetime] = None
    
    def add_call(self, duration_ms: float, success: bool, error_type: Optional[str] = None):
        """Add a call measurement."""
        now = datetime.now()
        
        self.total_calls += 1
        self.total_duration_ms += duration_ms
        self.response_times.append(duration_ms)
        self.last_call = now
        
        if self.first_call is None:
            self.first_call = now
        
        if success:
            self.successful_calls += 1
        else:
            self.failed_calls += 1
            if error_type:
                self.error_types[error_type] = self.error_types.get(error_type, 0) + 1
        
        # Update min/max
        self.min_duration_ms = min(self.min_duration_ms, duration_ms)
        self.max_duration_ms = max(self.max_duration_ms, duration_ms)
    
    def get_avg_duration_ms(self) -> float:
        """Get average duration."""
        if self.total_calls == 0:
            return 0.0
        return self.total_duration_ms / self.total_calls
    
    def get_success_rate(self) -> float:
        """Get success rate."""
        if self.total_calls == 0:
            return 1.0
        return self.successful_calls / self.total_calls
    
    def get_percentiles(self) -> Dict[str, float]:
        """Get response time percentiles."""
        if not self.response_times:
            return {"p50": 0, "p95": 0, "p99": 0}
        
        sorted_times = sorted(self.response_times)
        n = len(sorted_times)
        
        return {
            "p50": sorted_times[int(n * 0.5)] if n > 0 else 0,
            "p95": sorted_times[int(n * 0.95)] if n > 0 else 0,
            "p99": sorted_times[int(n * 0.99)] if n > 0 else 0
        }
    
    def get_calls_per_minute(self) -> float:
        """Get calls per minute rate."""
        if not self.first_call or not self.last_call:
            return 0.0
        
        duration_minutes = (self.last_call - self.first_call).total_seconds() / 60.0
        if duration_minutes <= 0:
            return 0.0
        
        return self.total_calls / duration_minutes


@dataclass
class SystemResourceMetrics:
    """System resource metrics."""
    timestamp: datetime = field(default_factory=datetime.now)
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0
    disk_io_read_mb: float = 0.0
    disk_io_write_mb: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    open_files: int = 0
    active_connections: int = 0


class MCPPerformanceMonitor:
    """
    Comprehensive performance monitoring system for MCP operations.
    
    Features:
    - Real-time metrics collection
    - Performance trend analysis
    - Alerting and notifications
    - Resource monitoring
    - Performance insights and recommendations
    """
    
    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or PerformanceConfig()
        
        # Metrics storage
        self._operation_metrics: Dict[str, MCPOperationMetrics] = {}
        self._system_metrics: deque = deque(maxlen=1440)  # 24 hours at 1-minute intervals
        self._alerts: Dict[str, Alert] = {}
        
        # Monitoring configuration
        self._thresholds: List[PerformanceThreshold] = []
        self._alert_handlers: List[Callable[[Alert], None]] = []
        
        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._alert_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        # Metrics integration
        self._metrics_collector: Optional[MetricsCollector] = None
        self._circuit_breaker_manager = None
        
        # Thread safety
        self._metrics_lock = threading.RLock()
        self._alerts_lock = threading.RLock()
        
        # Performance analysis
        self._trend_analyzer = TrendAnalyzer()
        self._anomaly_detector = AnomalyDetector()
        
        # Default thresholds
        self._setup_default_thresholds()
    
    async def initialize(self):
        """Initialize the performance monitor."""
        if self._is_running:
            return
        
        logger.info("Initializing MCP Performance Monitor")
        
        # Initialize metrics collector
        self._metrics_collector = get_metrics_collector()
        self._circuit_breaker_manager = get_circuit_breaker_manager()
        
        # Start background tasks
        self._is_running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        self._alert_task = asyncio.create_task(self._alerting_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("MCP Performance Monitor initialized")
    
    def record_mcp_call(
        self,
        server_name: str,
        tool_name: str,
        duration_ms: float,
        success: bool,
        error_type: Optional[str] = None
    ):
        """Record an MCP tool call for monitoring."""
        operation_key = f"{server_name}.{tool_name}"
        
        with self._metrics_lock:
            if operation_key not in self._operation_metrics:
                self._operation_metrics[operation_key] = MCPOperationMetrics(
                    server_name=server_name,
                    tool_name=tool_name
                )
            
            metrics = self._operation_metrics[operation_key]
            metrics.add_call(duration_ms, success, error_type)
        
        # Record in Prometheus metrics
        if self._metrics_collector:
            status = "success" if success else "error"
            self._metrics_collector.record_mcp_tool_call(
                server_name, tool_name, status, duration_ms / 1000.0
            )
    
    def add_threshold(self, threshold: PerformanceThreshold):
        """Add a performance threshold for alerting."""
        self._thresholds.append(threshold)
        logger.info(f"Added threshold for {threshold.metric_name}")
    
    def add_alert_handler(self, handler: Callable[[Alert], None]):
        """Add an alert handler."""
        self._alert_handlers.append(handler)
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self._is_running:
            try:
                await asyncio.sleep(10)  # Monitor every 10 seconds
                await self._collect_system_metrics()
                await self._analyze_performance_trends()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system resource metrics."""
        try:
            import psutil
            
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            
            # Network
            network_io = psutil.net_io_counters()
            
            # Process info
            process = psutil.Process()
            open_files = len(process.open_files())
            
            # Active connections (from connection manager)
            active_connections = 0
            if self._circuit_breaker_manager:
                summary = self._circuit_breaker_manager.get_summary()
                # This is a simplified way to get connection count
                active_connections = summary.get("total_calls", 0)
            
            # Create metrics record
            system_metrics = SystemResourceMetrics(
                cpu_percent=cpu_percent,
                memory_mb=memory.used / 1024 / 1024,
                memory_percent=memory.percent,
                disk_io_read_mb=disk_io.read_bytes / 1024 / 1024 if disk_io else 0,
                disk_io_write_mb=disk_io.write_bytes / 1024 / 1024 if disk_io else 0,
                network_bytes_sent=network_io.bytes_sent if network_io else 0,
                network_bytes_recv=network_io.bytes_recv if network_io else 0,
                open_files=open_files,
                active_connections=active_connections
            )
            
            self._system_metrics.append(system_metrics)
            
        except Exception as e:
            logger.error(f"System metrics collection error: {e}")
    
    async def _analyze_performance_trends(self):
        """Analyze performance trends and detect anomalies."""
        with self._metrics_lock:
            for operation_key, metrics in self._operation_metrics.items():
                try:
                    # Trend analysis
                    self._trend_analyzer.analyze(operation_key, metrics)
                    
                    # Anomaly detection
                    anomalies = self._anomaly_detector.detect(operation_key, metrics)
                    
                    # Generate alerts for anomalies
                    for anomaly in anomalies:
                        await self._create_alert(
                            level=AlertLevel.WARNING,
                            title=f"Performance Anomaly Detected",
                            description=f"Anomaly in {operation_key}: {anomaly}",
                            metric_name=operation_key,
                            threshold_value=0,
                            current_value=metrics.get_avg_duration_ms()
                        )
                
                except Exception as e:
                    logger.error(f"Trend analysis error for {operation_key}: {e}")
    
    async def _alerting_loop(self):
        """Alerting loop to check thresholds."""
        while self._is_running:
            try:
                await asyncio.sleep(30)  # Check alerts every 30 seconds
                await self._check_thresholds()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Alerting loop error: {e}")
    
    async def _check_thresholds(self):
        """Check performance thresholds and generate alerts."""
        for threshold in self._thresholds:
            try:
                current_value = await self._get_metric_value(threshold.metric_name)
                
                if current_value is None:
                    continue
                
                # Check threshold breach
                should_alert = False
                level = AlertLevel.INFO
                
                if threshold.comparison == "gt":
                    if current_value > threshold.critical_threshold:
                        should_alert = True
                        level = AlertLevel.CRITICAL
                    elif current_value > threshold.warning_threshold:
                        should_alert = True
                        level = AlertLevel.WARNING
                elif threshold.comparison == "lt":
                    if current_value < threshold.critical_threshold:
                        should_alert = True
                        level = AlertLevel.CRITICAL
                    elif current_value < threshold.warning_threshold:
                        should_alert = True
                        level = AlertLevel.WARNING
                
                if should_alert:
                    alert_id = f"{threshold.metric_name}_{level.value}"
                    
                    # Check if alert already exists
                    if alert_id not in self._alerts or self._alerts[alert_id].is_resolved():
                        await self._create_alert(
                            level=level,
                            title=f"Threshold Breach: {threshold.metric_name}",
                            description=f"Metric {threshold.metric_name} exceeded threshold",
                            metric_name=threshold.metric_name,
                            threshold_value=threshold.warning_threshold if level == AlertLevel.WARNING else threshold.critical_threshold,
                            current_value=current_value
                        )
                
            except Exception as e:
                logger.error(f"Threshold check error for {threshold.metric_name}: {e}")
    
    async def _get_metric_value(self, metric_name: str) -> Optional[float]:
        """Get current value for a metric."""
        # System metrics
        if metric_name == "cpu_percent" and self._system_metrics:
            return self._system_metrics[-1].cpu_percent
        elif metric_name == "memory_percent" and self._system_metrics:
            return self._system_metrics[-1].memory_percent
        elif metric_name == "memory_mb" and self._system_metrics:
            return self._system_metrics[-1].memory_mb
        
        # Operation metrics
        with self._metrics_lock:
            if metric_name in self._operation_metrics:
                metrics = self._operation_metrics[metric_name]
                if metric_name.endswith("_avg_duration"):
                    return metrics.get_avg_duration_ms()
                elif metric_name.endswith("_success_rate"):
                    return metrics.get_success_rate()
                elif metric_name.endswith("_calls_per_minute"):
                    return metrics.get_calls_per_minute()
        
        return None
    
    async def _create_alert(
        self,
        level: AlertLevel,
        title: str,
        description: str,
        metric_name: str,
        threshold_value: float,
        current_value: float
    ):
        """Create and handle an alert."""
        alert_id = f"{metric_name}_{level.value}_{int(time.time())}"
        
        alert = Alert(
            id=alert_id,
            level=level,
            title=title,
            description=description,
            metric_name=metric_name,
            threshold_value=threshold_value,
            current_value=current_value
        )
        
        with self._alerts_lock:
            self._alerts[alert_id] = alert
        
        # Notify alert handlers
        for handler in self._alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {e}")
        
        logger.warning(f"Alert created: {alert.title} - {alert.description}")
    
    async def _cleanup_loop(self):
        """Cleanup old data."""
        while self._is_running:
            try:
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old metrics and alerts."""
        current_time = datetime.now()
        
        # Clean up old alerts (older than 24 hours)
        with self._alerts_lock:
            old_alert_ids = [
                alert_id for alert_id, alert in self._alerts.items()
                if (current_time - alert.created_at).total_seconds() > 86400
            ]
            
            for alert_id in old_alert_ids:
                del self._alerts[alert_id]
        
        # Clean up operation metrics response times (keep only recent)
        with self._metrics_lock:
            for metrics in self._operation_metrics.values():
                # Response times are already limited by deque maxlen
                pass
    
    def _setup_default_thresholds(self):
        """Setup default performance thresholds."""
        default_thresholds = [
            PerformanceThreshold(
                metric_name="cpu_percent",
                warning_threshold=70.0,
                critical_threshold=90.0,
                comparison="gt"
            ),
            PerformanceThreshold(
                metric_name="memory_percent",
                warning_threshold=80.0,
                critical_threshold=95.0,
                comparison="gt"
            ),
            PerformanceThreshold(
                metric_name="memory_mb",
                warning_threshold=1000.0,
                critical_threshold=2000.0,
                comparison="gt"
            )
        ]
        
        self._thresholds.extend(default_thresholds)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        with self._metrics_lock:
            operation_summaries = {}
            
            for operation_key, metrics in self._operation_metrics.items():
                percentiles = metrics.get_percentiles()
                operation_summaries[operation_key] = {
                    "total_calls": metrics.total_calls,
                    "success_rate": metrics.get_success_rate(),
                    "avg_duration_ms": metrics.get_avg_duration_ms(),
                    "min_duration_ms": metrics.min_duration_ms if metrics.min_duration_ms != float('inf') else 0,
                    "max_duration_ms": metrics.max_duration_ms,
                    "percentiles": percentiles,
                    "calls_per_minute": metrics.get_calls_per_minute(),
                    "error_types": dict(metrics.error_types),
                    "last_call": metrics.last_call.isoformat() if metrics.last_call else None
                }
        
        # System metrics summary
        system_summary = {}
        if self._system_metrics:
            recent_metrics = list(self._system_metrics)[-10:]  # Last 10 measurements
            system_summary = {
                "avg_cpu_percent": statistics.mean(m.cpu_percent for m in recent_metrics),
                "avg_memory_mb": statistics.mean(m.memory_mb for m in recent_metrics),
                "avg_memory_percent": statistics.mean(m.memory_percent for m in recent_metrics),
                "active_connections": recent_metrics[-1].active_connections,
                "open_files": recent_metrics[-1].open_files
            }
        
        # Active alerts
        with self._alerts_lock:
            active_alerts = [
                {
                    "id": alert.id,
                    "level": alert.level.value,
                    "title": alert.title,
                    "description": alert.description,
                    "metric_name": alert.metric_name,
                    "current_value": alert.current_value,
                    "threshold_value": alert.threshold_value,
                    "created_at": alert.created_at.isoformat()
                }
                for alert in self._alerts.values()
                if not alert.is_resolved()
            ]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "operations": operation_summaries,
            "system": system_summary,
            "alerts": active_alerts,
            "trends": self._trend_analyzer.get_summary(),
            "anomalies": self._anomaly_detector.get_summary()
        }
    
    def get_operation_details(self, operation_key: str) -> Optional[Dict[str, Any]]:
        """Get detailed metrics for a specific operation."""
        with self._metrics_lock:
            if operation_key not in self._operation_metrics:
                return None
            
            metrics = self._operation_metrics[operation_key]
            return {
                "server_name": metrics.server_name,
                "tool_name": metrics.tool_name,
                "total_calls": metrics.total_calls,
                "successful_calls": metrics.successful_calls,
                "failed_calls": metrics.failed_calls,
                "success_rate": metrics.get_success_rate(),
                "avg_duration_ms": metrics.get_avg_duration_ms(),
                "min_duration_ms": metrics.min_duration_ms if metrics.min_duration_ms != float('inf') else 0,
                "max_duration_ms": metrics.max_duration_ms,
                "percentiles": metrics.get_percentiles(),
                "calls_per_minute": metrics.get_calls_per_minute(),
                "error_types": dict(metrics.error_types),
                "response_times": list(metrics.response_times),
                "first_call": metrics.first_call.isoformat() if metrics.first_call else None,
                "last_call": metrics.last_call.isoformat() if metrics.last_call else None
            }
    
    def export_metrics(self, filepath: str):
        """Export all metrics to a file."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "performance_summary": self.get_performance_summary(),
            "thresholds": [
                {
                    "metric_name": t.metric_name,
                    "warning_threshold": t.warning_threshold,
                    "critical_threshold": t.critical_threshold,
                    "comparison": t.comparison
                }
                for t in self._thresholds
            ]
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Metrics exported to {filepath}")
    
    async def shutdown(self):
        """Shutdown the performance monitor."""
        logger.info("Shutting down MCP Performance Monitor")
        
        self._is_running = False
        
        # Cancel background tasks
        for task in [self._monitor_task, self._alert_task, self._cleanup_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("MCP Performance Monitor shutdown complete")


class TrendAnalyzer:
    """Analyzes performance trends over time."""
    
    def __init__(self):
        self._trends: Dict[str, List[float]] = defaultdict(list)
        self._analysis_results: Dict[str, Dict[str, Any]] = {}
    
    def analyze(self, operation_key: str, metrics: MCPOperationMetrics):
        """Analyze trends for an operation."""
        current_avg = metrics.get_avg_duration_ms()
        self._trends[operation_key].append(current_avg)
        
        # Keep only recent data (last 100 measurements)
        if len(self._trends[operation_key]) > 100:
            self._trends[operation_key] = self._trends[operation_key][-100:]
        
        # Perform trend analysis if we have enough data
        if len(self._trends[operation_key]) >= 10:
            trend_data = self._trends[operation_key]
            
            # Simple linear trend analysis
            x = list(range(len(trend_data)))
            n = len(x)
            
            sum_x = sum(x)
            sum_y = sum(trend_data)
            sum_xy = sum(x[i] * trend_data[i] for i in range(n))
            sum_x2 = sum(x[i] ** 2 for i in range(n))
            
            # Calculate slope (trend direction)
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
            
            # Determine trend
            if abs(slope) < 0.1:
                trend = "stable"
            elif slope > 0:
                trend = "increasing"
            else:
                trend = "decreasing"
            
            self._analysis_results[operation_key] = {
                "trend": trend,
                "slope": slope,
                "recent_avg": current_avg,
                "baseline_avg": statistics.mean(trend_data[:10]) if len(trend_data) >= 10 else current_avg
            }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get trend analysis summary."""
        return dict(self._analysis_results)


class AnomalyDetector:
    """Detects performance anomalies."""
    
    def __init__(self):
        self._baselines: Dict[str, Dict[str, float]] = {}
        self._anomalies: Dict[str, List[str]] = defaultdict(list)
    
    def detect(self, operation_key: str, metrics: MCPOperationMetrics) -> List[str]:
        """Detect anomalies in operation metrics."""
        anomalies = []
        
        # Establish baseline if we have enough data
        if len(metrics.response_times) >= 20:
            recent_times = list(metrics.response_times)[-20:]
            baseline_avg = statistics.mean(recent_times)
            baseline_std = statistics.stdev(recent_times) if len(recent_times) > 1 else 0
            
            self._baselines[operation_key] = {
                "avg": baseline_avg,
                "std": baseline_std
            }
            
            # Detect outliers (values > 3 standard deviations from mean)
            current_avg = metrics.get_avg_duration_ms()
            
            if baseline_std > 0:
                z_score = abs(current_avg - baseline_avg) / baseline_std
                if z_score > 3:
                    anomalies.append(f"Response time anomaly (z-score: {z_score:.2f})")
        
        # Detect sudden success rate drops
        success_rate = metrics.get_success_rate()
        if success_rate < 0.9 and metrics.total_calls >= 10:
            anomalies.append(f"Low success rate: {success_rate:.2%}")
        
        # Store anomalies
        if anomalies:
            self._anomalies[operation_key].extend(anomalies)
            # Keep only recent anomalies
            self._anomalies[operation_key] = self._anomalies[operation_key][-10:]
        
        return anomalies
    
    def get_summary(self) -> Dict[str, List[str]]:
        """Get anomaly detection summary."""
        return dict(self._anomalies)


# Default alert handler
def default_alert_handler(alert: Alert):
    """Default alert handler that logs alerts."""
    log_level = {
        AlertLevel.INFO: logging.info,
        AlertLevel.WARNING: logging.warning,
        AlertLevel.ERROR: logging.error,
        AlertLevel.CRITICAL: logging.critical
    }.get(alert.level, logging.info)
    
    log_level(
        f"MCP Performance Alert [{alert.level.value.upper()}]: {alert.title} - "
        f"{alert.description} (Current: {alert.current_value:.2f}, "
        f"Threshold: {alert.threshold_value:.2f})"
    )


# Global performance monitor instance
_performance_monitor: Optional[MCPPerformanceMonitor] = None


async def get_performance_monitor(
    config: Optional[PerformanceConfig] = None
) -> MCPPerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = MCPPerformanceMonitor(config)
        _performance_monitor.add_alert_handler(default_alert_handler)
        await _performance_monitor.initialize()
    return _performance_monitor


__all__ = [
    "AlertLevel",
    "MetricType",
    "Alert",
    "PerformanceThreshold",
    "MCPOperationMetrics",
    "SystemResourceMetrics",
    "MCPPerformanceMonitor",
    "TrendAnalyzer",
    "AnomalyDetector",
    "get_performance_monitor",
    "default_alert_handler"
]