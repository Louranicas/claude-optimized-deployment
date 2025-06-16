"""Database connection pool monitoring and alerting.

This module provides comprehensive monitoring for database connections including:
- Connection pool metrics collection
- Health check automation
- Performance monitoring
- Alert generation for critical issues
- Connection leak detection
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging

from src.core.logging_config import get_logger
from src.monitoring.metrics import MetricsCollector
from src.database.pool_manager import DatabasePoolManager, get_pool_manager
from src.core.exceptions import DatabaseError

logger = get_logger(__name__)

__all__ = [
    "DatabaseMonitorConfig",
    "DatabaseAlert",
    "DatabaseMonitor",
    "get_database_monitor"
]


@dataclass
class DatabaseMonitorConfig:
    """Configuration for database monitoring."""
    # Monitoring intervals
    health_check_interval: int = 60    # seconds
    metrics_collection_interval: int = 30  # seconds
    leak_detection_interval: int = 300  # seconds (5 minutes)
    
    # Alert thresholds
    max_checkout_time_threshold: float = 5.0  # seconds
    max_query_time_threshold: float = 10.0   # seconds
    connection_failure_rate_threshold: float = 0.1  # 10%
    query_failure_rate_threshold: float = 0.05      # 5%
    
    # Connection pool thresholds
    high_pool_usage_threshold: float = 0.8   # 80% of max pool size
    connection_leak_threshold: int = 5       # number of leaked connections
    
    # Health check settings
    consecutive_failures_for_alert: int = 3
    alert_cooldown_minutes: int = 15
    
    # Performance monitoring
    slow_query_threshold: float = 5.0  # seconds
    collect_slow_queries: bool = True
    max_slow_queries_tracked: int = 100


@dataclass
class DatabaseAlert:
    """Database alert data."""
    alert_type: str
    severity: str  # "warning", "error", "critical"
    message: str
    timestamp: datetime
    metrics: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class DatabaseMonitor:
    """Database monitoring service."""
    
    def __init__(self, config: DatabaseMonitorConfig = None):
        self.config = config or DatabaseMonitorConfig()
        self.pool_manager: Optional[DatabasePoolManager] = None
        self.metrics_collector = MetricsCollector()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_tasks: List[asyncio.Task] = []
        
        # Alert management
        self.active_alerts: Dict[str, DatabaseAlert] = {}
        self.alert_history: List[DatabaseAlert] = []
        self.last_alert_times: Dict[str, datetime] = {}
        
        # Performance tracking
        self.slow_queries: List[Dict[str, Any]] = []
        self.connection_leak_count = 0
        self.last_health_check: Optional[datetime] = None
        self.consecutive_health_failures = 0
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable[[DatabaseAlert], None]] = []
    
    async def start_monitoring(self, pool_manager: Optional[DatabasePoolManager] = None):
        """Start database monitoring."""
        if self.is_monitoring:
            logger.warning("Database monitoring is already running")
            return
        
        self.pool_manager = pool_manager or await get_pool_manager()
        self.is_monitoring = True
        
        # Start monitoring tasks
        self.monitor_tasks = [
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._leak_detection_loop()),
            asyncio.create_task(self._performance_monitoring_loop())
        ]
        
        logger.info("Database monitoring started")
    
    async def stop_monitoring(self):
        """Stop database monitoring."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        
        # Cancel monitoring tasks
        for task in self.monitor_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.monitor_tasks, return_exceptions=True)
        self.monitor_tasks.clear()
        
        logger.info("Database monitoring stopped")
    
    def add_alert_callback(self, callback: Callable[[DatabaseAlert], None]):
        """Add a callback for alert notifications."""
        self.alert_callbacks.append(callback)
    
    async def _health_check_loop(self):
        """Health check monitoring loop."""
        while self.is_monitoring:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _metrics_collection_loop(self):
        """Metrics collection loop."""
        while self.is_monitoring:
            try:
                await asyncio.sleep(self.config.metrics_collection_interval)
                await self._collect_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
    
    async def _leak_detection_loop(self):
        """Connection leak detection loop."""
        while self.is_monitoring:
            try:
                await asyncio.sleep(self.config.leak_detection_interval)
                await self._detect_connection_leaks()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Leak detection error: {e}")
    
    async def _performance_monitoring_loop(self):
        """Performance monitoring loop."""
        while self.is_monitoring:
            try:
                await asyncio.sleep(self.config.metrics_collection_interval * 2)
                await self._monitor_performance()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
    
    async def _perform_health_check(self):
        """Perform database health check."""
        try:
            health_status = await self.pool_manager.health_check()
            self.last_health_check = datetime.utcnow()
            
            if health_status["status"] == "healthy":
                self.consecutive_health_failures = 0
                await self._resolve_alert("database_unhealthy")
            else:
                self.consecutive_health_failures += 1
                
                if self.consecutive_health_failures >= self.config.consecutive_failures_for_alert:
                    await self._trigger_alert(
                        alert_type="database_unhealthy",
                        severity="critical",
                        message=f"Database health check failed {self.consecutive_health_failures} times",
                        metrics=health_status
                    )
            
            # Check for connection leaks in health status
            if "connection_leaks" in health_status and health_status["connection_leaks"]:
                await self._trigger_alert(
                    alert_type="connection_leaks",
                    severity="warning",
                    message=f"Detected {len(health_status['connection_leaks'])} potential connection leaks",
                    metrics={"leaks": health_status["connection_leaks"]}
                )
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.consecutive_health_failures += 1
    
    async def _collect_metrics(self):
        """Collect database metrics."""
        try:
            metrics = self.pool_manager.metrics
            
            # Connection metrics
            self.metrics_collector.gauge("db_active_connections", metrics.active_connections)
            self.metrics_collector.gauge("db_idle_connections", metrics.idle_connections)
            self.metrics_collector.gauge("db_overflow_connections", metrics.overflow_connections)
            self.metrics_collector.gauge("db_total_connections_created", metrics.total_connections_created)
            
            # Checkout metrics
            self.metrics_collector.gauge("db_total_checkouts", metrics.total_checkouts)
            self.metrics_collector.gauge("db_successful_checkouts", metrics.successful_checkouts)
            self.metrics_collector.gauge("db_failed_checkouts", metrics.failed_checkouts)
            self.metrics_collector.gauge("db_average_checkout_time", metrics.get_average_checkout_time())
            self.metrics_collector.gauge("db_checkout_failure_rate", metrics.get_checkout_failure_rate())
            
            # Query metrics
            self.metrics_collector.gauge("db_total_queries", metrics.total_queries)
            self.metrics_collector.gauge("db_successful_queries", metrics.successful_queries)
            self.metrics_collector.gauge("db_failed_queries", metrics.failed_queries)
            self.metrics_collector.gauge("db_average_query_time", metrics.get_average_query_time())
            self.metrics_collector.gauge("db_query_failure_rate", metrics.get_query_failure_rate())
            
            # Health metrics
            self.metrics_collector.gauge("db_health_check_passes", metrics.health_check_passes)
            self.metrics_collector.gauge("db_health_check_failures", metrics.health_check_failures)
            
            # Connection lifecycle
            self.metrics_collector.gauge("db_connections_recycled", metrics.connections_recycled)
            self.metrics_collector.gauge("db_connections_invalidated", metrics.connections_invalidated)
            self.metrics_collector.gauge("db_connection_timeouts", metrics.connection_timeouts)
            
            # Check thresholds
            await self._check_metrics_thresholds(metrics)
            
        except Exception as e:
            logger.error(f"Metrics collection failed: {e}")
    
    async def _detect_connection_leaks(self):
        """Detect potential connection leaks."""
        try:
            health_status = await self.pool_manager.health_check()
            
            # Check for long-running sessions
            if "connection_leaks" in health_status:
                leak_count = len(health_status["connection_leaks"])
                
                if leak_count > self.config.connection_leak_threshold:
                    await self._trigger_alert(
                        alert_type="connection_leaks",
                        severity="error",
                        message=f"Detected {leak_count} connection leaks",
                        metrics={"leak_count": leak_count, "leaks": health_status["connection_leaks"]}
                    )
                
                self.connection_leak_count = leak_count
            
        except Exception as e:
            logger.error(f"Connection leak detection failed: {e}")
    
    async def _monitor_performance(self):
        """Monitor database performance."""
        try:
            metrics = self.pool_manager.metrics
            
            # Check for slow queries
            avg_query_time = metrics.get_average_query_time()
            if avg_query_time > self.config.slow_query_threshold:
                await self._trigger_alert(
                    alert_type="slow_queries",
                    severity="warning",
                    message=f"Average query time is {avg_query_time:.2f}s (threshold: {self.config.slow_query_threshold}s)",
                    metrics={"average_query_time": avg_query_time}
                )
            
            # Check checkout times
            avg_checkout_time = metrics.get_average_checkout_time()
            if avg_checkout_time > self.config.max_checkout_time_threshold:
                await self._trigger_alert(
                    alert_type="slow_checkouts",
                    severity="warning",
                    message=f"Average checkout time is {avg_checkout_time:.2f}s (threshold: {self.config.max_checkout_time_threshold}s)",
                    metrics={"average_checkout_time": avg_checkout_time}
                )
            
        except Exception as e:
            logger.error(f"Performance monitoring failed: {e}")
    
    async def _check_metrics_thresholds(self, metrics):
        """Check metrics against thresholds and trigger alerts."""
        # Check failure rates
        checkout_failure_rate = metrics.get_checkout_failure_rate()
        if checkout_failure_rate > self.config.connection_failure_rate_threshold:
            await self._trigger_alert(
                alert_type="high_checkout_failure_rate",
                severity="error",
                message=f"High checkout failure rate: {checkout_failure_rate:.2%}",
                metrics={"failure_rate": checkout_failure_rate}
            )
        
        query_failure_rate = metrics.get_query_failure_rate()
        if query_failure_rate > self.config.query_failure_rate_threshold:
            await self._trigger_alert(
                alert_type="high_query_failure_rate",
                severity="error",
                message=f"High query failure rate: {query_failure_rate:.2%}",
                metrics={"failure_rate": query_failure_rate}
            )
        
        # Check pool usage (if we can get max pool size)
        total_connections = metrics.active_connections + metrics.idle_connections
        if hasattr(self.pool_manager, 'config') and total_connections > 0:
            max_pool_size = self.pool_manager.config.max_pool_size
            usage_ratio = total_connections / max_pool_size
            
            if usage_ratio > self.config.high_pool_usage_threshold:
                await self._trigger_alert(
                    alert_type="high_pool_usage",
                    severity="warning",
                    message=f"High pool usage: {usage_ratio:.1%} ({total_connections}/{max_pool_size})",
                    metrics={"usage_ratio": usage_ratio, "total_connections": total_connections}
                )
    
    async def _trigger_alert(self, alert_type: str, severity: str, message: str, metrics: Dict[str, Any] = None):
        """Trigger an alert with cooldown logic."""
        now = datetime.utcnow()
        
        # Check cooldown
        if alert_type in self.last_alert_times:
            time_since_last = now - self.last_alert_times[alert_type]
            if time_since_last < timedelta(minutes=self.config.alert_cooldown_minutes):
                return  # Still in cooldown
        
        # Create alert
        alert = DatabaseAlert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=now,
            metrics=metrics or {}
        )
        
        # Store alert
        self.active_alerts[alert_type] = alert
        self.alert_history.append(alert)
        self.last_alert_times[alert_type] = now
        
        # Limit history size
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-800:]  # Keep last 800
        
        logger.warning(f"Database alert [{severity.upper()}]: {message}")
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    async def _resolve_alert(self, alert_type: str):
        """Resolve an active alert."""
        if alert_type in self.active_alerts:
            alert = self.active_alerts[alert_type]
            alert.resolved = True
            alert.resolved_at = datetime.utcnow()
            
            logger.info(f"Database alert resolved: {alert_type}")
            del self.active_alerts[alert_type]
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status."""
        return {
            "monitoring_active": self.is_monitoring,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "consecutive_health_failures": self.consecutive_health_failures,
            "active_alerts": len(self.active_alerts),
            "total_alerts": len(self.alert_history),
            "connection_leak_count": self.connection_leak_count,
            "config": {
                "health_check_interval": self.config.health_check_interval,
                "metrics_collection_interval": self.config.metrics_collection_interval,
                "leak_detection_interval": self.config.leak_detection_interval
            }
        }
    
    def get_alerts(self, include_resolved: bool = False) -> List[DatabaseAlert]:
        """Get alerts."""
        if include_resolved:
            return self.alert_history.copy()
        else:
            return list(self.active_alerts.values())
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of current metrics."""
        if not self.pool_manager:
            return {}
        
        metrics = self.pool_manager.metrics
        return metrics.to_dict()


# Global monitor instance
_database_monitor: Optional[DatabaseMonitor] = None
_monitor_lock = asyncio.Lock()


async def get_database_monitor(config: Optional[DatabaseMonitorConfig] = None) -> DatabaseMonitor:
    """Get or create the global database monitor."""
    global _database_monitor
    
    async with _monitor_lock:
        if _database_monitor is None:
            _database_monitor = DatabaseMonitor(config)
        
        return _database_monitor


async def start_database_monitoring(
    pool_manager: Optional[DatabasePoolManager] = None,
    config: Optional[DatabaseMonitorConfig] = None
):
    """Start database monitoring."""
    monitor = await get_database_monitor(config)
    await monitor.start_monitoring(pool_manager)


async def stop_database_monitoring():
    """Stop database monitoring."""
    global _database_monitor
    
    if _database_monitor:
        await _database_monitor.stop_monitoring()
        _database_monitor = None