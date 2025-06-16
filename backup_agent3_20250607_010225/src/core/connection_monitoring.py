"""
Connection pool monitoring and metrics export.

This module provides monitoring integration for connection pools,
including Prometheus metrics export and health check endpoints.
"""

from __future__ import annotations
import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from dataclasses import asdict

try:
    from prometheus_client import Counter, Gauge, Histogram, Summary, CollectorRegistry, generate_latest
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

from src.core.connections import (
    ConnectionPoolManager,
    ConnectionMetrics,
    get_connection_manager
)

logger = logging.getLogger(__name__)


class ConnectionPoolMonitor:
    """Monitor connection pools and export metrics."""
    
    def __init__(self, export_interval: int = 60):
        """
        Initialize connection pool monitor.
        
        Args:
            export_interval: Seconds between metric exports
        """
        self.export_interval = export_interval
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Prometheus metrics if available
        if HAS_PROMETHEUS:
            self.registry = CollectorRegistry()
            
            # Connection metrics
            self.active_connections = Gauge(
                'connection_pool_active_connections',
                'Number of active connections',
                ['pool_type', 'host'],
                registry=self.registry
            )
            
            self.total_connections = Counter(
                'connection_pool_total_connections',
                'Total connections created',
                ['pool_type', 'host'],
                registry=self.registry
            )
            
            self.failed_connections = Counter(
                'connection_pool_failed_connections',
                'Total failed connections',
                ['pool_type', 'host'],
                registry=self.registry
            )
            
            self.connection_wait_time = Histogram(
                'connection_pool_wait_seconds',
                'Time waiting for connection',
                ['pool_type', 'host'],
                buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
                registry=self.registry
            )
            
            self.request_duration = Histogram(
                'connection_pool_request_duration_seconds',
                'Request duration through connection pool',
                ['pool_type', 'host'],
                buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
                registry=self.registry
            )
            
            self.error_rate = Gauge(
                'connection_pool_error_rate',
                'Connection pool error rate',
                ['pool_type', 'host'],
                registry=self.registry
            )
            
            self.pool_efficiency = Gauge(
                'connection_pool_efficiency',
                'Connection reuse efficiency',
                ['pool_type', 'host'],
                registry=self.registry
            )
    
    async def start(self):
        """Start monitoring connection pools."""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Connection pool monitoring started")
    
    async def stop(self):
        """Stop monitoring."""
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Connection pool monitoring stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self._collect_metrics()
                await asyncio.sleep(self.export_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(self.export_interval)
    
    async def _collect_metrics(self):
        """Collect metrics from all connection pools."""
        try:
            manager = await get_connection_manager()
            all_metrics = manager.get_all_metrics()
            
            # Process HTTP pool metrics
            for host, metrics in all_metrics.get("http", {}).items():
                self._update_metrics("http", host, metrics)
            
            # Process database pool metrics
            for dsn, metrics in all_metrics.get("database", {}).items():
                self._update_metrics("database", dsn, metrics)
            
            # Process Redis pool metrics
            for url, metrics in all_metrics.get("redis", {}).items():
                self._update_metrics("redis", url, metrics)
            
            # Process WebSocket pool metrics
            for url, metrics in all_metrics.get("websocket", {}).items():
                self._update_metrics("websocket", url, metrics)
            
        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
    
    def _update_metrics(self, pool_type: str, identifier: str, metrics: ConnectionMetrics):
        """Update Prometheus metrics."""
        if not HAS_PROMETHEUS:
            return
        
        # Update gauges
        self.active_connections.labels(
            pool_type=pool_type,
            host=self._sanitize_label(identifier)
        ).set(metrics.active_connections)
        
        # Update counters (use _total suffix convention)
        self.total_connections.labels(
            pool_type=pool_type,
            host=self._sanitize_label(identifier)
        )._value._value = metrics.total_connections
        
        self.failed_connections.labels(
            pool_type=pool_type,
            host=self._sanitize_label(identifier)
        )._value._value = metrics.failed_connections
        
        # Update error rate
        error_rate = metrics.get_error_rate()
        self.error_rate.labels(
            pool_type=pool_type,
            host=self._sanitize_label(identifier)
        ).set(error_rate)
        
        # Update efficiency
        if metrics.total_connections > 0:
            efficiency = metrics.connection_reuse_count / metrics.total_connections
        else:
            efficiency = 0.0
        
        self.pool_efficiency.labels(
            pool_type=pool_type,
            host=self._sanitize_label(identifier)
        ).set(efficiency)
        
        # Update wait time histogram
        avg_wait = metrics.get_average_wait_time()
        if avg_wait > 0:
            self.connection_wait_time.labels(
                pool_type=pool_type,
                host=self._sanitize_label(identifier)
            ).observe(avg_wait)
    
    def _sanitize_label(self, value: str) -> str:
        """Sanitize label value for Prometheus."""
        # Remove or replace invalid characters
        return value.replace("://", "_").replace("/", "_").replace(":", "_")
    
    def get_metrics(self) -> bytes:
        """Get Prometheus metrics in text format."""
        if HAS_PROMETHEUS:
            return generate_latest(self.registry)
        return b""
    
    async def get_health_report(self) -> Dict[str, Any]:
        """Get detailed health report for all connection pools."""
        try:
            manager = await get_connection_manager()
            all_metrics = manager.get_all_metrics()
            
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "healthy",
                "pools": {}
            }
            
            total_errors = 0
            total_requests = 0
            
            # Analyze each pool type
            for pool_type, pool_metrics in all_metrics.items():
                pool_report = {
                    "hosts": {},
                    "summary": {
                        "total_hosts": len(pool_metrics),
                        "total_active": 0,
                        "total_failed": 0,
                        "average_error_rate": 0.0
                    }
                }
                
                for identifier, metrics in pool_metrics.items():
                    host_report = {
                        "active_connections": metrics.active_connections,
                        "total_connections": metrics.total_connections,
                        "failed_connections": metrics.failed_connections,
                        "error_rate": metrics.get_error_rate(),
                        "average_wait_time": metrics.get_average_wait_time(),
                        "efficiency": (
                            metrics.connection_reuse_count / metrics.total_connections
                            if metrics.total_connections > 0 else 0.0
                        ),
                        "health": self._determine_health(metrics)
                    }
                    
                    pool_report["hosts"][identifier] = host_report
                    pool_report["summary"]["total_active"] += metrics.active_connections
                    pool_report["summary"]["total_failed"] += metrics.failed_connections
                    
                    total_errors += metrics.total_errors
                    total_requests += metrics.total_requests
                
                # Calculate average error rate for pool
                if pool_metrics:
                    avg_error_rate = sum(
                        m.get_error_rate() for m in pool_metrics.values()
                    ) / len(pool_metrics)
                    pool_report["summary"]["average_error_rate"] = avg_error_rate
                
                report["pools"][pool_type] = pool_report
            
            # Overall health determination
            overall_error_rate = total_errors / total_requests if total_requests > 0 else 0.0
            
            if overall_error_rate > 0.1:  # >10% errors
                report["status"] = "unhealthy"
            elif overall_error_rate > 0.05:  # >5% errors
                report["status"] = "degraded"
            
            report["overall_error_rate"] = overall_error_rate
            report["total_requests"] = total_requests
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate health report: {e}")
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "error",
                "error": str(e)
            }
    
    def _determine_health(self, metrics: ConnectionMetrics) -> str:
        """Determine health status of a connection pool."""
        error_rate = metrics.get_error_rate()
        
        if error_rate > 0.2:  # >20% errors
            return "critical"
        elif error_rate > 0.1:  # >10% errors
            return "unhealthy"
        elif error_rate > 0.05:  # >5% errors
            return "degraded"
        elif metrics.health_check_failures > 5:
            return "warning"
        else:
            return "healthy"


class ConnectionPoolHealthCheck:
    """Health check endpoint for connection pools."""
    
    def __init__(self, monitor: ConnectionPoolMonitor):
        self.monitor = monitor
    
    async def check_health(self) -> Dict[str, Any]:
        """Perform health check."""
        report = await self.monitor.get_health_report()
        
        # Add recommendations based on health
        recommendations = []
        
        for pool_type, pool_data in report.get("pools", {}).items():
            for host, host_data in pool_data.get("hosts", {}).items():
                if host_data.get("health") in ["critical", "unhealthy"]:
                    recommendations.append(
                        f"High error rate for {pool_type} pool {host}: "
                        f"{host_data.get('error_rate', 0):.1%}"
                    )
                
                if host_data.get("average_wait_time", 0) > 1.0:
                    recommendations.append(
                        f"High connection wait time for {pool_type} pool {host}: "
                        f"{host_data.get('average_wait_time', 0):.2f}s"
                    )
                
                if host_data.get("efficiency", 0) < 0.5:
                    recommendations.append(
                        f"Low connection reuse efficiency for {pool_type} pool {host}: "
                        f"{host_data.get('efficiency', 0):.1%}"
                    )
        
        report["recommendations"] = recommendations
        
        return report
    
    async def get_metrics(self) -> bytes:
        """Get Prometheus metrics."""
        return self.monitor.get_metrics()


# Global monitor instance
_global_monitor: Optional[ConnectionPoolMonitor] = None


async def get_connection_monitor() -> ConnectionPoolMonitor:
    """Get or create global connection monitor."""
    global _global_monitor
    
    if _global_monitor is None:
        _global_monitor = ConnectionPoolMonitor()
        await _global_monitor.start()
    
    return _global_monitor


async def stop_connection_monitor():
    """Stop global connection monitor."""
    global _global_monitor
    
    if _global_monitor:
        await _global_monitor.stop()
        _global_monitor = None