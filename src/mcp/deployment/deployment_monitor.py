"""
Deployment Monitoring and Status Reporting System

Real-time monitoring, metrics collection, and comprehensive status
reporting for MCP deployment operations.
"""

from __future__ import annotations
import asyncio
import time
import json
import psutil
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from pathlib import Path
import websockets
import threading
from datetime import datetime, timedelta

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError

logger = get_logger(__name__)


class MonitoringEventType(Enum):
    """Types of monitoring events"""
    DEPLOYMENT_STARTED = "deployment_started"
    DEPLOYMENT_COMPLETED = "deployment_completed"
    DEPLOYMENT_FAILED = "deployment_failed"
    SERVER_STARTING = "server_starting"
    SERVER_READY = "server_ready"
    SERVER_FAILED = "server_failed"
    HEALTH_CHECK_PASSED = "health_check_passed"
    HEALTH_CHECK_FAILED = "health_check_failed"
    ROLLBACK_STARTED = "rollback_started"
    ROLLBACK_COMPLETED = "rollback_completed"
    PERFORMANCE_ALERT = "performance_alert"
    RESOURCE_USAGE = "resource_usage"


@dataclass
class MonitoringEvent:
    """Individual monitoring event"""
    event_id: str
    event_type: MonitoringEventType
    deployment_id: str
    server_name: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # info, warning, error, critical
    tags: List[str] = field(default_factory=list)


@dataclass
class DeploymentMetrics:
    """Metrics for a deployment operation"""
    deployment_id: str
    start_time: float
    end_time: Optional[float] = None
    total_servers: int = 0
    successful_servers: int = 0
    failed_servers: int = 0
    current_phase: str = ""
    progress_percentage: float = 0.0
    resource_usage: Dict[str, float] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerStatus:
    """Status information for an individual server"""
    server_name: str
    deployment_id: str
    status: str  # "pending", "starting", "running", "failed", "stopped"
    health_status: str = "unknown"
    last_health_check: Optional[float] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)


class DeploymentMonitor:
    """
    Comprehensive deployment monitoring and status reporting system
    with real-time updates and performance tracking.
    """
    
    def __init__(self, websocket_port: int = 8765):
        """
        Initialize deployment monitor.
        
        Args:
            websocket_port: Port for WebSocket server for real-time updates
        """
        self.websocket_port = websocket_port
        
        # Monitoring state
        self.active_deployments: Dict[str, DeploymentMetrics] = {}
        self.server_statuses: Dict[str, ServerStatus] = {}
        self.monitoring_events: List[MonitoringEvent] = []
        self.event_subscribers: Set[Callable[[MonitoringEvent], None]] = set()
        
        # Performance tracking
        self.performance_baselines: Dict[str, Dict[str, float]] = {}
        self.alert_thresholds: Dict[str, float] = {
            "cpu_usage": 80.0,
            "memory_usage": 85.0,
            "disk_usage": 90.0,
            "response_time_ms": 1000.0,
            "error_rate": 5.0
        }
        
        # WebSocket connections for real-time updates
        self.websocket_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.websocket_server = None
        
        # Background monitoring task
        self.monitoring_task: Optional[asyncio.Task] = None
        self.monitoring_active = False
        
        # Event history management
        self.max_events = 10000
        self.event_retention_hours = 24
    
    async def start_monitoring(self):
        """Start the monitoring system."""
        logger.info("Starting deployment monitor")
        
        self.monitoring_active = True
        
        # Start WebSocket server for real-time updates
        await self._start_websocket_server()
        
        # Start background monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info(f"Deployment monitor started on WebSocket port {self.websocket_port}")
    
    async def stop_monitoring(self):
        """Stop the monitoring system."""
        logger.info("Stopping deployment monitor")
        
        self.monitoring_active = False
        
        # Stop monitoring task
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Stop WebSocket server
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        
        logger.info("Deployment monitor stopped")
    
    def subscribe_to_events(self, callback: Callable[[MonitoringEvent], None]):
        """Subscribe to monitoring events."""
        self.event_subscribers.add(callback)
        logger.debug(f"Added event subscriber: {callback}")
    
    def unsubscribe_from_events(self, callback: Callable[[MonitoringEvent], None]):
        """Unsubscribe from monitoring events."""
        self.event_subscribers.discard(callback)
        logger.debug(f"Removed event subscriber: {callback}")
    
    async def start_deployment_monitoring(
        self,
        deployment_id: str,
        total_servers: int,
        server_names: List[str]
    ):
        """Start monitoring a new deployment."""
        metrics = DeploymentMetrics(
            deployment_id=deployment_id,
            start_time=time.time(),
            total_servers=total_servers,
            current_phase="initialization"
        )
        
        self.active_deployments[deployment_id] = metrics
        
        # Initialize server statuses
        for server_name in server_names:
            self.server_statuses[f"{deployment_id}_{server_name}"] = ServerStatus(
                server_name=server_name,
                deployment_id=deployment_id,
                status="pending"
            )
        
        # Emit deployment started event
        await self._emit_event(MonitoringEvent(
            event_id=f"deploy_start_{deployment_id}",
            event_type=MonitoringEventType.DEPLOYMENT_STARTED,
            deployment_id=deployment_id,
            data={
                "total_servers": total_servers,
                "server_names": server_names
            }
        ))
        
        logger.info(f"Started monitoring deployment: {deployment_id}")
    
    async def update_deployment_progress(
        self,
        deployment_id: str,
        phase: str,
        progress_percentage: float,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Update deployment progress."""
        if deployment_id not in self.active_deployments:
            logger.warning(f"Deployment not found for progress update: {deployment_id}")
            return
        
        metrics = self.active_deployments[deployment_id]
        metrics.current_phase = phase
        metrics.progress_percentage = progress_percentage
        
        if additional_data:
            metrics.performance_metrics.update(additional_data)
        
        # Broadcast progress update
        await self._broadcast_deployment_update(deployment_id, metrics)
        
        logger.debug(f"Updated deployment progress: {deployment_id} - {phase} ({progress_percentage:.1f}%)")
    
    async def update_server_status(
        self,
        deployment_id: str,
        server_name: str,
        status: str,
        health_status: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
        alerts: Optional[List[str]] = None
    ):
        """Update individual server status."""
        server_key = f"{deployment_id}_{server_name}"
        
        if server_key not in self.server_statuses:
            self.server_statuses[server_key] = ServerStatus(
                server_name=server_name,
                deployment_id=deployment_id,
                status=status
            )
        
        server_status = self.server_statuses[server_key]
        server_status.status = status
        
        if health_status:
            server_status.health_status = health_status
            server_status.last_health_check = time.time()
        
        if metrics:
            server_status.metrics.update(metrics)
        
        if alerts:
            server_status.alerts = alerts
        
        # Emit server status event
        event_type = MonitoringEventType.SERVER_READY if status == "running" else MonitoringEventType.SERVER_STARTING
        if status == "failed":
            event_type = MonitoringEventType.SERVER_FAILED
        
        await self._emit_event(MonitoringEvent(
            event_id=f"server_{status}_{deployment_id}_{server_name}",
            event_type=event_type,
            deployment_id=deployment_id,
            server_name=server_name,
            data={
                "status": status,
                "health_status": health_status,
                "metrics": metrics or {},
                "alerts": alerts or []
            },
            severity="error" if status == "failed" else "info"
        ))
        
        # Update deployment metrics
        if deployment_id in self.active_deployments:
            self._update_deployment_server_counts(deployment_id)
        
        logger.debug(f"Updated server status: {server_name} -> {status}")
    
    async def complete_deployment_monitoring(
        self,
        deployment_id: str,
        success: bool,
        final_metrics: Optional[Dict[str, Any]] = None
    ):
        """Complete monitoring for a deployment."""
        if deployment_id not in self.active_deployments:
            logger.warning(f"Deployment not found for completion: {deployment_id}")
            return
        
        metrics = self.active_deployments[deployment_id]
        metrics.end_time = time.time()
        metrics.current_phase = "completed" if success else "failed"
        metrics.progress_percentage = 100.0
        
        if final_metrics:
            metrics.performance_metrics.update(final_metrics)
        
        # Calculate deployment duration
        duration_seconds = metrics.end_time - metrics.start_time
        
        # Emit completion event
        event_type = MonitoringEventType.DEPLOYMENT_COMPLETED if success else MonitoringEventType.DEPLOYMENT_FAILED
        await self._emit_event(MonitoringEvent(
            event_id=f"deploy_complete_{deployment_id}",
            event_type=event_type,
            deployment_id=deployment_id,
            data={
                "success": success,
                "duration_seconds": duration_seconds,
                "total_servers": metrics.total_servers,
                "successful_servers": metrics.successful_servers,
                "failed_servers": metrics.failed_servers,
                "final_metrics": final_metrics or {}
            },
            severity="info" if success else "error"
        ))
        
        logger.info(f"Completed deployment monitoring: {deployment_id} ({'success' if success else 'failed'})")
    
    async def record_health_check_result(
        self,
        deployment_id: str,
        server_name: str,
        check_name: str,
        success: bool,
        duration_ms: float,
        details: Optional[Dict[str, Any]] = None
    ):
        """Record health check result."""
        event_type = MonitoringEventType.HEALTH_CHECK_PASSED if success else MonitoringEventType.HEALTH_CHECK_FAILED
        
        await self._emit_event(MonitoringEvent(
            event_id=f"health_{check_name}_{deployment_id}_{server_name}",
            event_type=event_type,
            deployment_id=deployment_id,
            server_name=server_name,
            data={
                "check_name": check_name,
                "success": success,
                "duration_ms": duration_ms,
                "details": details or {}
            },
            severity="warning" if not success else "info"
        ))
        
        # Update server health status
        await self.update_server_status(
            deployment_id,
            server_name,
            status="running" if success else "unhealthy",
            health_status="healthy" if success else "unhealthy"
        )
    
    async def record_performance_metrics(
        self,
        deployment_id: str,
        server_name: Optional[str],
        metrics: Dict[str, float]
    ):
        """Record performance metrics and check for alerts."""
        # Check for performance alerts
        alerts = []
        for metric_name, value in metrics.items():
            if metric_name in self.alert_thresholds:
                threshold = self.alert_thresholds[metric_name]
                if value > threshold:
                    alerts.append(f"{metric_name} ({value:.1f}) exceeds threshold ({threshold})")
        
        # Emit performance alert if needed
        if alerts:
            await self._emit_event(MonitoringEvent(
                event_id=f"perf_alert_{deployment_id}_{server_name or 'system'}",
                event_type=MonitoringEventType.PERFORMANCE_ALERT,
                deployment_id=deployment_id,
                server_name=server_name,
                data={
                    "metrics": metrics,
                    "alerts": alerts,
                    "thresholds": self.alert_thresholds
                },
                severity="warning"
            ))
        
        # Emit resource usage event
        await self._emit_event(MonitoringEvent(
            event_id=f"resource_{deployment_id}_{server_name or 'system'}_{int(time.time())}",
            event_type=MonitoringEventType.RESOURCE_USAGE,
            deployment_id=deployment_id,
            server_name=server_name,
            data={"metrics": metrics}
        ))
        
        # Update server metrics if specific server
        if server_name:
            await self.update_server_status(
                deployment_id,
                server_name,
                status="running",  # Assume running if sending metrics
                metrics=metrics,
                alerts=alerts
            )
    
    def get_deployment_status(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive status for a deployment."""
        if deployment_id not in self.active_deployments:
            return None
        
        metrics = self.active_deployments[deployment_id]
        
        # Get server statuses for this deployment
        deployment_servers = {
            key: status for key, status in self.server_statuses.items()
            if status.deployment_id == deployment_id
        }
        
        # Calculate statistics
        total_duration = None
        if metrics.end_time:
            total_duration = metrics.end_time - metrics.start_time
        
        return {
            "deployment_id": deployment_id,
            "status": metrics.current_phase,
            "progress_percentage": metrics.progress_percentage,
            "start_time": metrics.start_time,
            "end_time": metrics.end_time,
            "duration_seconds": total_duration,
            "servers": {
                "total": metrics.total_servers,
                "successful": metrics.successful_servers,
                "failed": metrics.failed_servers,
                "pending": metrics.total_servers - metrics.successful_servers - metrics.failed_servers
            },
            "server_details": [
                {
                    "name": status.server_name,
                    "status": status.status,
                    "health_status": status.health_status,
                    "last_health_check": status.last_health_check,
                    "alerts_count": len(status.alerts),
                    "metrics": status.metrics
                }
                for status in deployment_servers.values()
            ],
            "performance_metrics": metrics.performance_metrics,
            "resource_usage": metrics.resource_usage
        }
    
    def get_recent_events(
        self,
        deployment_id: Optional[str] = None,
        event_types: Optional[List[MonitoringEventType]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get recent monitoring events."""
        filtered_events = []
        
        for event in reversed(self.monitoring_events[-limit*2:]):  # Get more to ensure we have enough after filtering
            # Filter by deployment_id if specified
            if deployment_id and event.deployment_id != deployment_id:
                continue
            
            # Filter by event types if specified
            if event_types and event.event_type not in event_types:
                continue
            
            filtered_events.append({
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "deployment_id": event.deployment_id,
                "server_name": event.server_name,
                "timestamp": event.timestamp,
                "severity": event.severity,
                "data": event.data,
                "tags": event.tags
            })
            
            if len(filtered_events) >= limit:
                break
        
        return filtered_events
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system resource metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network I/O
            net_io = psutil.net_io_counters()
            
            return {
                "cpu_usage": cpu_percent,
                "memory_usage": memory_percent,
                "memory_total_gb": memory.total / (1024**3),
                "memory_available_gb": memory.available / (1024**3),
                "disk_usage": disk_percent,
                "disk_total_gb": disk.total / (1024**3),
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": net_io.bytes_sent,
                "network_bytes_recv": net_io.bytes_recv,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    async def _emit_event(self, event: MonitoringEvent):
        """Emit a monitoring event to all subscribers."""
        # Add to event history
        self.monitoring_events.append(event)
        
        # Maintain event history size
        if len(self.monitoring_events) > self.max_events:
            self.monitoring_events = self.monitoring_events[-self.max_events:]
        
        # Notify subscribers
        for subscriber in self.event_subscribers:
            try:
                if asyncio.iscoroutinefunction(subscriber):
                    await subscriber(event)
                else:
                    subscriber(event)
            except Exception as e:
                logger.error(f"Error in event subscriber: {e}")
        
        # Broadcast to WebSocket clients
        await self._broadcast_event(event)
    
    def _update_deployment_server_counts(self, deployment_id: str):
        """Update server success/failure counts for a deployment."""
        metrics = self.active_deployments[deployment_id]
        
        deployment_servers = [
            status for status in self.server_statuses.values()
            if status.deployment_id == deployment_id
        ]
        
        metrics.successful_servers = len([s for s in deployment_servers if s.status == "running"])
        metrics.failed_servers = len([s for s in deployment_servers if s.status == "failed"])
    
    async def _monitoring_loop(self):
        """Background monitoring loop for system metrics."""
        while self.monitoring_active:
            try:
                # Collect system metrics
                system_metrics = self.get_system_metrics()
                
                # Record system metrics for active deployments
                for deployment_id in self.active_deployments:
                    await self.record_performance_metrics(
                        deployment_id,
                        None,  # System-wide metrics
                        system_metrics
                    )
                
                # Clean up old events
                await self._cleanup_old_events()
                
                # Wait before next collection
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _cleanup_old_events(self):
        """Clean up old monitoring events."""
        cutoff_time = time.time() - (self.event_retention_hours * 3600)
        original_count = len(self.monitoring_events)
        
        self.monitoring_events = [
            event for event in self.monitoring_events
            if event.timestamp > cutoff_time
        ]
        
        cleaned_count = original_count - len(self.monitoring_events)
        if cleaned_count > 0:
            logger.debug(f"Cleaned up {cleaned_count} old monitoring events")
    
    # WebSocket server for real-time updates
    async def _start_websocket_server(self):
        """Start WebSocket server for real-time monitoring updates."""
        try:
            self.websocket_server = await websockets.serve(
                self._handle_websocket_connection,
                "localhost",
                self.websocket_port
            )
            logger.info(f"WebSocket server started on port {self.websocket_port}")
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {e}")
    
    async def _handle_websocket_connection(self, websocket, path):
        """Handle new WebSocket connection."""
        self.websocket_clients.add(websocket)
        logger.debug(f"WebSocket client connected: {websocket.remote_address}")
        
        try:
            # Send current deployment statuses to new client
            for deployment_id in self.active_deployments:
                status = self.get_deployment_status(deployment_id)
                if status:
                    await websocket.send(json.dumps({
                        "type": "deployment_status",
                        "data": status
                    }))
            
            # Keep connection alive
            await websocket.wait_closed()
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
        finally:
            self.websocket_clients.discard(websocket)
            logger.debug("WebSocket client disconnected")
    
    async def _broadcast_event(self, event: MonitoringEvent):
        """Broadcast event to all WebSocket clients."""
        if not self.websocket_clients:
            return
        
        message = json.dumps({
            "type": "monitoring_event",
            "data": {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "deployment_id": event.deployment_id,
                "server_name": event.server_name,
                "timestamp": event.timestamp,
                "severity": event.severity,
                "data": event.data,
                "tags": event.tags
            }
        }, default=str)
        
        # Send to all connected clients
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket client: {e}")
                disconnected_clients.add(client)
        
        # Remove disconnected clients
        self.websocket_clients -= disconnected_clients
    
    async def _broadcast_deployment_update(self, deployment_id: str, metrics: DeploymentMetrics):
        """Broadcast deployment progress update."""
        if not self.websocket_clients:
            return
        
        status = self.get_deployment_status(deployment_id)
        if not status:
            return
        
        message = json.dumps({
            "type": "deployment_update",
            "data": status
        }, default=str)
        
        # Send to all connected clients
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                logger.error(f"Error broadcasting deployment update: {e}")
                disconnected_clients.add(client)
        
        # Remove disconnected clients
        self.websocket_clients -= disconnected_clients