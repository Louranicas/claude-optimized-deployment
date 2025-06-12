#!/usr/bin/env python3
"""
Real-time Dashboard Server
Interactive monitoring and visualization with WebSocket support
"""

import asyncio
import json
import time
import logging
import threading
import weakref
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import websockets
import socket
from datetime import datetime
import statistics

from metrics_collector import MetricValue, MetricsCollector
from real_time_processor import RealTimeProcessor, IntegratedMonitoringSystem
from analytics_engine import AdvancedAnalyticsEngine

logger = logging.getLogger(__name__)

@dataclass
class DashboardConfig:
    """Dashboard configuration"""
    host: str = "localhost"
    port: int = 8765
    max_connections: int = 100
    update_interval: float = 1.0
    history_size: int = 1000
    enable_cors: bool = True
    
@dataclass
class ChartData:
    """Chart data structure"""
    chart_id: str
    chart_type: str  # line, bar, gauge, heatmap, scatter
    title: str
    data_points: List[Dict[str, Any]]
    config: Dict[str, Any]
    last_updated: float

@dataclass
class DashboardWidget:
    """Dashboard widget configuration"""
    widget_id: str
    widget_type: str  # chart, table, alert, status, metric
    title: str
    position: Dict[str, int]  # x, y, width, height
    config: Dict[str, Any]
    data_sources: List[str]
    update_frequency: float = 1.0

class WebSocketManager:
    """Manages WebSocket connections and broadcasting"""
    
    def __init__(self):
        self.connections: Set[websockets.WebSocketServerProtocol] = set()
        self.subscription_map: Dict[str, Set[websockets.WebSocketServerProtocol]] = defaultdict(set)
        self.connection_metadata: Dict[websockets.WebSocketServerProtocol, Dict[str, Any]] = {}
    
    async def register(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Register a new WebSocket connection"""
        self.connections.add(websocket)
        self.connection_metadata[websocket] = {
            'connected_at': time.time(),
            'path': path,
            'subscriptions': set(),
            'message_count': 0
        }
        logger.info(f"New WebSocket connection from {websocket.remote_address}")
    
    async def unregister(self, websocket: websockets.WebSocketServerProtocol):
        """Unregister a WebSocket connection"""
        self.connections.discard(websocket)
        
        # Remove from all subscriptions
        for subscription_set in self.subscription_map.values():
            subscription_set.discard(websocket)
        
        # Remove metadata
        self.connection_metadata.pop(websocket, None)
        
        logger.info(f"WebSocket connection closed")
    
    async def subscribe(self, websocket: websockets.WebSocketServerProtocol, topics: List[str]):
        """Subscribe a connection to specific topics"""
        for topic in topics:
            self.subscription_map[topic].add(websocket)
            self.connection_metadata[websocket]['subscriptions'].add(topic)
        
        logger.info(f"Connection subscribed to topics: {topics}")
    
    async def unsubscribe(self, websocket: websockets.WebSocketServerProtocol, topics: List[str]):
        """Unsubscribe a connection from specific topics"""
        for topic in topics:
            self.subscription_map[topic].discard(websocket)
            self.connection_metadata[websocket]['subscriptions'].discard(topic)
    
    async def broadcast(self, message: Dict[str, Any], topic: str = None):
        """Broadcast message to all or topic-specific connections"""
        if topic:
            target_connections = self.subscription_map[topic]
        else:
            target_connections = self.connections
        
        if target_connections:
            message_str = json.dumps(message)
            disconnected = set()
            
            for websocket in target_connections:
                try:
                    await websocket.send(message_str)
                    self.connection_metadata[websocket]['message_count'] += 1
                except websockets.exceptions.ConnectionClosed:
                    disconnected.add(websocket)
                except Exception as e:
                    logger.error(f"Error sending message to WebSocket: {e}")
                    disconnected.add(websocket)
            
            # Clean up disconnected connections
            for websocket in disconnected:
                await self.unregister(websocket)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'total_connections': len(self.connections),
            'total_subscriptions': sum(len(subs) for subs in self.subscription_map.values()),
            'topics_active': len(self.subscription_map),
            'connections_by_topic': {topic: len(subs) for topic, subs in self.subscription_map.items()}
        }

class DashboardDataManager:
    """Manages dashboard data and chart configurations"""
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.chart_data: Dict[str, ChartData] = {}
        self.widgets: Dict[str, DashboardWidget] = {}
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.alert_history: deque = deque(maxlen=100)
        
        # Initialize default charts and widgets
        self._initialize_default_charts()
        self._initialize_default_widgets()
    
    def _initialize_default_charts(self):
        """Initialize default chart configurations"""
        
        # System metrics charts
        self.chart_data["cpu_usage"] = ChartData(
            chart_id="cpu_usage",
            chart_type="line",
            title="CPU Usage",
            data_points=[],
            config={
                "y_axis": {"min": 0, "max": 100, "unit": "%"},
                "colors": ["#ff6b6b", "#4ecdc4", "#45b7d1"],
                "refresh_rate": 1000,
                "max_points": 100
            },
            last_updated=0
        )
        
        self.chart_data["memory_usage"] = ChartData(
            chart_id="memory_usage",
            chart_type="line",
            title="Memory Usage",
            data_points=[],
            config={
                "y_axis": {"min": 0, "max": 100, "unit": "%"},
                "colors": ["#96ceb4", "#feca57"],
                "refresh_rate": 1000,
                "max_points": 100
            },
            last_updated=0
        )
        
        # Performance metrics charts
        self.chart_data["response_times"] = ChartData(
            chart_id="response_times",
            chart_type="line",
            title="Response Times",
            data_points=[],
            config={
                "y_axis": {"min": 0, "unit": "ms"},
                "colors": ["#6c5ce7", "#fd79a8", "#fdcb6e"],
                "refresh_rate": 1000,
                "max_points": 100
            },
            last_updated=0
        )
        
        # Circle of Experts metrics
        self.chart_data["expert_performance"] = ChartData(
            chart_id="expert_performance",
            chart_type="bar",
            title="Expert Performance",
            data_points=[],
            config={
                "y_axis": {"min": 0, "unit": "requests/min"},
                "colors": ["#00b894", "#e17055", "#0984e3", "#6c5ce7"],
                "refresh_rate": 5000,
                "max_points": 50
            },
            last_updated=0
        )
        
        # System health gauge
        self.chart_data["system_health"] = ChartData(
            chart_id="system_health",
            chart_type="gauge",
            title="System Health Score",
            data_points=[],
            config={
                "min": 0, "max": 1,
                "thresholds": [
                    {"value": 0.8, "color": "#00b894"},
                    {"value": 0.6, "color": "#fdcb6e"},
                    {"value": 0.0, "color": "#e17055"}
                ],
                "refresh_rate": 2000
            },
            last_updated=0
        )
        
        # Alert timeline
        self.chart_data["alert_timeline"] = ChartData(
            chart_id="alert_timeline",
            chart_type="timeline",
            title="Alert Timeline",
            data_points=[],
            config={
                "height": 200,
                "refresh_rate": 1000,
                "max_points": 50
            },
            last_updated=0
        )
        
        # Resource utilization heatmap
        self.chart_data["resource_heatmap"] = ChartData(
            chart_id="resource_heatmap",
            chart_type="heatmap",
            title="Resource Utilization Heatmap",
            data_points=[],
            config={
                "refresh_rate": 5000,
                "color_scale": ["#2d3436", "#74b9ff", "#00cec9", "#fdcb6e", "#e17055"]
            },
            last_updated=0
        )
    
    def _initialize_default_widgets(self):
        """Initialize default dashboard widgets"""
        
        self.widgets["system_overview"] = DashboardWidget(
            widget_id="system_overview",
            widget_type="chart",
            title="System Overview",
            position={"x": 0, "y": 0, "width": 6, "height": 4},
            config={"chart_ids": ["cpu_usage", "memory_usage"]},
            data_sources=["system.cpu_usage_percent", "system.memory_usage_percent"]
        )
        
        self.widgets["performance_metrics"] = DashboardWidget(
            widget_id="performance_metrics",
            widget_type="chart",
            title="Performance Metrics",
            position={"x": 6, "y": 0, "width": 6, "height": 4},
            config={"chart_ids": ["response_times"]},
            data_sources=["application.response_time", "application.query_time"]
        )
        
        self.widgets["health_status"] = DashboardWidget(
            widget_id="health_status",
            widget_type="status",
            title="Health Status",
            position={"x": 0, "y": 4, "width": 3, "height": 2},
            config={"show_score": True, "show_indicators": True},
            data_sources=["system_health_score", "application_health_score"]
        )
        
        self.widgets["alert_panel"] = DashboardWidget(
            widget_id="alert_panel",
            widget_type="alert",
            title="Active Alerts",
            position={"x": 3, "y": 4, "width": 9, "height": 2},
            config={"max_alerts": 10, "auto_refresh": True},
            data_sources=["alerts"]
        )
        
        self.widgets["expert_dashboard"] = DashboardWidget(
            widget_id="expert_dashboard",
            widget_type="chart",
            title="Circle of Experts",
            position={"x": 0, "y": 6, "width": 6, "height": 4},
            config={"chart_ids": ["expert_performance"]},
            data_sources=["circle_of_experts.*"]
        )
        
        self.widgets["resource_monitor"] = DashboardWidget(
            widget_id="resource_monitor",
            widget_type="chart",
            title="Resource Monitor",
            position={"x": 6, "y": 6, "width": 6, "height": 4},
            config={"chart_ids": ["resource_heatmap"]},
            data_sources=["system.*", "application.*"]
        )
    
    def update_metric_data(self, metric: MetricValue):
        """Update metric data for charts"""
        timestamp = metric.timestamp * 1000  # Convert to milliseconds for JavaScript
        
        # Store in history
        self.metric_history[metric.name].append({
            'timestamp': timestamp,
            'value': metric.value,
            'tags': metric.tags
        })
        
        # Update relevant charts
        self._update_cpu_chart(metric, timestamp)
        self._update_memory_chart(metric, timestamp)
        self._update_response_time_chart(metric, timestamp)
        self._update_expert_performance_chart(metric, timestamp)
        self._update_system_health_chart(metric, timestamp)
        self._update_resource_heatmap(metric, timestamp)
    
    def _update_cpu_chart(self, metric: MetricValue, timestamp: float):
        """Update CPU usage chart"""
        if "cpu_usage_percent" in metric.name:
            chart = self.chart_data["cpu_usage"]
            
            # Add data point
            data_point = {
                'x': timestamp,
                'y': metric.value,
                'series': metric.tags.get('core', 'total')
            }
            
            chart.data_points.append(data_point)
            
            # Limit data points
            if len(chart.data_points) > chart.config["max_points"]:
                chart.data_points = chart.data_points[-chart.config["max_points"]:]
            
            chart.last_updated = time.time()
    
    def _update_memory_chart(self, metric: MetricValue, timestamp: float):
        """Update memory usage chart"""
        if "memory_usage_percent" in metric.name or "memory_percent" in metric.name:
            chart = self.chart_data["memory_usage"]
            
            data_point = {
                'x': timestamp,
                'y': metric.value,
                'series': metric.tags.get('type', 'memory')
            }
            
            chart.data_points.append(data_point)
            
            if len(chart.data_points) > chart.config["max_points"]:
                chart.data_points = chart.data_points[-chart.config["max_points"]:]
            
            chart.last_updated = time.time()
    
    def _update_response_time_chart(self, metric: MetricValue, timestamp: float):
        """Update response time chart"""
        if "response_time" in metric.name or "query_time" in metric.name:
            chart = self.chart_data["response_times"]
            
            data_point = {
                'x': timestamp,
                'y': metric.value,
                'series': metric.tags.get('component', 'application')
            }
            
            chart.data_points.append(data_point)
            
            if len(chart.data_points) > chart.config["max_points"]:
                chart.data_points = chart.data_points[-chart.config["max_points"]:]
            
            chart.last_updated = time.time()
    
    def _update_expert_performance_chart(self, metric: MetricValue, timestamp: float):
        """Update Circle of Experts performance chart"""
        if "circle_of_experts" in metric.name or "expert" in metric.name:
            chart = self.chart_data["expert_performance"]
            
            expert_type = metric.tags.get('expert_type', 'unknown')
            
            # Find existing data point for this expert type
            existing_point = None
            for point in chart.data_points:
                if point.get('category') == expert_type:
                    existing_point = point
                    break
            
            if existing_point:
                existing_point['y'] = metric.value
                existing_point['timestamp'] = timestamp
            else:
                data_point = {
                    'category': expert_type,
                    'y': metric.value,
                    'timestamp': timestamp
                }
                chart.data_points.append(data_point)
            
            chart.last_updated = time.time()
    
    def _update_system_health_chart(self, metric: MetricValue, timestamp: float):
        """Update system health gauge"""
        if "health_score" in metric.name:
            chart = self.chart_data["system_health"]
            
            data_point = {
                'value': metric.value,
                'timestamp': timestamp,
                'label': metric.tags.get('component', 'system')
            }
            
            chart.data_points = [data_point]  # Gauge shows single value
            chart.last_updated = time.time()
    
    def _update_resource_heatmap(self, metric: MetricValue, timestamp: float):
        """Update resource utilization heatmap"""
        resource_metrics = [
            "cpu_usage_percent", "memory_usage_percent", "disk_usage_percent",
            "network_utilization", "process_cpu_percent", "process_memory_percent"
        ]
        
        if any(rm in metric.name for rm in resource_metrics):
            chart = self.chart_data["resource_heatmap"]
            
            # Determine resource type and component
            if "cpu" in metric.name:
                resource_type = "CPU"
            elif "memory" in metric.name:
                resource_type = "Memory"
            elif "disk" in metric.name:
                resource_type = "Disk"
            elif "network" in metric.name:
                resource_type = "Network"
            else:
                resource_type = "Other"
            
            component = metric.tags.get('component', metric.source)
            
            data_point = {
                'x': component,
                'y': resource_type,
                'value': metric.value,
                'timestamp': timestamp
            }
            
            # Update or add data point
            updated = False
            for i, point in enumerate(chart.data_points):
                if point['x'] == component and point['y'] == resource_type:
                    chart.data_points[i] = data_point
                    updated = True
                    break
            
            if not updated:
                chart.data_points.append(data_point)
            
            chart.last_updated = time.time()
    
    def add_alert(self, alert_data: Dict[str, Any]):
        """Add alert to timeline"""
        timestamp = time.time() * 1000
        
        alert_entry = {
            'timestamp': timestamp,
            'level': alert_data.get('level', 'info'),
            'message': alert_data.get('message', 'Unknown alert'),
            'metric': alert_data.get('metric', ''),
            'value': alert_data.get('value', ''),
            'id': f"alert_{int(timestamp)}"
        }
        
        self.alert_history.append(alert_entry)
        
        # Update alert timeline chart
        chart = self.chart_data["alert_timeline"]
        chart.data_points.append(alert_entry)
        
        if len(chart.data_points) > chart.config["max_points"]:
            chart.data_points = chart.data_points[-chart.config["max_points"]:]
        
        chart.last_updated = time.time()
    
    def get_chart_data(self, chart_id: str) -> Optional[Dict[str, Any]]:
        """Get chart data for specific chart"""
        if chart_id in self.chart_data:
            chart = self.chart_data[chart_id]
            return {
                'chart_id': chart.chart_id,
                'chart_type': chart.chart_type,
                'title': chart.title,
                'data': chart.data_points,
                'config': chart.config,
                'last_updated': chart.last_updated
            }
        return None
    
    def get_widget_config(self, widget_id: str) -> Optional[Dict[str, Any]]:
        """Get widget configuration"""
        if widget_id in self.widgets:
            widget = self.widgets[widget_id]
            return asdict(widget)
        return None
    
    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get complete dashboard configuration"""
        return {
            'widgets': [asdict(widget) for widget in self.widgets.values()],
            'charts': [asdict(chart) for chart in self.chart_data.values()],
            'timestamp': time.time()
        }

class DashboardServer:
    """Real-time dashboard server with WebSocket support"""
    
    def __init__(self, config: DashboardConfig = None, monitoring_system: IntegratedMonitoringSystem = None):
        self.config = config or DashboardConfig()
        self.monitoring_system = monitoring_system
        self.websocket_manager = WebSocketManager()
        self.data_manager = DashboardDataManager(self.config.history_size)
        self.running = False
        self.server = None
        
        # Background tasks
        self.update_task: Optional[asyncio.Task] = None
        self.broadcast_task: Optional[asyncio.Task] = None
        
        # Connect to monitoring system if provided
        if self.monitoring_system:
            self.monitoring_system.add_alert_callback(self._handle_metric_update)
            self.monitoring_system.processor.add_output_callback(self._handle_alert)
        
        logger.info(f"Initialized dashboard server on {self.config.host}:{self.config.port}")
    
    def _handle_metric_update(self, metric: MetricValue):
        """Handle metric updates from monitoring system"""
        self.data_manager.update_metric_data(metric)
    
    def _handle_alert(self, alert_data: Any):
        """Handle alerts from monitoring system"""
        if isinstance(alert_data, dict):
            self.data_manager.add_alert(alert_data)
    
    async def start(self):
        """Start the dashboard server"""
        if self.running:
            logger.warning("Dashboard server already running")
            return
        
        self.running = True
        
        # Start WebSocket server
        self.server = await websockets.serve(
            self._handle_websocket,
            self.config.host,
            self.config.port,
            max_size=1024*1024,  # 1MB max message size
            max_queue=100
        )
        
        # Start background tasks
        self.update_task = asyncio.create_task(self._update_loop())
        self.broadcast_task = asyncio.create_task(self._broadcast_loop())
        
        logger.info(f"Dashboard server started on ws://{self.config.host}:{self.config.port}")
    
    async def stop(self):
        """Stop the dashboard server"""
        self.running = False
        
        # Cancel background tasks
        if self.update_task:
            self.update_task.cancel()
        if self.broadcast_task:
            self.broadcast_task.cancel()
        
        # Close WebSocket server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("Dashboard server stopped")
    
    async def _handle_websocket(self, websocket, path):
        """Handle WebSocket connections"""
        await self.websocket_manager.register(websocket, path)
        
        try:
            # Send initial dashboard configuration
            config_message = {
                'type': 'dashboard_config',
                'data': self.data_manager.get_dashboard_config()
            }
            await websocket.send(json.dumps(config_message))
            
            # Handle incoming messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._handle_websocket_message(websocket, data)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received: {message}")
                except Exception as e:
                    logger.error(f"Error handling WebSocket message: {e}")
        
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            await self.websocket_manager.unregister(websocket)
    
    async def _handle_websocket_message(self, websocket, message: Dict[str, Any]):
        """Handle incoming WebSocket messages"""
        message_type = message.get('type')
        
        if message_type == 'subscribe':
            topics = message.get('topics', [])
            await self.websocket_manager.subscribe(websocket, topics)
            
        elif message_type == 'unsubscribe':
            topics = message.get('topics', [])
            await self.websocket_manager.unsubscribe(websocket, topics)
            
        elif message_type == 'get_chart_data':
            chart_id = message.get('chart_id')
            if chart_id:
                chart_data = self.data_manager.get_chart_data(chart_id)
                if chart_data:
                    response = {
                        'type': 'chart_data',
                        'data': chart_data
                    }
                    await websocket.send(json.dumps(response))
            
        elif message_type == 'get_widget_config':
            widget_id = message.get('widget_id')
            if widget_id:
                widget_config = self.data_manager.get_widget_config(widget_id)
                if widget_config:
                    response = {
                        'type': 'widget_config',
                        'data': widget_config
                    }
                    await websocket.send(json.dumps(response))
        
        elif message_type == 'ping':
            response = {
                'type': 'pong',
                'timestamp': time.time()
            }
            await websocket.send(json.dumps(response))
        
        else:
            logger.warning(f"Unknown message type: {message_type}")
    
    async def _update_loop(self):
        """Background task for updating dashboard data"""
        while self.running:
            try:
                # Get latest metrics from monitoring system
                if self.monitoring_system:
                    latest_metrics = self.monitoring_system.collector.get_latest_metrics()
                    
                    for metric_name, metric in latest_metrics.items():
                        self.data_manager.update_metric_data(metric)
                
                # Sleep for update interval
                await asyncio.sleep(self.config.update_interval)
                
            except Exception as e:
                logger.error(f"Update loop error: {e}")
                await asyncio.sleep(5)
    
    async def _broadcast_loop(self):
        """Background task for broadcasting updates"""
        while self.running:
            try:
                current_time = time.time()
                
                # Broadcast updated chart data
                for chart_id, chart in self.data_manager.chart_data.items():
                    if current_time - chart.last_updated < self.config.update_interval * 2:
                        chart_data = self.data_manager.get_chart_data(chart_id)
                        if chart_data:
                            message = {
                                'type': 'chart_update',
                                'data': chart_data
                            }
                            await self.websocket_manager.broadcast(message, f"chart_{chart_id}")
                
                # Broadcast system status
                if self.monitoring_system:
                    status = self.monitoring_system.get_system_status()
                    message = {
                        'type': 'system_status',
                        'data': status
                    }
                    await self.websocket_manager.broadcast(message, "system_status")
                
                # Broadcast connection stats
                connection_stats = self.websocket_manager.get_connection_stats()
                message = {
                    'type': 'connection_stats',
                    'data': connection_stats
                }
                await self.websocket_manager.broadcast(message, "admin")
                
                # Sleep for update interval
                await asyncio.sleep(self.config.update_interval)
                
            except Exception as e:
                logger.error(f"Broadcast loop error: {e}")
                await asyncio.sleep(5)
    
    def get_server_stats(self) -> Dict[str, Any]:
        """Get dashboard server statistics"""
        return {
            'config': asdict(self.config),
            'running': self.running,
            'websocket_stats': self.websocket_manager.get_connection_stats(),
            'charts_count': len(self.data_manager.chart_data),
            'widgets_count': len(self.data_manager.widgets),
            'total_metrics_tracked': sum(len(history) for history in self.data_manager.metric_history.values()),
            'server_uptime': time.time() - getattr(self, 'start_time', time.time())
        }

# HTML Dashboard Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claude Deployment Monitoring Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #ffffff; }
        .dashboard { display: grid; grid-template-columns: repeat(12, 1fr); gap: 20px; padding: 20px; min-height: 100vh; }
        .widget { background: #2d2d2d; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .widget h3 { margin-bottom: 15px; color: #ffffff; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        .metric-value { font-size: 2.5em; font-weight: bold; color: #4CAF50; }
        .metric-label { font-size: 0.9em; color: #cccccc; margin-top: 5px; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-healthy { background-color: #4CAF50; }
        .status-warning { background-color: #FF9800; }
        .status-critical { background-color: #F44336; }
        .alert-item { padding: 10px; margin: 5px 0; border-left: 4px solid #FF9800; background: rgba(255,152,0,0.1); border-radius: 4px; }
        .connection-status { position: fixed; top: 20px; right: 20px; padding: 10px; border-radius: 4px; }
        .connected { background: #4CAF50; }
        .disconnected { background: #F44336; }
        .chart-container { position: relative; height: 300px; }
        .grid-item-1 { grid-column: span 1; }
        .grid-item-2 { grid-column: span 2; }
        .grid-item-3 { grid-column: span 3; }
        .grid-item-4 { grid-column: span 4; }
        .grid-item-6 { grid-column: span 6; }
        .grid-item-12 { grid-column: span 12; }
    </style>
</head>
<body>
    <div id="connectionStatus" class="connection-status disconnected">Connecting...</div>
    
    <div class="dashboard">
        <!-- System Overview -->
        <div class="widget grid-item-6">
            <h3>System Overview</h3>
            <div class="chart-container">
                <canvas id="systemChart"></canvas>
            </div>
        </div>
        
        <!-- Performance Metrics -->
        <div class="widget grid-item-6">
            <h3>Performance Metrics</h3>
            <div class="chart-container">
                <canvas id="performanceChart"></canvas>
            </div>
        </div>
        
        <!-- Health Status -->
        <div class="widget grid-item-3">
            <h3>Health Status</h3>
            <div id="healthStatus">
                <div class="metric-value" id="healthScore">--</div>
                <div class="metric-label">System Health Score</div>
                <div style="margin-top: 20px;">
                    <div><span class="status-indicator status-healthy"></span>All Systems Operational</div>
                </div>
            </div>
        </div>
        
        <!-- Active Alerts -->
        <div class="widget grid-item-9">
            <h3>Active Alerts</h3>
            <div id="alertsContainer">
                <div class="metric-label">No active alerts</div>
            </div>
        </div>
        
        <!-- Circle of Experts -->
        <div class="widget grid-item-6">
            <h3>Circle of Experts Performance</h3>
            <div class="chart-container">
                <canvas id="expertChart"></canvas>
            </div>
        </div>
        
        <!-- Resource Monitor -->
        <div class="widget grid-item-6">
            <h3>Resource Utilization</h3>
            <div class="chart-container">
                <canvas id="resourceChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        class DashboardManager {
            constructor() {
                this.ws = null;
                this.charts = {};
                this.reconnectAttempts = 0;
                this.maxReconnectAttempts = 5;
                this.reconnectDelay = 1000;
                
                this.initializeCharts();
                this.connect();
            }
            
            connect() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.hostname}:8765`;
                
                this.ws = new WebSocket(wsUrl);
                
                this.ws.onopen = () => {
                    console.log('Connected to dashboard server');
                    document.getElementById('connectionStatus').textContent = 'Connected';
                    document.getElementById('connectionStatus').className = 'connection-status connected';
                    this.reconnectAttempts = 0;
                    
                    // Subscribe to all chart updates
                    this.ws.send(JSON.stringify({
                        type: 'subscribe',
                        topics: ['chart_cpu_usage', 'chart_memory_usage', 'chart_response_times', 'chart_expert_performance', 'chart_system_health', 'system_status']
                    }));
                };
                
                this.ws.onmessage = (event) => {
                    try {
                        const message = JSON.parse(event.data);
                        this.handleMessage(message);
                    } catch (error) {
                        console.error('Error parsing message:', error);
                    }
                };
                
                this.ws.onclose = () => {
                    console.log('Disconnected from dashboard server');
                    document.getElementById('connectionStatus').textContent = 'Disconnected';
                    document.getElementById('connectionStatus').className = 'connection-status disconnected';
                    
                    // Attempt reconnection
                    if (this.reconnectAttempts < this.maxReconnectAttempts) {
                        this.reconnectAttempts++;
                        setTimeout(() => this.connect(), this.reconnectDelay * this.reconnectAttempts);
                    }
                };
                
                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };
            }
            
            handleMessage(message) {
                switch (message.type) {
                    case 'chart_update':
                        this.updateChart(message.data);
                        break;
                    case 'system_status':
                        this.updateSystemStatus(message.data);
                        break;
                    case 'dashboard_config':
                        this.initializeDashboard(message.data);
                        break;
                }
            }
            
            initializeCharts() {
                // System Chart (CPU & Memory)
                const systemCtx = document.getElementById('systemChart').getContext('2d');
                this.charts.system = new Chart(systemCtx, {
                    type: 'line',
                    data: {
                        datasets: [
                            {
                                label: 'CPU Usage %',
                                data: [],
                                borderColor: '#ff6b6b',
                                backgroundColor: 'rgba(255, 107, 107, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Memory Usage %',
                                data: [],
                                borderColor: '#4ecdc4',
                                backgroundColor: 'rgba(78, 205, 196, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#ffffff' } } },
                        scales: {
                            x: { 
                                type: 'time',
                                ticks: { color: '#ffffff' },
                                grid: { color: '#444444' }
                            },
                            y: { 
                                min: 0, max: 100,
                                ticks: { color: '#ffffff' },
                                grid: { color: '#444444' }
                            }
                        }
                    }
                });
                
                // Performance Chart
                const perfCtx = document.getElementById('performanceChart').getContext('2d');
                this.charts.performance = new Chart(perfCtx, {
                    type: 'line',
                    data: {
                        datasets: [
                            {
                                label: 'Response Time (ms)',
                                data: [],
                                borderColor: '#6c5ce7',
                                backgroundColor: 'rgba(108, 92, 231, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#ffffff' } } },
                        scales: {
                            x: { 
                                type: 'time',
                                ticks: { color: '#ffffff' },
                                grid: { color: '#444444' }
                            },
                            y: { 
                                min: 0,
                                ticks: { color: '#ffffff' },
                                grid: { color: '#444444' }
                            }
                        }
                    }
                });
                
                // Expert Performance Chart
                const expertCtx = document.getElementById('expertChart').getContext('2d');
                this.charts.expert = new Chart(expertCtx, {
                    type: 'bar',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Requests/min',
                            data: [],
                            backgroundColor: ['#00b894', '#e17055', '#0984e3', '#6c5ce7']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#ffffff' } } },
                        scales: {
                            x: { ticks: { color: '#ffffff' }, grid: { color: '#444444' } },
                            y: { ticks: { color: '#ffffff' }, grid: { color: '#444444' } }
                        }
                    }
                });
                
                // Resource Chart
                const resourceCtx = document.getElementById('resourceChart').getContext('2d');
                this.charts.resource = new Chart(resourceCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['CPU', 'Memory', 'Disk', 'Network'],
                        datasets: [{
                            data: [0, 0, 0, 0],
                            backgroundColor: ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#ffffff' } } }
                    }
                });
            }
            
            updateChart(chartData) {
                const chartId = chartData.chart_id;
                
                if (chartId === 'cpu_usage' || chartId === 'memory_usage') {
                    this.updateSystemChart(chartData);
                } else if (chartId === 'response_times') {
                    this.updatePerformanceChart(chartData);
                } else if (chartId === 'expert_performance') {
                    this.updateExpertChart(chartData);
                } else if (chartId === 'system_health') {
                    this.updateHealthScore(chartData);
                }
            }
            
            updateSystemChart(chartData) {
                const chart = this.charts.system;
                const datasetIndex = chartData.chart_id === 'cpu_usage' ? 0 : 1;
                
                chart.data.datasets[datasetIndex].data = chartData.data.map(point => ({
                    x: new Date(point.x),
                    y: point.y
                }));
                
                chart.update('none');
            }
            
            updatePerformanceChart(chartData) {
                const chart = this.charts.performance;
                
                chart.data.datasets[0].data = chartData.data.map(point => ({
                    x: new Date(point.x),
                    y: point.y
                }));
                
                chart.update('none');
            }
            
            updateExpertChart(chartData) {
                const chart = this.charts.expert;
                
                chart.data.labels = chartData.data.map(point => point.category);
                chart.data.datasets[0].data = chartData.data.map(point => point.y);
                
                chart.update('none');
            }
            
            updateHealthScore(chartData) {
                if (chartData.data.length > 0) {
                    const healthScore = (chartData.data[0].value * 100).toFixed(1);
                    document.getElementById('healthScore').textContent = healthScore + '%';
                }
            }
            
            updateSystemStatus(statusData) {
                // Update connection stats, error rates, etc.
                console.log('System status:', statusData);
            }
        }
        
        // Initialize dashboard when page loads
        document.addEventListener('DOMContentLoaded', () => {
            new DashboardManager();
        });
    </script>
</body>
</html>
"""

# Example usage and testing
async def main():
    """Example usage of the dashboard server"""
    
    # Create monitoring system
    monitoring_system = IntegratedMonitoringSystem()
    
    # Create dashboard server
    dashboard_config = DashboardConfig(
        host="localhost",
        port=8765,
        update_interval=1.0
    )
    
    dashboard = DashboardServer(dashboard_config, monitoring_system)
    
    try:
        # Start systems
        monitoring_system.start()
        await dashboard.start()
        
        logger.info("Dashboard server running. Open http://localhost:8765 in your browser")
        logger.info("WebSocket endpoint: ws://localhost:8765")
        
        # Create simple HTTP server for the dashboard HTML
        from aiohttp import web
        
        async def serve_dashboard(request):
            return web.Response(text=DASHBOARD_HTML, content_type='text/html')
        
        app = web.Application()
        app.router.add_get('/', serve_dashboard)
        
        http_runner = web.AppRunner(app)
        await http_runner.setup()
        
        http_site = web.TCPSite(http_runner, 'localhost', 8080)
        await http_site.start()
        
        logger.info("Dashboard available at: http://localhost:8080")
        
        # Run for demonstration
        await asyncio.sleep(300)  # Run for 5 minutes
        
        # Print server stats
        stats = dashboard.get_server_stats()
        print("\n=== Dashboard Server Statistics ===")
        print(json.dumps(stats, indent=2, default=str))
    
    finally:
        await dashboard.stop()
        monitoring_system.stop()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())