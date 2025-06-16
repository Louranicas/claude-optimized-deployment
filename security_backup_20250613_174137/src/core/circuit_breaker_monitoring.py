"""
Comprehensive monitoring and alerting system for circuit breakers.

This module provides:
- Real-time metrics collection
- Alert management and notifications
- Dashboard data aggregation
- Performance analytics
- Health scoring
- Trend analysis
- Anomaly detection
- Automated reporting
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
import json
import statistics
from abc import ABC, abstractmethod

from src.core.circuit_breaker_standard import (
    StandardizedCircuitBreaker,
    get_all_standardized_breakers
)
from src.core.circuit_breaker_database import get_database_circuit_breaker_manager
from src.core.circuit_breaker_mcp import get_mcp_circuit_breaker_manager

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of alerts."""
    CIRCUIT_OPEN = "circuit_open"
    HIGH_FAILURE_RATE = "high_failure_rate"
    SLOW_RESPONSE = "slow_response"
    HEALTH_DEGRADED = "health_degraded"
    CONNECTION_LOST = "connection_lost"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    ANOMALY_DETECTED = "anomaly_detected"


@dataclass
class Alert:
    """Circuit breaker alert."""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    service_name: str
    service_category: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    resolved: bool = False
    resolved_timestamp: Optional[datetime] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_timestamp: Optional[datetime] = None


@dataclass
class MetricSnapshot:
    """Point-in-time metrics snapshot."""
    timestamp: datetime
    service_name: str
    service_category: str
    total_calls: int
    successful_calls: int
    failed_calls: int
    rejected_calls: int
    failure_rate: float
    average_response_time: float
    circuit_state: str
    health_score: float
    active_connections: int = 0
    queue_depth: int = 0


@dataclass
class HealthScore:
    """Service health score calculation."""
    overall_score: float
    availability_score: float
    performance_score: float
    reliability_score: float
    factors: Dict[str, float]
    last_updated: datetime


@dataclass
class AlertRule:
    """Alert rule configuration."""
    name: str
    alert_type: AlertType
    severity: AlertSeverity
    condition: Callable[[MetricSnapshot], bool]
    cooldown_minutes: int = 30
    service_patterns: Optional[List[str]] = None
    enabled: bool = True


class MetricsCollector:
    """Collects metrics from all circuit breakers."""
    
    def __init__(self, collection_interval: float = 30.0):
        """Initialize metrics collector."""
        self.collection_interval = collection_interval
        self._metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2880))  # 24 hours at 30s intervals
        self._latest_metrics: Dict[str, MetricSnapshot] = {}
        self._collection_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start_collection(self):
        """Start metrics collection."""
        if self._running:
            return
        
        self._running = True
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Started circuit breaker metrics collection")
    
    async def stop_collection(self):
        """Stop metrics collection."""
        self._running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped circuit breaker metrics collection")
    
    async def _collection_loop(self):
        """Main metrics collection loop."""
        while self._running:
            try:
                await self._collect_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_metrics(self):
        """Collect metrics from all circuit breakers."""
        timestamp = datetime.now()
        
        # Collect from standardized circuit breakers
        try:
            standardized_breakers = get_all_standardized_breakers()
            for name, breaker in standardized_breakers.items():
                try:
                    metrics = breaker.get_metrics()
                    snapshot = self._create_snapshot(name, metrics, timestamp)
                    self._store_snapshot(snapshot)
                except Exception as e:
                    logger.error(f"Error collecting metrics from standardized breaker '{name}': {e}")
        except Exception as e:
            logger.debug(f"No standardized circuit breakers available: {e}")
        
        # Collect from database circuit breakers
        try:
            db_manager = get_database_circuit_breaker_manager()
            db_metrics = db_manager.get_all_metrics()
            for db_name, metrics in db_metrics.items():
                snapshot = self._create_db_snapshot(db_name, metrics, timestamp)
                self._store_snapshot(snapshot)
        except Exception as e:
            logger.debug(f"Error collecting database circuit breaker metrics: {e}")
        
        # Collect from MCP circuit breakers
        try:
            mcp_manager = get_mcp_circuit_breaker_manager()
            mcp_metrics = mcp_manager.get_all_metrics()
            for server_name, metrics in mcp_metrics.items():
                snapshot = self._create_mcp_snapshot(server_name, metrics, timestamp)
                self._store_snapshot(snapshot)
        except Exception as e:
            logger.debug(f"Error collecting MCP circuit breaker metrics: {e}")
    
    def _create_snapshot(self, name: str, metrics: Dict[str, Any], timestamp: datetime) -> MetricSnapshot:
        """Create metrics snapshot from standardized breaker metrics."""
        return MetricSnapshot(
            timestamp=timestamp,
            service_name=name,
            service_category=metrics.get('service_category', 'unknown'),
            total_calls=metrics.get('total_calls', 0),
            successful_calls=metrics.get('successful_calls', 0),
            failed_calls=metrics.get('failed_calls', 0),
            rejected_calls=metrics.get('rejected_calls', 0),
            failure_rate=metrics.get('failed_calls', 0) / max(1, metrics.get('total_calls', 1)),
            average_response_time=0.0,  # Would need to be calculated from metrics
            circuit_state=metrics.get('state', 'unknown'),
            health_score=metrics.get('health_score', 0.0),
            active_connections=0,
            queue_depth=0
        )
    
    def _create_db_snapshot(self, db_name: str, metrics: Dict[str, Any], timestamp: datetime) -> MetricSnapshot:
        """Create metrics snapshot from database breaker metrics."""
        connection_metrics = metrics.get('connection_metrics', {})
        query_metrics = metrics.get('query_metrics', {})
        
        total_calls = query_metrics.get('total_queries', 0)
        failed_calls = query_metrics.get('failed_queries', 0)
        
        return MetricSnapshot(
            timestamp=timestamp,
            service_name=db_name,
            service_category='database',
            total_calls=total_calls,
            successful_calls=query_metrics.get('successful_queries', 0),
            failed_calls=failed_calls,
            rejected_calls=0,
            failure_rate=failed_calls / max(1, total_calls),
            average_response_time=query_metrics.get('average_query_time', 0.0),
            circuit_state='closed',  # Would need to be extracted from circuit_breakers
            health_score=1.0 if metrics.get('is_healthy', False) else 0.0,
            active_connections=connection_metrics.get('active_connections', 0),
            queue_depth=0
        )
    
    def _create_mcp_snapshot(self, server_name: str, metrics: Dict[str, Any], timestamp: datetime) -> MetricSnapshot:
        """Create metrics snapshot from MCP breaker metrics."""
        mcp_metrics = metrics.get('mcp_metrics', {})
        
        total_calls = (
            mcp_metrics.get('tool_invocations', 0) +
            mcp_metrics.get('resource_accesses', 0) +
            mcp_metrics.get('message_count', 0)
        )
        
        failed_calls = (
            mcp_metrics.get('failed_tools', 0) +
            mcp_metrics.get('failed_resources', 0) +
            mcp_metrics.get('message_failures', 0)
        )
        
        return MetricSnapshot(
            timestamp=timestamp,
            service_name=server_name,
            service_category='mcp',
            total_calls=total_calls,
            successful_calls=total_calls - failed_calls,
            failed_calls=failed_calls,
            rejected_calls=0,
            failure_rate=failed_calls / max(1, total_calls),
            average_response_time=mcp_metrics.get('average_response_time', 0.0),
            circuit_state='closed',  # Would need to be extracted
            health_score=1.0,  # Would need to be calculated
            active_connections=mcp_metrics.get('active_connections', 0),
            queue_depth=0
        )
    
    def _store_snapshot(self, snapshot: MetricSnapshot):
        """Store metrics snapshot."""
        service_key = f"{snapshot.service_category}_{snapshot.service_name}"
        self._metrics_history[service_key].append(snapshot)
        self._latest_metrics[service_key] = snapshot
    
    def get_latest_metrics(self) -> Dict[str, MetricSnapshot]:
        """Get latest metrics for all services."""
        return dict(self._latest_metrics)
    
    def get_metrics_history(
        self,
        service_name: str,
        service_category: str,
        duration_minutes: int = 60
    ) -> List[MetricSnapshot]:
        """Get metrics history for a specific service."""
        service_key = f"{service_category}_{service_name}"
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        
        history = self._metrics_history.get(service_key, deque())
        return [
            snapshot for snapshot in history
            if snapshot.timestamp >= cutoff_time
        ]
    
    def get_aggregated_metrics(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get aggregated metrics across all services."""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        
        total_calls = 0
        total_failures = 0
        total_services = len(self._latest_metrics)
        healthy_services = 0
        open_circuits = []
        
        for service_key, latest in self._latest_metrics.items():
            if latest.timestamp >= cutoff_time:
                total_calls += latest.total_calls
                total_failures += latest.failed_calls
                
                if latest.health_score > 0.7:
                    healthy_services += 1
                
                if latest.circuit_state == 'open':
                    open_circuits.append(service_key)
        
        return {
            'total_services': total_services,
            'healthy_services': healthy_services,
            'total_calls': total_calls,
            'total_failures': total_failures,
            'overall_failure_rate': total_failures / max(1, total_calls),
            'open_circuits': open_circuits,
            'health_percentage': healthy_services / max(1, total_services) * 100
        }


class AlertManager:
    """Manages circuit breaker alerts and notifications."""
    
    def __init__(self):
        """Initialize alert manager."""
        self._alert_rules: List[AlertRule] = []
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: deque = deque(maxlen=10000)
        self._cooldown_tracker: Dict[str, datetime] = {}
        self._notification_handlers: List[Callable[[Alert], None]] = []
        
        # Set up default alert rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Set up default alert rules."""
        self._alert_rules = [
            AlertRule(
                name="circuit_open",
                alert_type=AlertType.CIRCUIT_OPEN,
                severity=AlertSeverity.HIGH,
                condition=lambda m: m.circuit_state == 'open',
                cooldown_minutes=15
            ),
            AlertRule(
                name="high_failure_rate",
                alert_type=AlertType.HIGH_FAILURE_RATE,
                severity=AlertSeverity.MEDIUM,
                condition=lambda m: m.failure_rate > 0.5 and m.total_calls > 10,
                cooldown_minutes=30
            ),
            AlertRule(
                name="slow_response",
                alert_type=AlertType.SLOW_RESPONSE,
                severity=AlertSeverity.MEDIUM,
                condition=lambda m: m.average_response_time > 5.0,
                cooldown_minutes=60
            ),
            AlertRule(
                name="health_degraded",
                alert_type=AlertType.HEALTH_DEGRADED,
                severity=AlertSeverity.MEDIUM,
                condition=lambda m: m.health_score < 0.5,
                cooldown_minutes=45
            ),
            AlertRule(
                name="critical_failure_rate",
                alert_type=AlertType.HIGH_FAILURE_RATE,
                severity=AlertSeverity.CRITICAL,
                condition=lambda m: m.failure_rate > 0.8 and m.total_calls > 5,
                cooldown_minutes=10
            )
        ]
    
    def add_alert_rule(self, rule: AlertRule):
        """Add a custom alert rule."""
        self._alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def add_notification_handler(self, handler: Callable[[Alert], None]):
        """Add a notification handler."""
        self._notification_handlers.append(handler)
    
    def process_metrics(self, metrics: Dict[str, MetricSnapshot]):
        """Process metrics and generate alerts."""
        for service_key, snapshot in metrics.items():
            self._check_alert_rules(snapshot)
    
    def _check_alert_rules(self, snapshot: MetricSnapshot):
        """Check alert rules against a metrics snapshot."""
        for rule in self._alert_rules:
            if not rule.enabled:
                continue
            
            # Check service patterns if specified
            if rule.service_patterns:
                matches_pattern = any(
                    pattern in snapshot.service_name or pattern in snapshot.service_category
                    for pattern in rule.service_patterns
                )
                if not matches_pattern:
                    continue
            
            # Check cooldown
            cooldown_key = f"{rule.name}_{snapshot.service_name}"
            if cooldown_key in self._cooldown_tracker:
                last_alert = self._cooldown_tracker[cooldown_key]
                if datetime.now() - last_alert < timedelta(minutes=rule.cooldown_minutes):
                    continue
            
            # Evaluate condition
            try:
                if rule.condition(snapshot):
                    self._create_alert(rule, snapshot)
                    self._cooldown_tracker[cooldown_key] = datetime.now()
            except Exception as e:
                logger.error(f"Error evaluating alert rule '{rule.name}': {e}")
    
    def _create_alert(self, rule: AlertRule, snapshot: MetricSnapshot):
        """Create an alert based on rule and snapshot."""
        alert_id = f"{rule.name}_{snapshot.service_name}_{int(time.time())}"
        
        alert = Alert(
            id=alert_id,
            alert_type=rule.alert_type,
            severity=rule.severity,
            service_name=snapshot.service_name,
            service_category=snapshot.service_category,
            message=self._generate_alert_message(rule, snapshot),
            details=asdict(snapshot),
            timestamp=datetime.now()
        )
        
        self._active_alerts[alert_id] = alert
        self._alert_history.append(alert)
        
        # Send notifications
        for handler in self._notification_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in notification handler: {e}")
        
        logger.warning(f"Alert created: {alert.message}")
    
    def _generate_alert_message(self, rule: AlertRule, snapshot: MetricSnapshot) -> str:
        """Generate alert message."""
        if rule.alert_type == AlertType.CIRCUIT_OPEN:
            return f"Circuit breaker is OPEN for service '{snapshot.service_name}'"
        elif rule.alert_type == AlertType.HIGH_FAILURE_RATE:
            return f"High failure rate ({snapshot.failure_rate:.1%}) for service '{snapshot.service_name}'"
        elif rule.alert_type == AlertType.SLOW_RESPONSE:
            return f"Slow response time ({snapshot.average_response_time:.2f}s) for service '{snapshot.service_name}'"
        elif rule.alert_type == AlertType.HEALTH_DEGRADED:
            return f"Health degraded (score: {snapshot.health_score:.2f}) for service '{snapshot.service_name}'"
        else:
            return f"Alert triggered for service '{snapshot.service_name}'"
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str):
        """Acknowledge an alert."""
        if alert_id in self._active_alerts:
            alert = self._active_alerts[alert_id]
            alert.acknowledged = True
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_timestamp = datetime.now()
            logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert."""
        if alert_id in self._active_alerts:
            alert = self._active_alerts[alert_id]
            alert.resolved = True
            alert.resolved_timestamp = datetime.now()
            del self._active_alerts[alert_id]
            logger.info(f"Alert {alert_id} resolved")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self._active_alerts.values())
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary."""
        active_by_severity = defaultdict(int)
        active_by_type = defaultdict(int)
        
        for alert in self._active_alerts.values():
            active_by_severity[alert.severity.value] += 1
            active_by_type[alert.alert_type.value] += 1
        
        return {
            'total_active': len(self._active_alerts),
            'by_severity': dict(active_by_severity),
            'by_type': dict(active_by_type),
            'total_history': len(self._alert_history)
        }


class HealthScoreCalculator:
    """Calculates health scores for services."""
    
    def calculate_health_score(self, snapshots: List[MetricSnapshot]) -> HealthScore:
        """Calculate health score from metrics snapshots."""
        if not snapshots:
            return HealthScore(
                overall_score=0.0,
                availability_score=0.0,
                performance_score=0.0,
                reliability_score=0.0,
                factors={},
                last_updated=datetime.now()
            )
        
        latest = snapshots[-1]
        
        # Calculate availability score (circuit state and uptime)
        availability_score = 1.0 if latest.circuit_state == 'closed' else 0.0
        if latest.circuit_state == 'half_open':
            availability_score = 0.5
        
        # Calculate performance score (response time)
        if latest.average_response_time <= 1.0:
            performance_score = 1.0
        elif latest.average_response_time <= 5.0:
            performance_score = 0.8
        elif latest.average_response_time <= 10.0:
            performance_score = 0.6
        else:
            performance_score = 0.4
        
        # Calculate reliability score (failure rate over time)
        if len(snapshots) > 1:
            recent_snapshots = snapshots[-10:]  # Last 10 snapshots
            failure_rates = [s.failure_rate for s in recent_snapshots]
            avg_failure_rate = statistics.mean(failure_rates)
            reliability_score = max(0.0, 1.0 - (avg_failure_rate * 2))
        else:
            reliability_score = max(0.0, 1.0 - latest.failure_rate)
        
        # Calculate overall score (weighted average)
        overall_score = (
            availability_score * 0.4 +
            performance_score * 0.3 +
            reliability_score * 0.3
        )
        
        factors = {
            'availability': availability_score,
            'performance': performance_score,
            'reliability': reliability_score,
            'circuit_state': latest.circuit_state,
            'failure_rate': latest.failure_rate,
            'response_time': latest.average_response_time
        }
        
        return HealthScore(
            overall_score=overall_score,
            availability_score=availability_score,
            performance_score=performance_score,
            reliability_score=reliability_score,
            factors=factors,
            last_updated=datetime.now()
        )


class CircuitBreakerMonitor:
    """Main monitoring orchestrator for circuit breakers."""
    
    def __init__(self, collection_interval: float = 30.0):
        """Initialize circuit breaker monitor."""
        self.metrics_collector = MetricsCollector(collection_interval)
        self.alert_manager = AlertManager()
        self.health_calculator = HealthScoreCalculator()
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Health scores cache
        self._health_scores: Dict[str, HealthScore] = {}
        
        # Set up default notification handlers
        self._setup_default_notifications()
    
    def _setup_default_notifications(self):
        """Set up default notification handlers."""
        def log_alert(alert: Alert):
            log_level = logging.WARNING
            if alert.severity == AlertSeverity.CRITICAL:
                log_level = logging.ERROR
            elif alert.severity == AlertSeverity.LOW:
                log_level = logging.INFO
            
            logger.log(log_level, f"ALERT [{alert.severity.value.upper()}] {alert.message}")
        
        self.alert_manager.add_notification_handler(log_alert)
    
    async def start(self):
        """Start the monitoring system."""
        if self._running:
            return
        
        self._running = True
        await self.metrics_collector.start_collection()
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Started circuit breaker monitoring system")
    
    async def stop(self):
        """Stop the monitoring system."""
        self._running = False
        await self.metrics_collector.stop_collection()
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped circuit breaker monitoring system")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                # Process alerts
                latest_metrics = self.metrics_collector.get_latest_metrics()
                self.alert_manager.process_metrics(latest_metrics)
                
                # Update health scores
                await self._update_health_scores()
                
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _update_health_scores(self):
        """Update health scores for all services."""
        latest_metrics = self.metrics_collector.get_latest_metrics()
        
        for service_key, latest_snapshot in latest_metrics.items():
            try:
                # Get historical data
                history = self.metrics_collector.get_metrics_history(
                    latest_snapshot.service_name,
                    latest_snapshot.service_category,
                    duration_minutes=120
                )
                
                # Calculate health score
                health_score = self.health_calculator.calculate_health_score(history)
                self._health_scores[service_key] = health_score
                
            except Exception as e:
                logger.error(f"Error calculating health score for {service_key}: {e}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data."""
        latest_metrics = self.metrics_collector.get_latest_metrics()
        aggregated = self.metrics_collector.get_aggregated_metrics()
        alert_summary = self.alert_manager.get_alert_summary()
        
        # Service details
        services = {}
        for service_key, snapshot in latest_metrics.items():
            health_score = self._health_scores.get(service_key)
            services[service_key] = {
                'snapshot': asdict(snapshot),
                'health_score': asdict(health_score) if health_score else None
            }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'overview': aggregated,
            'alerts': alert_summary,
            'services': services,
            'active_alerts': [asdict(alert) for alert in self.alert_manager.get_active_alerts()]
        }
    
    def add_custom_alert_rule(self, rule: AlertRule):
        """Add a custom alert rule."""
        self.alert_manager.add_alert_rule(rule)
    
    def add_notification_handler(self, handler: Callable[[Alert], None]):
        """Add a notification handler."""
        self.alert_manager.add_notification_handler(handler)


# Global monitoring instance
_monitor: Optional[CircuitBreakerMonitor] = None


def get_circuit_breaker_monitor() -> CircuitBreakerMonitor:
    """Get or create the global circuit breaker monitor."""
    global _monitor
    if _monitor is None:
        _monitor = CircuitBreakerMonitor()
    return _monitor


async def start_circuit_breaker_monitoring():
    """Start the global circuit breaker monitoring."""
    monitor = get_circuit_breaker_monitor()
    await monitor.start()


async def stop_circuit_breaker_monitoring():
    """Stop the global circuit breaker monitoring."""
    monitor = get_circuit_breaker_monitor()
    await monitor.stop()


# Export public API
__all__ = [
    'CircuitBreakerMonitor',
    'MetricsCollector',
    'AlertManager',
    'HealthScoreCalculator',
    'Alert',
    'AlertRule',
    'AlertSeverity',
    'AlertType',
    'MetricSnapshot',
    'HealthScore',
    'get_circuit_breaker_monitor',
    'start_circuit_breaker_monitoring',
    'stop_circuit_breaker_monitoring',
]