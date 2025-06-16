"""
Memory Alerts - Multi-level alerting system for memory monitoring.

This module provides comprehensive memory alerting capabilities including:
- Multi-level alert thresholds (Warning, High, Critical, Emergency)
- Predictive alerting based on memory trends
- Component-specific alerts
- Integration with external alerting systems
- Alert suppression and escalation
"""

import asyncio
import time
import json
from typing import Dict, List, Set, Optional, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging
import aiohttp
from prometheus_client import Counter, Histogram

from ..core.logging_config import get_logger
from ..core.exceptions import MonitoringError
from .memory_monitor import MemoryMonitor, MemorySnapshot, MemoryTrend, get_memory_monitor

__all__ = [
    "AlertLevel",
    "AlertType",
    "AlertRule",
    "MemoryAlert",
    "MemoryAlertManager"
]


logger = get_logger(__name__)

# Prometheus metrics for alerts
memory_alerts_fired_counter = Counter(
    'memory_alerts_fired_total',
    'Total number of memory alerts fired',
    ['alert_level', 'component', 'alert_type']
)

memory_alert_resolution_time_histogram = Histogram(
    'memory_alert_resolution_seconds',
    'Time taken to resolve memory alerts',
    ['alert_level', 'component']
)


class AlertLevel(Enum):
    """Memory alert severity levels."""
    WARNING = 1
    HIGH = 2
    CRITICAL = 3
    EMERGENCY = 4


class AlertType(Enum):
    """Types of memory alerts."""
    THRESHOLD = "threshold"
    TREND = "trend"
    COMPONENT = "component"
    PREDICTION = "prediction"


@dataclass
class AlertRule:
    """Configuration for a memory alert rule."""
    name: str
    level: AlertLevel
    alert_type: AlertType
    threshold: float
    component: Optional[str] = None
    enabled: bool = True
    suppression_duration: int = 300  # seconds
    evaluation_window: int = 60  # seconds
    min_samples: int = 3
    
    # Prediction-specific settings
    prediction_window: int = 900  # 15 minutes
    confidence_threshold: float = 0.8


@dataclass
class MemoryAlert:
    """Represents a fired memory alert."""
    id: str
    rule: AlertRule
    level: AlertLevel
    message: str
    timestamp: datetime
    component: Optional[str] = None
    current_value: float = 0.0
    predicted_value: Optional[float] = None
    time_to_threshold: Optional[float] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    suppressed: bool = False
    escalated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class MemoryAlertManager:
    """Manages memory alerts and notifications."""
    
    def __init__(
        self,
        memory_monitor: Optional[MemoryMonitor] = None,
        webhook_urls: Optional[List[str]] = None,
        alert_rules: Optional[List[AlertRule]] = None
    ):
        self.memory_monitor = memory_monitor or get_memory_monitor()
        self.webhook_urls = webhook_urls or []
        
        # Alert state
        self.active_alerts: Dict[str, MemoryAlert] = {}
        self.suppressed_alerts: Set[str] = set()
        self.alert_history: List[MemoryAlert] = []
        
        # Notification handlers
        self.notification_handlers: List[Callable[[MemoryAlert], None]] = []
        
        # Default alert rules
        self.alert_rules = alert_rules or self._create_default_rules()
        
        # Evaluation state
        self._evaluating = False
        self._evaluation_task: Optional[asyncio.Task] = None
    
    def _create_default_rules(self) -> List[AlertRule]:
        """Create default memory alert rules."""
        return [
            # System-wide threshold alerts
            AlertRule(
                name="system_memory_warning",
                level=AlertLevel.WARNING,
                alert_type=AlertType.THRESHOLD,
                threshold=70.0,
                suppression_duration=300
            ),
            AlertRule(
                name="system_memory_high",
                level=AlertLevel.HIGH,
                alert_type=AlertType.THRESHOLD,
                threshold=80.0,
                suppression_duration=180
            ),
            AlertRule(
                name="system_memory_critical",
                level=AlertLevel.CRITICAL,
                alert_type=AlertType.THRESHOLD,
                threshold=90.0,
                suppression_duration=60
            ),
            AlertRule(
                name="system_memory_emergency",
                level=AlertLevel.EMERGENCY,
                alert_type=AlertType.THRESHOLD,
                threshold=95.0,
                suppression_duration=30
            ),
            
            # Trend-based alerts
            AlertRule(
                name="memory_increasing_rapidly",
                level=AlertLevel.HIGH,
                alert_type=AlertType.TREND,
                threshold=1.0,  # 1 MB/s increase
                evaluation_window=300,
                suppression_duration=600
            ),
            
            # Predictive alerts
            AlertRule(
                name="memory_exhaustion_predicted",
                level=AlertLevel.CRITICAL,
                alert_type=AlertType.PREDICTION,
                threshold=900.0,  # 15 minutes to exhaustion
                prediction_window=900,
                suppression_duration=1800
            ),
            
            # Component-specific alerts
            AlertRule(
                name="circle_of_experts_memory_high",
                level=AlertLevel.HIGH,
                alert_type=AlertType.COMPONENT,
                threshold=1073741824,  # 1GB
                component="circle_of_experts",
                suppression_duration=300
            ),
            AlertRule(
                name="mcp_servers_memory_high",
                level=AlertLevel.HIGH,
                alert_type=AlertType.COMPONENT,
                threshold=536870912,  # 512MB
                component="mcp_servers",
                suppression_duration=300
            )
        ]
    
    async def start(self) -> None:
        """Start the alert evaluation loop."""
        if self._evaluating:
            logger.warning("Memory alert manager already started")
            return
        
        self._evaluating = True
        self._evaluation_task = asyncio.create_task(self._evaluation_loop())
        logger.info("Memory alert manager started")
    
    async def stop(self) -> None:
        """Stop the alert evaluation loop."""
        if not self._evaluating:
            return
        
        self._evaluating = False
        if self._evaluation_task:
            self._evaluation_task.cancel()
            try:
                await self._evaluation_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Memory alert manager stopped")
    
    async def _evaluation_loop(self) -> None:
        """Main alert evaluation loop."""
        while self._evaluating:
            try:
                await self._evaluate_alerts()
                await self._check_alert_resolution()
                await self._cleanup_old_alerts()
                await asyncio.sleep(10)  # Evaluate every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in alert evaluation loop: {e}")
                await asyncio.sleep(10)
    
    async def _evaluate_alerts(self) -> None:
        """Evaluate all alert rules against current state."""
        snapshot = self.memory_monitor.get_current_snapshot()
        if not snapshot:
            return
        
        trend = self.memory_monitor.get_memory_trend()
        
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            
            try:
                should_fire = await self._evaluate_rule(rule, snapshot, trend)
                if should_fire:
                    await self._fire_alert(rule, snapshot, trend)
                    
            except Exception as e:
                logger.error(f"Error evaluating alert rule {rule.name}: {e}")
    
    async def _evaluate_rule(
        self,
        rule: AlertRule,
        snapshot: MemorySnapshot,
        trend: MemoryTrend
    ) -> bool:
        """Evaluate a single alert rule."""
        alert_id = self._get_alert_id(rule)
        
        # Check if alert is already active or suppressed
        if alert_id in self.active_alerts or alert_id in self.suppressed_alerts:
            return False
        
        if rule.alert_type == AlertType.THRESHOLD:
            return await self._evaluate_threshold_rule(rule, snapshot)
        elif rule.alert_type == AlertType.TREND:
            return await self._evaluate_trend_rule(rule, trend)
        elif rule.alert_type == AlertType.COMPONENT:
            return await self._evaluate_component_rule(rule, snapshot)
        elif rule.alert_type == AlertType.PREDICTION:
            return await self._evaluate_prediction_rule(rule, trend)
        
        return False
    
    async def _evaluate_threshold_rule(
        self,
        rule: AlertRule,
        snapshot: MemorySnapshot
    ) -> bool:
        """Evaluate threshold-based alert rule."""
        current_value = snapshot.percent_used
        return current_value >= rule.threshold
    
    async def _evaluate_trend_rule(
        self,
        rule: AlertRule,
        trend: MemoryTrend
    ) -> bool:
        """Evaluate trend-based alert rule."""
        if trend.trend_direction != 'increasing':
            return False
        
        # Check if rate of change exceeds threshold
        return trend.rate_of_change >= rule.threshold
    
    async def _evaluate_component_rule(
        self,
        rule: AlertRule,
        snapshot: MemorySnapshot
    ) -> bool:
        """Evaluate component-specific alert rule."""
        if not rule.component:
            return False
        
        component_usage = snapshot.component_usage.get(rule.component, 0)
        return component_usage >= rule.threshold
    
    async def _evaluate_prediction_rule(
        self,
        rule: AlertRule,
        trend: MemoryTrend
    ) -> bool:
        """Evaluate prediction-based alert rule."""
        if trend.time_to_threshold is None:
            return False
        
        # Fire if time to threshold is less than rule threshold
        return trend.time_to_threshold <= rule.threshold
    
    async def _fire_alert(
        self,
        rule: AlertRule,
        snapshot: MemorySnapshot,
        trend: MemoryTrend
    ) -> None:
        """Fire a memory alert."""
        alert_id = self._get_alert_id(rule)
        
        # Create alert message
        message = self._create_alert_message(rule, snapshot, trend)
        
        alert = MemoryAlert(
            id=alert_id,
            rule=rule,
            level=rule.level,
            message=message,
            timestamp=datetime.now(),
            component=rule.component,
            current_value=snapshot.percent_used,
            predicted_value=trend.predicted_peak,
            time_to_threshold=trend.time_to_threshold,
            metadata={
                'snapshot': {
                    'total_memory': snapshot.total_memory,
                    'used_memory': snapshot.used_memory,
                    'available_memory': snapshot.available_memory,
                    'pressure_level': snapshot.pressure_level
                },
                'trend': {
                    'direction': trend.trend_direction,
                    'rate_of_change': trend.rate_of_change
                }
            }
        )
        
        # Store alert
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Update metrics
        memory_alerts_fired_counter.labels(
            alert_level=rule.level.name.lower(),
            component=rule.component or 'system',
            alert_type=rule.alert_type.value
        ).inc()
        
        # Send notifications
        await self._send_notifications(alert)
        
        # Add to suppression list
        self.suppressed_alerts.add(alert_id)
        asyncio.create_task(self._remove_suppression(alert_id, rule.suppression_duration))
        
        logger.warning(f"Memory alert fired: {message}")
    
    def _create_alert_message(
        self,
        rule: AlertRule,
        snapshot: MemorySnapshot,
        trend: MemoryTrend
    ) -> str:
        """Create human-readable alert message."""
        if rule.alert_type == AlertType.THRESHOLD:
            return (
                f"Memory usage {rule.level.name}: {snapshot.percent_used:.1f}% "
                f"(threshold: {rule.threshold}%)"
            )
        elif rule.alert_type == AlertType.TREND:
            return (
                f"Memory increasing rapidly: {trend.rate_of_change:.2f} MB/s "
                f"(threshold: {rule.threshold} MB/s)"
            )
        elif rule.alert_type == AlertType.COMPONENT:
            component_mb = snapshot.component_usage.get(rule.component, 0) / (1024 * 1024)
            threshold_mb = rule.threshold / (1024 * 1024)
            return (
                f"Component {rule.component} memory {rule.level.name}: "
                f"{component_mb:.1f}MB (threshold: {threshold_mb:.1f}MB)"
            )
        elif rule.alert_type == AlertType.PREDICTION:
            minutes_to_threshold = (trend.time_to_threshold or 0) / 60
            return (
                f"Memory exhaustion predicted in {minutes_to_threshold:.1f} minutes "
                f"(predicted peak: {trend.predicted_peak:.1f}%)"
            )
        
        return f"Memory alert: {rule.name}"
    
    async def _send_notifications(self, alert: MemoryAlert) -> None:
        """Send alert notifications to configured channels."""
        # Call registered handlers
        for handler in self.notification_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in notification handler: {e}")
        
        # Send webhook notifications
        if self.webhook_urls:
            await self._send_webhook_notifications(alert)
    
    async def _send_webhook_notifications(self, alert: MemoryAlert) -> None:
        """Send webhook notifications for alert."""
        payload = {
            'alert_id': alert.id,
            'level': alert.level.name,
            'message': alert.message,
            'timestamp': alert.timestamp.isoformat(),
            'component': alert.component,
            'current_value': alert.current_value,
            'predicted_value': alert.predicted_value,
            'time_to_threshold': alert.time_to_threshold,
            'metadata': alert.metadata
        }
        
        async with aiohttp.ClientSession() as session:
            for url in self.webhook_urls:
                try:
                    async with session.post(
                        url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            logger.info(f"Webhook notification sent to {url}")
                        else:
                            logger.warning(f"Webhook notification failed: {response.status}")
                            
                except Exception as e:
                    logger.error(f"Error sending webhook to {url}: {e}")
    
    async def _check_alert_resolution(self) -> None:
        """Check if active alerts should be resolved."""
        snapshot = self.memory_monitor.get_current_snapshot()
        if not snapshot:
            return
        
        resolved_alerts = []
        
        for alert_id, alert in self.active_alerts.items():
            if self._should_resolve_alert(alert, snapshot):
                alert.resolved = True
                alert.resolved_at = datetime.now()
                resolved_alerts.append(alert_id)
                
                # Update resolution time metric
                resolution_time = (alert.resolved_at - alert.timestamp).total_seconds()
                memory_alert_resolution_time_histogram.labels(
                    alert_level=alert.level.name.lower(),
                    component=alert.component or 'system'
                ).observe(resolution_time)
                
                logger.info(f"Memory alert resolved: {alert.message}")
        
        # Remove resolved alerts
        for alert_id in resolved_alerts:
            del self.active_alerts[alert_id]
    
    def _should_resolve_alert(self, alert: MemoryAlert, snapshot: MemorySnapshot) -> bool:
        """Determine if an alert should be resolved."""
        rule = alert.rule
        
        if rule.alert_type == AlertType.THRESHOLD:
            # Resolve when usage drops below threshold with hysteresis
            hysteresis = rule.threshold * 0.9  # 10% hysteresis
            return snapshot.percent_used < hysteresis
        elif rule.alert_type == AlertType.COMPONENT:
            component_usage = snapshot.component_usage.get(rule.component, 0)
            hysteresis = rule.threshold * 0.9
            return component_usage < hysteresis
        
        # For trend and prediction alerts, resolve after fixed time
        time_since_alert = (datetime.now() - alert.timestamp).total_seconds()
        return time_since_alert > 300  # 5 minutes
    
    async def _remove_suppression(self, alert_id: str, delay: int) -> None:
        """Remove alert from suppression list after delay."""
        await asyncio.sleep(delay)
        self.suppressed_alerts.discard(alert_id)
    
    async def _cleanup_old_alerts(self) -> None:
        """Clean up old alerts from history."""
        cutoff = datetime.now() - timedelta(hours=24)
        self.alert_history = [
            alert for alert in self.alert_history
            if alert.timestamp > cutoff
        ]
    
    def _get_alert_id(self, rule: AlertRule) -> str:
        """Generate unique alert ID for rule."""
        if rule.component:
            return f"{rule.name}_{rule.component}"
        return rule.name
    
    def add_notification_handler(self, handler: Callable[[MemoryAlert], None]) -> None:
        """Add a custom notification handler."""
        self.notification_handlers.append(handler)
    
    def add_webhook_url(self, url: str) -> None:
        """Add a webhook URL for notifications."""
        if url not in self.webhook_urls:
            self.webhook_urls.append(url)
    
    def get_active_alerts(self) -> List[MemoryAlert]:
        """Get list of currently active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_history(self, hours: int = 24) -> List[MemoryAlert]:
        """Get alert history for specified hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            alert for alert in self.alert_history
            if alert.timestamp > cutoff
        ]
    
    def add_alert_rule(self, rule: AlertRule) -> None:
        """Add a custom alert rule."""
        self.alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_name: str) -> bool:
        """Remove an alert rule by name."""
        for i, rule in enumerate(self.alert_rules):
            if rule.name == rule_name:
                del self.alert_rules[i]
                logger.info(f"Removed alert rule: {rule_name}")
                return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable an alert rule."""
        for rule in self.alert_rules:
            if rule.name == rule_name:
                rule.enabled = True
                logger.info(f"Enabled alert rule: {rule_name}")
                return True
        return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable an alert rule."""
        for rule in self.alert_rules:
            if rule.name == rule_name:
                rule.enabled = False
                logger.info(f"Disabled alert rule: {rule_name}")
                return True
        return False


# Global alert manager instance
_alert_manager: Optional[MemoryAlertManager] = None


async def get_alert_manager() -> MemoryAlertManager:
    """Get or create the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = MemoryAlertManager()
        await _alert_manager.start()
    return _alert_manager


async def shutdown_alert_manager() -> None:
    """Shutdown the global alert manager."""
    global _alert_manager
    if _alert_manager is not None:
        await _alert_manager.stop()
        _alert_manager = None