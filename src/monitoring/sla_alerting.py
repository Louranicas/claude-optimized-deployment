"""
SLA breach detection and alerting system.

Provides:
- Real-time SLA monitoring
- Breach detection with severity levels
- Alert routing and escalation
- Historical breach tracking
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging

from .sla import SLATracker, SLAReport, SLAObjective, get_sla_tracker
from .metrics import get_metrics_collector
from src.core.exceptions import ConfigurationError

__all__ = [
    "AlertSeverity",
    "SLAAlert",
    "AlertingRule",
    "SLAAlertManager",
    "get_sla_alert_manager"
]

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SLAAlert:
    """SLA alert representation."""
    id: str
    objective_name: str
    severity: AlertSeverity
    title: str
    description: str
    current_value: float
    target_value: float
    error_budget_remaining: float
    timestamp: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "objective_name": self.objective_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "current_value": self.current_value,
            "target_value": self.target_value,
            "error_budget_remaining": self.error_budget_remaining,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "metadata": self.metadata
        }


@dataclass
class AlertingRule:
    """Configuration for SLA alerting."""
    objective_name: str
    enabled: bool = True
    
    # Thresholds for different severity levels
    critical_threshold: float = 90.0  # SLA compliance %
    high_threshold: float = 95.0
    medium_threshold: float = 98.0
    
    # Error budget thresholds
    critical_budget_threshold: float = 5.0  # % remaining
    high_budget_threshold: float = 10.0
    medium_budget_threshold: float = 25.0
    
    # Alert suppression
    suppression_duration: timedelta = timedelta(minutes=15)
    escalation_duration: timedelta = timedelta(hours=1)
    
    # Notification channels
    notification_channels: List[str] = field(default_factory=lambda: ["default"])
    
    def get_severity_for_compliance(self, compliance: float, error_budget: float) -> Optional[AlertSeverity]:
        """Determine alert severity based on compliance and error budget."""
        if not self.enabled:
            return None
        
        # Critical conditions
        if (compliance < self.critical_threshold or 
            error_budget < self.critical_budget_threshold):
            return AlertSeverity.CRITICAL
        
        # High severity conditions
        if (compliance < self.high_threshold or 
            error_budget < self.high_budget_threshold):
            return AlertSeverity.HIGH
        
        # Medium severity conditions
        if (compliance < self.medium_threshold or 
            error_budget < self.medium_budget_threshold):
            return AlertSeverity.MEDIUM
        
        return None  # No alert needed


class SLAAlertManager:
    """Manages SLA alerts and notifications."""
    
    def __init__(self):
        self.sla_tracker = get_sla_tracker()
        self.metrics_collector = get_metrics_collector()
        self.alerting_rules: Dict[str, AlertingRule] = {}
        self.active_alerts: Dict[str, SLAAlert] = {}
        self.alert_history: List[SLAAlert] = []
        self.notification_handlers: Dict[str, Callable] = {}
        
        # Monitoring metrics
        from prometheus_client import Counter, Gauge, Histogram
        
        self.alerts_total = Counter(
            'sla_alerts_total',
            'Total SLA alerts generated',
            ['objective', 'severity']
        )
        
        self.active_alerts_gauge = Gauge(
            'sla_active_alerts',
            'Number of active SLA alerts',
            ['severity']
        )
        
        self.alert_duration = Histogram(
            'sla_alert_duration_seconds',
            'Duration of SLA alerts',
            ['objective', 'severity'],
            buckets=(60, 300, 900, 1800, 3600, 7200, 14400)
        )
        
        # Set up default alerting rules
        self._setup_default_rules()
        
        # Background monitoring task
        self._monitoring_task: Optional[asyncio.Task] = None
        self._is_running = False
    
    def _setup_default_rules(self):
        """Set up default alerting rules for all SLA objectives."""
        for objective_name in self.sla_tracker.objectives.keys():
            if objective_name not in self.alerting_rules:
                self.alerting_rules[objective_name] = AlertingRule(
                    objective_name=objective_name
                )
    
    def add_alerting_rule(self, rule: AlertingRule):
        \"\"\"Add or update an alerting rule.\"\"\"
        self.alerting_rules[rule.objective_name] = rule
        logger.info(f\"Added alerting rule for {rule.objective_name}\")
    
    def register_notification_handler(self, channel: str, handler: Callable[[SLAAlert], None]):
        \"\"\"Register a notification handler for a channel.\"\"\"
        self.notification_handlers[channel] = handler
        logger.info(f\"Registered notification handler for channel: {channel}\")
    
    async def check_all_slas(self) -> List[SLAAlert]:
        \"\"\"Check all SLA objectives and generate alerts.\"\"\"
        new_alerts = []
        
        try:
            # Get current SLA reports
            reports = await self.sla_tracker.check_all_objectives()
            
            for objective_name, report in reports.items():
                alerts = await self._process_sla_report(report)
                new_alerts.extend(alerts)
            
            # Update active alert metrics
            self._update_alert_metrics()
            
        except Exception as e:
            logger.error(f\"Error during SLA check: {e}\", exc_info=True)
        
        return new_alerts
    
    async def _process_sla_report(self, report: SLAReport) -> List[SLAAlert]:
        \"\"\"Process a single SLA report and generate alerts if needed.\"\"\"
        objective_name = report.objective.name
        rule = self.alerting_rules.get(objective_name)
        
        if not rule:
            return []
        
        # Determine if alert is needed
        severity = rule.get_severity_for_compliance(
            report.compliance_percent,
            report.error_budget_remaining
        )
        
        if not severity:
            # Check if we need to resolve an existing alert
            await self._maybe_resolve_alert(objective_name)
            return []
        
        # Check if alert should be suppressed
        existing_alert = self.active_alerts.get(objective_name)
        if existing_alert and self._should_suppress_alert(existing_alert, rule):
            return []
        
        # Create new alert or escalate existing one
        alert = await self._create_or_escalate_alert(report, severity, rule)
        
        if alert:
            return [alert]
        
        return []
    
    async def _create_or_escalate_alert(self,
                                      report: SLAReport,
                                      severity: AlertSeverity,
                                      rule: AlertingRule) -> Optional[SLAAlert]:
        \"\"\"Create a new alert or escalate an existing one.\"\"\"
        objective_name = report.objective.name
        existing_alert = self.active_alerts.get(objective_name)
        
        # If alert exists and severity hasn't changed significantly, don't create new
        if existing_alert and existing_alert.severity == severity:
            return None
        
        # Generate alert ID
        alert_id = f\"{objective_name}_{int(datetime.now().timestamp())}\"
        
        # Create alert description
        description = self._generate_alert_description(report, severity)
        
        # Create alert
        alert = SLAAlert(
            id=alert_id,
            objective_name=objective_name,
            severity=severity,
            title=f\"SLA {severity.value.upper()} - {objective_name}\",
            description=description,
            current_value=report.current_value,
            target_value=report.objective.target,
            error_budget_remaining=report.error_budget_remaining,
            timestamp=datetime.now(),
            metadata={
                \"objective_type\": report.objective.type.value,
                \"measurement_window\": str(report.objective.measurement_window),
                \"violations\": report.violations
            }
        )
        
        # Replace existing alert if escalating
        if existing_alert:
            await self._resolve_alert(objective_name, \"escalated\")
        
        # Store alert
        self.active_alerts[objective_name] = alert
        self.alert_history.append(alert)
        
        # Record metrics
        self.alerts_total.labels(
            objective=objective_name,
            severity=severity.value
        ).inc()
        
        # Send notifications
        await self._send_notifications(alert, rule)
        
        logger.warning(f\"SLA alert generated: {alert.title}\", extra={
            \"alert_id\": alert.id,
            \"severity\": severity.value,
            \"compliance\": report.compliance_percent,
            \"error_budget\": report.error_budget_remaining
        })
        
        return alert
    
    def _generate_alert_description(self, report: SLAReport, severity: AlertSeverity) -> str:
        \"\"\"Generate detailed alert description.\"\"\"
        objective = report.objective
        
        description = (
            f\"SLA '{objective.name}' is in {severity.value} state.\
\"
            f\"Type: {objective.type.value}\
\"
            f\"Current Value: {report.current_value:.2f}\
\"
            f\"Target: {objective.target}\
\"
            f\"Compliance: {report.compliance_percent:.2f}%\
\"
            f\"Error Budget Remaining: {report.error_budget_remaining:.2f}%\
\"
        )
        
        if objective.type.value == \"latency\":
            description += f\"Latency Threshold: {objective.latency_threshold_ms}ms\
\"
            description += f\"Percentile: {objective.latency_percentile * 100}th\
\"
        
        if report.violations:
            description += f\"\
Violations in measurement window: {len(report.violations)}\
\"
        
        return description
    
    async def _send_notifications(self, alert: SLAAlert, rule: AlertingRule):
        \"\"\"Send alert notifications to configured channels.\"\"\"
        for channel in rule.notification_channels:
            handler = self.notification_handlers.get(channel)
            if handler:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(alert)
                    else:
                        handler(alert)
                except Exception as e:
                    logger.error(f\"Failed to send notification to {channel}: {e}\")
            else:
                logger.warning(f\"No handler registered for notification channel: {channel}\")
    
    def _should_suppress_alert(self, existing_alert: SLAAlert, rule: AlertingRule) -> bool:
        \"\"\"Check if alert should be suppressed due to recent activity.\"\"\"
        time_since_last = datetime.now() - existing_alert.timestamp
        return time_since_last < rule.suppression_duration
    
    async def _maybe_resolve_alert(self, objective_name: str):
        \"\"\"Resolve alert if SLA is back to normal.\"\"\"
        if objective_name in self.active_alerts:
            await self._resolve_alert(objective_name, \"resolved\")
    
    async def _resolve_alert(self, objective_name: str, reason: str = \"resolved\"):
        \"\"\"Mark an alert as resolved.\"\"\"
        alert = self.active_alerts.pop(objective_name, None)
        if alert:
            alert.resolved = True
            alert.resolved_at = datetime.now()
            alert.metadata[\"resolution_reason\"] = reason
            
            # Record duration
            duration = (alert.resolved_at - alert.timestamp).total_seconds()
            self.alert_duration.labels(
                objective=objective_name,
                severity=alert.severity.value
            ).observe(duration)
            
            logger.info(f\"SLA alert resolved: {alert.title} ({reason})\", extra={
                \"alert_id\": alert.id,
                \"duration_seconds\": duration
            })
    
    def _update_alert_metrics(self):
        \"\"\"Update Prometheus metrics for active alerts.\"\"\"
        # Count alerts by severity
        severity_counts = {s.value: 0 for s in AlertSeverity}
        
        for alert in self.active_alerts.values():
            severity_counts[alert.severity.value] += 1
        
        # Update gauges
        for severity, count in severity_counts.items():
            self.active_alerts_gauge.labels(severity=severity).set(count)
    
    def get_active_alerts(self) -> List[SLAAlert]:
        \"\"\"Get all active alerts.\"\"\"
        return list(self.active_alerts.values())
    
    def get_alert_history(self, 
                         hours: int = 24, 
                         severity: Optional[AlertSeverity] = None) -> List[SLAAlert]:
        \"\"\"Get alert history for specified time period.\"\"\"
        cutoff = datetime.now() - timedelta(hours=hours)
        
        filtered_alerts = [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff
        ]
        
        if severity:
            filtered_alerts = [
                alert for alert in filtered_alerts
                if alert.severity == severity
            ]
        
        return sorted(filtered_alerts, key=lambda a: a.timestamp, reverse=True)
    
    async def start_monitoring(self, check_interval: int = 60):
        \"\"\"Start background SLA monitoring.\"\"\"
        if self._is_running:
            return
        
        self._is_running = True
        self._monitoring_task = asyncio.create_task(
            self._monitoring_loop(check_interval)
        )
        logger.info(f\"Started SLA monitoring with {check_interval}s interval\")
    
    async def stop_monitoring(self):
        \"\"\"Stop background monitoring.\"\"\"
        self._is_running = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info(\"Stopped SLA monitoring\")
    
    async def _monitoring_loop(self, check_interval: int):
        \"\"\"Background monitoring loop.\"\"\"
        while self._is_running:
            try:
                await self.check_all_slas()
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f\"Error in SLA monitoring loop: {e}\", exc_info=True)
                await asyncio.sleep(min(check_interval, 30))  # Back off on error
    
    def get_alert_summary(self) -> Dict[str, Any]:
        \"\"\"Get summary of current alert status.\"\"\"
        active = self.get_active_alerts()
        recent_history = self.get_alert_history(hours=24)
        
        severity_counts = {s.value: 0 for s in AlertSeverity}
        for alert in active:
            severity_counts[alert.severity.value] += 1
        
        return {
            \"active_alerts\": len(active),
            \"severity_breakdown\": severity_counts,
            \"alerts_last_24h\": len(recent_history),
            \"objectives_monitored\": len(self.alerting_rules),
            \"notification_channels\": list(self.notification_handlers.keys())
        }


# Global alert manager instance
_sla_alert_manager: Optional[SLAAlertManager] = None


def get_sla_alert_manager() -> SLAAlertManager:
    \"\"\"Get the global SLA alert manager instance.\"\"\"
    global _sla_alert_manager
    if _sla_alert_manager is None:
        _sla_alert_manager = SLAAlertManager()
    return _sla_alert_manager