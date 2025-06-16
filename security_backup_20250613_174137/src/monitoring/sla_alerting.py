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
        self.notification_handlers: Dict[str, Callable] = {}\n        \n        # Monitoring metrics\n        from prometheus_client import Counter, Gauge, Histogram\n        \n        self.alerts_total = Counter(\n            'sla_alerts_total',\n            'Total SLA alerts generated',\n            ['objective', 'severity']\n        )\n        \n        self.active_alerts_gauge = Gauge(\n            'sla_active_alerts',\n            'Number of active SLA alerts',\n            ['severity']\n        )\n        \n        self.alert_duration = Histogram(\n            'sla_alert_duration_seconds',\n            'Duration of SLA alerts',\n            ['objective', 'severity'],\n            buckets=(60, 300, 900, 1800, 3600, 7200, 14400)\n        )\n        \n        # Set up default alerting rules\n        self._setup_default_rules()\n        \n        # Background monitoring task\n        self._monitoring_task: Optional[asyncio.Task] = None\n        self._is_running = False\n    \n    def _setup_default_rules(self):\n        """Set up default alerting rules for all SLA objectives."""\n        for objective_name in self.sla_tracker.objectives.keys():\n            if objective_name not in self.alerting_rules:\n                self.alerting_rules[objective_name] = AlertingRule(\n                    objective_name=objective_name\n                )\n    \n    def add_alerting_rule(self, rule: AlertingRule):\n        \"\"\"Add or update an alerting rule.\"\"\"\n        self.alerting_rules[rule.objective_name] = rule\n        logger.info(f\"Added alerting rule for {rule.objective_name}\")\n    \n    def register_notification_handler(self, channel: str, handler: Callable[[SLAAlert], None]):\n        \"\"\"Register a notification handler for a channel.\"\"\"\n        self.notification_handlers[channel] = handler\n        logger.info(f\"Registered notification handler for channel: {channel}\")\n    \n    async def check_all_slas(self) -> List[SLAAlert]:\n        \"\"\"Check all SLA objectives and generate alerts.\"\"\"\n        new_alerts = []\n        \n        try:\n            # Get current SLA reports\n            reports = await self.sla_tracker.check_all_objectives()\n            \n            for objective_name, report in reports.items():\n                alerts = await self._process_sla_report(report)\n                new_alerts.extend(alerts)\n            \n            # Update active alert metrics\n            self._update_alert_metrics()\n            \n        except Exception as e:\n            logger.error(f\"Error during SLA check: {e}\", exc_info=True)\n        \n        return new_alerts\n    \n    async def _process_sla_report(self, report: SLAReport) -> List[SLAAlert]:\n        \"\"\"Process a single SLA report and generate alerts if needed.\"\"\"\n        objective_name = report.objective.name\n        rule = self.alerting_rules.get(objective_name)\n        \n        if not rule:\n            return []\n        \n        # Determine if alert is needed\n        severity = rule.get_severity_for_compliance(\n            report.compliance_percent,\n            report.error_budget_remaining\n        )\n        \n        if not severity:\n            # Check if we need to resolve an existing alert\n            await self._maybe_resolve_alert(objective_name)\n            return []\n        \n        # Check if alert should be suppressed\n        existing_alert = self.active_alerts.get(objective_name)\n        if existing_alert and self._should_suppress_alert(existing_alert, rule):\n            return []\n        \n        # Create new alert or escalate existing one\n        alert = await self._create_or_escalate_alert(report, severity, rule)\n        \n        if alert:\n            return [alert]\n        \n        return []\n    \n    async def _create_or_escalate_alert(self,\n                                      report: SLAReport,\n                                      severity: AlertSeverity,\n                                      rule: AlertingRule) -> Optional[SLAAlert]:\n        \"\"\"Create a new alert or escalate an existing one.\"\"\"\n        objective_name = report.objective.name\n        existing_alert = self.active_alerts.get(objective_name)\n        \n        # If alert exists and severity hasn't changed significantly, don't create new\n        if existing_alert and existing_alert.severity == severity:\n            return None\n        \n        # Generate alert ID\n        alert_id = f\"{objective_name}_{int(datetime.now().timestamp())}\"\n        \n        # Create alert description\n        description = self._generate_alert_description(report, severity)\n        \n        # Create alert\n        alert = SLAAlert(\n            id=alert_id,\n            objective_name=objective_name,\n            severity=severity,\n            title=f\"SLA {severity.value.upper()} - {objective_name}\",\n            description=description,\n            current_value=report.current_value,\n            target_value=report.objective.target,\n            error_budget_remaining=report.error_budget_remaining,\n            timestamp=datetime.now(),\n            metadata={\n                \"objective_type\": report.objective.type.value,\n                \"measurement_window\": str(report.objective.measurement_window),\n                \"violations\": report.violations\n            }\n        )\n        \n        # Replace existing alert if escalating\n        if existing_alert:\n            await self._resolve_alert(objective_name, \"escalated\")\n        \n        # Store alert\n        self.active_alerts[objective_name] = alert\n        self.alert_history.append(alert)\n        \n        # Record metrics\n        self.alerts_total.labels(\n            objective=objective_name,\n            severity=severity.value\n        ).inc()\n        \n        # Send notifications\n        await self._send_notifications(alert, rule)\n        \n        logger.warning(f\"SLA alert generated: {alert.title}\", extra={\n            \"alert_id\": alert.id,\n            \"severity\": severity.value,\n            \"compliance\": report.compliance_percent,\n            \"error_budget\": report.error_budget_remaining\n        })\n        \n        return alert\n    \n    def _generate_alert_description(self, report: SLAReport, severity: AlertSeverity) -> str:\n        \"\"\"Generate detailed alert description.\"\"\"\n        objective = report.objective\n        \n        description = (\n            f\"SLA '{objective.name}' is in {severity.value} state.\\n\"\n            f\"Type: {objective.type.value}\\n\"\n            f\"Current Value: {report.current_value:.2f}\\n\"\n            f\"Target: {objective.target}\\n\"\n            f\"Compliance: {report.compliance_percent:.2f}%\\n\"\n            f\"Error Budget Remaining: {report.error_budget_remaining:.2f}%\\n\"\n        )\n        \n        if objective.type.value == \"latency\":\n            description += f\"Latency Threshold: {objective.latency_threshold_ms}ms\\n\"\n            description += f\"Percentile: {objective.latency_percentile * 100}th\\n\"\n        \n        if report.violations:\n            description += f\"\\nViolations in measurement window: {len(report.violations)}\\n\"\n        \n        return description\n    \n    async def _send_notifications(self, alert: SLAAlert, rule: AlertingRule):\n        \"\"\"Send alert notifications to configured channels.\"\"\"\n        for channel in rule.notification_channels:\n            handler = self.notification_handlers.get(channel)\n            if handler:\n                try:\n                    if asyncio.iscoroutinefunction(handler):\n                        await handler(alert)\n                    else:\n                        handler(alert)\n                except Exception as e:\n                    logger.error(f\"Failed to send notification to {channel}: {e}\")\n            else:\n                logger.warning(f\"No handler registered for notification channel: {channel}\")\n    \n    def _should_suppress_alert(self, existing_alert: SLAAlert, rule: AlertingRule) -> bool:\n        \"\"\"Check if alert should be suppressed due to recent activity.\"\"\"\n        time_since_last = datetime.now() - existing_alert.timestamp\n        return time_since_last < rule.suppression_duration\n    \n    async def _maybe_resolve_alert(self, objective_name: str):\n        \"\"\"Resolve alert if SLA is back to normal.\"\"\"\n        if objective_name in self.active_alerts:\n            await self._resolve_alert(objective_name, \"resolved\")\n    \n    async def _resolve_alert(self, objective_name: str, reason: str = \"resolved\"):\n        \"\"\"Mark an alert as resolved.\"\"\"\n        alert = self.active_alerts.pop(objective_name, None)\n        if alert:\n            alert.resolved = True\n            alert.resolved_at = datetime.now()\n            alert.metadata[\"resolution_reason\"] = reason\n            \n            # Record duration\n            duration = (alert.resolved_at - alert.timestamp).total_seconds()\n            self.alert_duration.labels(\n                objective=objective_name,\n                severity=alert.severity.value\n            ).observe(duration)\n            \n            logger.info(f\"SLA alert resolved: {alert.title} ({reason})\", extra={\n                \"alert_id\": alert.id,\n                \"duration_seconds\": duration\n            })\n    \n    def _update_alert_metrics(self):\n        \"\"\"Update Prometheus metrics for active alerts.\"\"\"\n        # Count alerts by severity\n        severity_counts = {s.value: 0 for s in AlertSeverity}\n        \n        for alert in self.active_alerts.values():\n            severity_counts[alert.severity.value] += 1\n        \n        # Update gauges\n        for severity, count in severity_counts.items():\n            self.active_alerts_gauge.labels(severity=severity).set(count)\n    \n    def get_active_alerts(self) -> List[SLAAlert]:\n        \"\"\"Get all active alerts.\"\"\"\n        return list(self.active_alerts.values())\n    \n    def get_alert_history(self, \n                         hours: int = 24, \n                         severity: Optional[AlertSeverity] = None) -> List[SLAAlert]:\n        \"\"\"Get alert history for specified time period.\"\"\"\n        cutoff = datetime.now() - timedelta(hours=hours)\n        \n        filtered_alerts = [\n            alert for alert in self.alert_history\n            if alert.timestamp >= cutoff\n        ]\n        \n        if severity:\n            filtered_alerts = [\n                alert for alert in filtered_alerts\n                if alert.severity == severity\n            ]\n        \n        return sorted(filtered_alerts, key=lambda a: a.timestamp, reverse=True)\n    \n    async def start_monitoring(self, check_interval: int = 60):\n        \"\"\"Start background SLA monitoring.\"\"\"\n        if self._is_running:\n            return\n        \n        self._is_running = True\n        self._monitoring_task = asyncio.create_task(\n            self._monitoring_loop(check_interval)\n        )\n        logger.info(f\"Started SLA monitoring with {check_interval}s interval\")\n    \n    async def stop_monitoring(self):\n        \"\"\"Stop background monitoring.\"\"\"\n        self._is_running = False\n        if self._monitoring_task:\n            self._monitoring_task.cancel()\n            try:\n                await self._monitoring_task\n            except asyncio.CancelledError:\n                pass\n        logger.info(\"Stopped SLA monitoring\")\n    \n    async def _monitoring_loop(self, check_interval: int):\n        \"\"\"Background monitoring loop.\"\"\"\n        while self._is_running:\n            try:\n                await self.check_all_slas()\n                await asyncio.sleep(check_interval)\n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f\"Error in SLA monitoring loop: {e}\", exc_info=True)\n                await asyncio.sleep(min(check_interval, 30))  # Back off on error\n    \n    def get_alert_summary(self) -> Dict[str, Any]:\n        \"\"\"Get summary of current alert status.\"\"\"\n        active = self.get_active_alerts()\n        recent_history = self.get_alert_history(hours=24)\n        \n        severity_counts = {s.value: 0 for s in AlertSeverity}\n        for alert in active:\n            severity_counts[alert.severity.value] += 1\n        \n        return {\n            \"active_alerts\": len(active),\n            \"severity_breakdown\": severity_counts,\n            \"alerts_last_24h\": len(recent_history),\n            \"objectives_monitored\": len(self.alerting_rules),\n            \"notification_channels\": list(self.notification_handlers.keys())\n        }\n\n\n# Global alert manager instance\n_sla_alert_manager: Optional[SLAAlertManager] = None\n\n\ndef get_sla_alert_manager() -> SLAAlertManager:\n    \"\"\"Get the global SLA alert manager instance.\"\"\"\n    global _sla_alert_manager\n    if _sla_alert_manager is None:\n        _sla_alert_manager = SLAAlertManager()\n    return _sla_alert_manager