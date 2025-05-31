"""
Alert definitions and management for proactive monitoring.

Provides:
- Alert rule definitions
- Alert severity levels
- Alert routing and notifications
- Integration with alerting systems
"""

import os
import json
import time
import asyncio
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import yaml
from pathlib import Path


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"         # Action required within 1 hour
    MEDIUM = "medium"     # Action required within 24 hours
    LOW = "low"           # Informational
    INFO = "info"         # FYI only


class AlertState(Enum):
    """Alert states."""
    PENDING = "pending"      # Alert condition met, waiting for duration
    FIRING = "firing"        # Alert is active
    RESOLVED = "resolved"    # Alert condition no longer met


@dataclass
class AlertRule:
    """Alert rule definition."""
    name: str
    expression: str
    duration: timedelta
    severity: AlertSeverity
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    
    # For Prometheus compatibility
    def to_prometheus_rule(self) -> Dict[str, Any]:
        """Convert to Prometheus rule format."""
        return {
            "alert": self.name,
            "expr": self.expression,
            "for": f"{int(self.duration.total_seconds())}s",
            "labels": {
                "severity": self.severity.value,
                **self.labels
            },
            "annotations": self.annotations
        }


@dataclass
class Alert:
    """Active alert instance."""
    rule: AlertRule
    state: AlertState
    started_at: datetime
    fired_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    value: Optional[float] = None
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    
    @property
    def duration(self) -> timedelta:
        """Get alert duration."""
        end_time = self.resolved_at or datetime.now()
        return end_time - self.started_at
    
    @property
    def fingerprint(self) -> str:
        """Get unique alert fingerprint."""
        labels_str = json.dumps(sorted(self.labels.items()))
        return f"{self.rule.name}:{labels_str}"


class AlertManager:
    """Manages alert rules and active alerts."""
    
    # Pre-defined alert rules for common scenarios
    DEFAULT_RULES = [
        # API Performance
        AlertRule(
            name="HighAPILatency",
            expression='histogram_quantile(0.95, http_request_duration_seconds) > 2',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "API latency is high",
                "description": "95th percentile API latency is above 2 seconds for 5 minutes"
            }
        ),
        AlertRule(
            name="HighErrorRate",
            expression='rate(http_requests_total{status=~"5.."}[5m]) > 0.05',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "High error rate detected",
                "description": "Error rate is above 5% for 5 minutes"
            }
        ),
        
        # Resource Usage
        AlertRule(
            name="HighCPUUsage",
            expression='cpu_usage_percent > 90',
            duration=timedelta(minutes=10),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "CPU usage is critically high",
                "description": "CPU usage has been above 90% for 10 minutes"
            }
        ),
        AlertRule(
            name="HighMemoryUsage",
            expression='memory_usage_bytes{type="percent"} > 90',
            duration=timedelta(minutes=10),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "Memory usage is critically high",
                "description": "Memory usage has been above 90% for 10 minutes"
            }
        ),
        AlertRule(
            name="DiskSpaceLow",
            expression='disk_usage_bytes{type="percent"} > 85',
            duration=timedelta(minutes=30),
            severity=AlertSeverity.MEDIUM,
            annotations={
                "summary": "Disk space is running low",
                "description": "Disk usage is above 85%"
            }
        ),
        
        # AI/ML Specific
        AlertRule(
            name="HighAILatency",
            expression='histogram_quantile(0.95, ai_request_duration_seconds) > 30',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.MEDIUM,
            annotations={
                "summary": "AI request latency is high",
                "description": "95th percentile AI latency is above 30 seconds"
            }
        ),
        AlertRule(
            name="AIProviderErrors",
            expression='rate(ai_requests_total{status="error"}[5m]) > 0.1',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "AI provider error rate is high",
                "description": "AI provider error rate is above 10%"
            }
        ),
        AlertRule(
            name="HighAICosts",
            expression='rate(ai_cost_dollars[1h]) > 10',
            duration=timedelta(minutes=15),
            severity=AlertSeverity.MEDIUM,
            annotations={
                "summary": "AI costs are high",
                "description": "AI costs are exceeding $10/hour"
            }
        ),
        
        # MCP Specific
        AlertRule(
            name="MCPToolFailures",
            expression='rate(mcp_tool_calls_total{status="error"}[5m]) > 0.1',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.HIGH,
            annotations={
                "summary": "MCP tool failure rate is high",
                "description": "MCP tool error rate is above 10%"
            }
        ),
        
        # SLA Compliance
        AlertRule(
            name="SLAViolation",
            expression='sla_compliance_percent < 99.9',
            duration=timedelta(minutes=15),
            severity=AlertSeverity.CRITICAL,
            annotations={
                "summary": "SLA compliance is below target",
                "description": "SLA compliance has fallen below 99.9%"
            }
        ),
        AlertRule(
            name="AvailabilityLow",
            expression='availability_percent < 99.95',
            duration=timedelta(minutes=5),
            severity=AlertSeverity.CRITICAL,
            annotations={
                "summary": "Service availability is low",
                "description": "Service availability has fallen below 99.95%"
            }
        ),
    ]
    
    def __init__(self, config_path: Optional[Path] = None):
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.handlers: List[Callable[[Alert], None]] = []
        self.async_handlers: List[Callable[[Alert], asyncio.Task]] = []
        
        # Load default rules
        for rule in self.DEFAULT_RULES:
            self.add_rule(rule)
        
        # Load custom rules from config if provided
        if config_path and config_path.exists():
            self.load_rules_from_file(config_path)
    
    def add_rule(self, rule: AlertRule):
        """Add an alert rule."""
        self.rules[rule.name] = rule
    
    def remove_rule(self, name: str):
        """Remove an alert rule."""
        self.rules.pop(name, None)
    
    def enable_rule(self, name: str):
        """Enable an alert rule."""
        if name in self.rules:
            self.rules[name].enabled = True
    
    def disable_rule(self, name: str):
        """Disable an alert rule."""
        if name in self.rules:
            self.rules[name].enabled = False
    
    def load_rules_from_file(self, path: Path):
        """Load alert rules from YAML file."""
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        
        for rule_config in config.get('rules', []):
            rule = AlertRule(
                name=rule_config['name'],
                expression=rule_config['expression'],
                duration=timedelta(seconds=rule_config.get('duration_seconds', 300)),
                severity=AlertSeverity(rule_config.get('severity', 'medium')),
                labels=rule_config.get('labels', {}),
                annotations=rule_config.get('annotations', {}),
                enabled=rule_config.get('enabled', True)
            )
            self.add_rule(rule)
    
    def save_rules_to_file(self, path: Path):
        """Save alert rules to YAML file."""
        rules_config = []
        for rule in self.rules.values():
            rules_config.append({
                'name': rule.name,
                'expression': rule.expression,
                'duration_seconds': int(rule.duration.total_seconds()),
                'severity': rule.severity.value,
                'labels': rule.labels,
                'annotations': rule.annotations,
                'enabled': rule.enabled
            })
        
        config = {'rules': rules_config}
        with open(path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def register_handler(self, handler: Callable[[Alert], None], is_async: bool = False):
        """Register an alert handler."""
        if is_async:
            self.async_handlers.append(handler)
        else:
            self.handlers.append(handler)
    
    def check_alert(self, rule: AlertRule, value: float, labels: Optional[Dict[str, str]] = None) -> Optional[Alert]:
        """Check if an alert should fire based on current value."""
        if not rule.enabled:
            return None
        
        labels = labels or {}
        alert_labels = {**rule.labels, **labels}
        
        # Create alert instance
        alert = Alert(
            rule=rule,
            state=AlertState.PENDING,
            started_at=datetime.now(),
            value=value,
            labels=alert_labels,
            annotations=rule.annotations
        )
        
        fingerprint = alert.fingerprint
        
        # Check if alert already exists
        if fingerprint in self.active_alerts:
            existing = self.active_alerts[fingerprint]
            
            # Update value
            existing.value = value
            
            # Check if pending alert should fire
            if existing.state == AlertState.PENDING:
                if datetime.now() - existing.started_at >= rule.duration:
                    existing.state = AlertState.FIRING
                    existing.fired_at = datetime.now()
                    self._notify_handlers(existing)
            
            return existing
        else:
            # New alert
            self.active_alerts[fingerprint] = alert
            
            # Check if it should fire immediately (for critical alerts)
            if rule.severity == AlertSeverity.CRITICAL:
                alert.state = AlertState.FIRING
                alert.fired_at = datetime.now()
                self._notify_handlers(alert)
            
            return alert
    
    def resolve_alert(self, rule_name: str, labels: Optional[Dict[str, str]] = None):
        """Resolve an alert."""
        if rule_name not in self.rules:
            return
        
        rule = self.rules[rule_name]
        labels = labels or {}
        alert_labels = {**rule.labels, **labels}
        
        # Find matching alert
        fingerprint = None
        for fp, alert in self.active_alerts.items():
            if alert.rule.name == rule_name and alert.labels == alert_labels:
                fingerprint = fp
                break
        
        if fingerprint:
            alert = self.active_alerts[fingerprint]
            alert.state = AlertState.RESOLVED
            alert.resolved_at = datetime.now()
            
            # Notify handlers
            self._notify_handlers(alert)
            
            # Remove from active alerts
            del self.active_alerts[fingerprint]
    
    def _notify_handlers(self, alert: Alert):
        """Notify all registered handlers about an alert."""
        # Sync handlers
        for handler in self.handlers:
            try:
                handler(alert)
            except Exception:
                pass  # Don't let handler errors affect alerting
        
        # Async handlers
        for handler in self.async_handlers:
            try:
                asyncio.create_task(handler(alert))
            except Exception:
                pass
    
    def get_active_alerts(self, severity: Optional[AlertSeverity] = None) -> List[Alert]:
        """Get list of active alerts."""
        alerts = list(self.active_alerts.values())
        
        if severity:
            alerts = [a for a in alerts if a.rule.severity == severity]
        
        return sorted(alerts, key=lambda a: (a.rule.severity.value, a.started_at))
    
    def get_prometheus_rules(self) -> List[Dict[str, Any]]:
        """Get all rules in Prometheus format."""
        return [rule.to_prometheus_rule() for rule in self.rules.values() if rule.enabled]
    
    def export_prometheus_rules(self, path: Path):
        """Export rules in Prometheus format."""
        rules = {
            "groups": [{
                "name": "claude_deployment_engine",
                "interval": "30s",
                "rules": self.get_prometheus_rules()
            }]
        }
        
        with open(path, 'w') as f:
            yaml.dump(rules, f, default_flow_style=False)


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


# Convenience functions
def check_alert(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Check an alert condition."""
    manager = get_alert_manager()
    if name in manager.rules:
        return manager.check_alert(manager.rules[name], value, labels)


def resolve_alert(name: str, labels: Optional[Dict[str, str]] = None):
    """Resolve an alert."""
    get_alert_manager().resolve_alert(name, labels)


def register_alert_handler(handler: Callable[[Alert], None], is_async: bool = False):
    """Register a global alert handler."""
    get_alert_manager().register_handler(handler, is_async)


# Example alert handlers
def log_alert_handler(alert: Alert):
    """Log alerts to standard logging."""
    import logging
    logger = logging.getLogger(__name__)
    
    if alert.state == AlertState.FIRING:
        logger.error(
            f"ALERT FIRING: {alert.rule.name} - {alert.annotations.get('summary', 'No summary')}",
            extra={
                "alert_name": alert.rule.name,
                "severity": alert.rule.severity.value,
                "labels": alert.labels,
                "value": alert.value,
                "duration": str(alert.duration)
            }
        )
    elif alert.state == AlertState.RESOLVED:
        logger.info(
            f"ALERT RESOLVED: {alert.rule.name}",
            extra={
                "alert_name": alert.rule.name,
                "duration": str(alert.duration)
            }
        )


async def slack_alert_handler(alert: Alert):
    """Send alerts to Slack (requires MCP Slack server)."""
    if alert.state != AlertState.FIRING:
        return
    
    try:
        from ..mcp.manager import get_mcp_manager
        manager = await get_mcp_manager()
        
        severity_emoji = {
            AlertSeverity.CRITICAL: "🚨",
            AlertSeverity.HIGH: "⚠️",
            AlertSeverity.MEDIUM: "⚡",
            AlertSeverity.LOW: "ℹ️",
            AlertSeverity.INFO: "📌"
        }
        
        emoji = severity_emoji.get(alert.rule.severity, "❗")
        
        message = f"{emoji} *{alert.rule.name}*\n"
        message += f"Severity: {alert.rule.severity.value.upper()}\n"
        message += f"Summary: {alert.annotations.get('summary', 'No summary')}\n"
        if alert.value is not None:
            message += f"Value: {alert.value}\n"
        message += f"Started: {alert.started_at.strftime('%Y-%m-%d %H:%M:%S')}"
        
        await manager.call_tool(
            "slack-notifications.send_notification",
            {
                "message": message,
                "notification_type": "alert"
            }
        )
    except Exception:
        pass  # Silently fail Slack notifications