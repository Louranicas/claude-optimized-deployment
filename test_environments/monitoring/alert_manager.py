#!/usr/bin/env python3
"""
Intelligent Alert Manager
Advanced alerting with correlation, escalation, and smart notification
"""

import asyncio
import time
import logging
import threading
import json
import smtplib
import hashlib
from typing import Dict, List, Any, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum
from datetime import datetime, timedelta
import statistics
import re
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

from metrics_collector import MetricValue
from real_time_processor import AlertLevel, AnomalyDetectionResult

logger = logging.getLogger(__name__)

class AlertState(Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"

class AlertPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class NotificationChannel(Enum):
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PHONE = "phone"
    DASHBOARD = "dashboard"

@dataclass
class AlertRule:
    """Alert rule definition"""
    rule_id: str
    name: str
    description: str
    condition: str  # Expression to evaluate
    level: AlertLevel
    priority: AlertPriority
    metric_patterns: List[str]
    evaluation_window: int = 60  # seconds
    threshold_count: int = 1  # consecutive occurrences
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    
    # Escalation settings
    escalation_enabled: bool = False
    escalation_after: int = 300  # seconds
    escalation_levels: List[AlertLevel] = field(default_factory=list)
    
    # Suppression settings
    suppression_window: int = 3600  # seconds
    auto_resolve: bool = True
    auto_resolve_after: int = 1800  # seconds

@dataclass
class Alert:
    """Alert instance"""
    alert_id: str
    rule_id: str
    name: str
    description: str
    level: AlertLevel
    priority: AlertPriority
    state: AlertState
    
    # Timing
    created_at: float
    updated_at: float
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    
    # Context
    metric_name: str = ""
    metric_value: Any = None
    threshold_value: Any = None
    tags: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Relationships
    correlated_alerts: List[str] = field(default_factory=list)
    root_cause_alert: Optional[str] = None
    
    # Notification tracking
    notifications_sent: List[Dict[str, Any]] = field(default_factory=list)
    escalation_level: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return asdict(self)

@dataclass
class NotificationTarget:
    """Notification target configuration"""
    target_id: str
    name: str
    channel: NotificationChannel
    address: str  # email, webhook URL, phone number, etc.
    enabled: bool = True
    
    # Filtering
    alert_levels: List[AlertLevel] = field(default_factory=list)
    alert_priorities: List[AlertPriority] = field(default_factory=list)
    metric_patterns: List[str] = field(default_factory=list)
    time_windows: List[Dict[str, str]] = field(default_factory=list)
    
    # Rate limiting
    rate_limit_count: int = 10
    rate_limit_window: int = 3600  # seconds
    
    # Template
    message_template: str = ""

@dataclass
class CorrelationRule:
    """Alert correlation rule"""
    rule_id: str
    name: str
    description: str
    alert_patterns: List[str]
    time_window: int = 300  # seconds
    min_alerts: int = 2
    correlation_type: str = "temporal"  # temporal, causal, metric-based
    enabled: bool = True

class AlertEvaluator:
    """Evaluates alert conditions against metrics"""
    
    def __init__(self):
        self.operators = {
            '>': lambda x, y: x > y,
            '>=': lambda x, y: x >= y,
            '<': lambda x, y: x < y,
            '<=': lambda x, y: x <= y,
            '==': lambda x, y: x == y,
            '!=': lambda x, y: x != y,
            'contains': lambda x, y: str(y) in str(x),
            'matches': lambda x, y: bool(re.search(str(y), str(x))),
            'in': lambda x, y: x in y
        }
    
    def evaluate_condition(self, condition: str, metric: MetricValue, context: Dict[str, Any] = None) -> bool:
        """Evaluate alert condition against metric"""
        try:
            # Simple condition parsing: "metric_value > 80"
            condition = condition.strip()
            
            # Replace placeholders
            condition = condition.replace('metric_value', str(metric.value))
            condition = condition.replace('metric_name', f"'{metric.name}'")
            
            if context:
                for key, value in context.items():
                    condition = condition.replace(f'context.{key}', str(value))
            
            # Parse condition
            for op in ['>=', '<=', '!=', '==', '>', '<']:
                if op in condition:
                    left, right = condition.split(op, 1)
                    left_val = self._parse_value(left.strip())
                    right_val = self._parse_value(right.strip())
                    
                    return self.operators[op](left_val, right_val)
            
            # Handle special operators
            if ' contains ' in condition:
                left, right = condition.split(' contains ', 1)
                left_val = self._parse_value(left.strip())
                right_val = self._parse_value(right.strip())
                return self.operators['contains'](left_val, right_val)
            
            if ' matches ' in condition:
                left, right = condition.split(' matches ', 1)
                left_val = self._parse_value(left.strip())
                right_val = self._parse_value(right.strip())
                return self.operators['matches'](left_val, right_val)
            
            # If no operator found, evaluate as boolean
            return bool(self._parse_value(condition))
            
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False
    
    def _parse_value(self, value_str: str) -> Any:
        """Parse string value to appropriate type"""
        value_str = value_str.strip()
        
        # String literal
        if value_str.startswith("'") and value_str.endswith("'"):
            return value_str[1:-1]
        if value_str.startswith('"') and value_str.endswith('"'):
            return value_str[1:-1]
        
        # Boolean
        if value_str.lower() in ['true', 'false']:
            return value_str.lower() == 'true'
        
        # Number
        try:
            if '.' in value_str:
                return float(value_str)
            else:
                return int(value_str)
        except ValueError:
            pass
        
        # Return as string
        return value_str

class AlertCorrelator:
    """Correlates related alerts to reduce noise"""
    
    def __init__(self):
        self.correlation_rules: List[CorrelationRule] = []
        self.alert_groups: Dict[str, List[str]] = {}
        
    def add_correlation_rule(self, rule: CorrelationRule):
        """Add a correlation rule"""
        self.correlation_rules.append(rule)
        logger.info(f"Added correlation rule: {rule.name}")
    
    def correlate_alerts(self, alerts: List[Alert]) -> List[List[Alert]]:
        """Find correlated alert groups"""
        correlated_groups = []
        
        for rule in self.correlation_rules:
            if not rule.enabled:
                continue
            
            # Find alerts matching the rule patterns
            matching_alerts = []
            current_time = time.time()
            
            for alert in alerts:
                if alert.state != AlertState.ACTIVE:
                    continue
                
                # Check if alert is within time window
                if current_time - alert.created_at > rule.time_window:
                    continue
                
                # Check if alert matches any pattern
                for pattern in rule.alert_patterns:
                    if self._matches_pattern(alert, pattern):
                        matching_alerts.append(alert)
                        break
            
            # Group alerts if minimum threshold is met
            if len(matching_alerts) >= rule.min_alerts:
                # Apply correlation logic based on type
                if rule.correlation_type == "temporal":
                    groups = self._temporal_correlation(matching_alerts, rule.time_window)
                elif rule.correlation_type == "causal":
                    groups = self._causal_correlation(matching_alerts)
                elif rule.correlation_type == "metric-based":
                    groups = self._metric_based_correlation(matching_alerts)
                else:
                    groups = [matching_alerts]  # Default grouping
                
                correlated_groups.extend(groups)
        
        return correlated_groups
    
    def _matches_pattern(self, alert: Alert, pattern: str) -> bool:
        """Check if alert matches pattern"""
        try:
            # Simple pattern matching - can be enhanced with regex
            if pattern == "*":
                return True
            
            # Check alert name
            if pattern in alert.name.lower():
                return True
            
            # Check metric name
            if pattern in alert.metric_name.lower():
                return True
            
            # Check tags
            for tag_value in alert.tags.values():
                if pattern in str(tag_value).lower():
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error matching pattern '{pattern}': {e}")
            return False
    
    def _temporal_correlation(self, alerts: List[Alert], time_window: int) -> List[List[Alert]]:
        """Correlate alerts based on temporal proximity"""
        groups = []
        sorted_alerts = sorted(alerts, key=lambda a: a.created_at)
        
        current_group = []
        group_start_time = None
        
        for alert in sorted_alerts:
            if not current_group:
                current_group = [alert]
                group_start_time = alert.created_at
            elif alert.created_at - group_start_time <= time_window:
                current_group.append(alert)
            else:
                if len(current_group) > 1:
                    groups.append(current_group)
                current_group = [alert]
                group_start_time = alert.created_at
        
        if len(current_group) > 1:
            groups.append(current_group)
        
        return groups
    
    def _causal_correlation(self, alerts: List[Alert]) -> List[List[Alert]]:
        """Correlate alerts based on causal relationships"""
        # Simple causal correlation based on metric dependencies
        groups = []
        
        # Group by component/service
        component_groups = defaultdict(list)
        for alert in alerts:
            component = alert.tags.get('component', 'unknown')
            component_groups[component].append(alert)
        
        # Return groups with more than one alert
        for component, component_alerts in component_groups.items():
            if len(component_alerts) > 1:
                groups.append(component_alerts)
        
        return groups
    
    def _metric_based_correlation(self, alerts: List[Alert]) -> List[List[Alert]]:
        """Correlate alerts based on metric relationships"""
        groups = []
        
        # Group by metric source
        source_groups = defaultdict(list)
        for alert in alerts:
            source = alert.tags.get('source', 'unknown')
            source_groups[source].append(alert)
        
        # Return groups with more than one alert
        for source, source_alerts in source_groups.items():
            if len(source_alerts) > 1:
                groups.append(source_alerts)
        
        return groups

class NotificationManager:
    """Manages alert notifications across multiple channels"""
    
    def __init__(self):
        self.targets: Dict[str, NotificationTarget] = {}
        self.rate_limiters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.notification_history: deque = deque(maxlen=10000)
        
        # Email configuration
        self.smtp_config = {
            'host': 'localhost',
            'port': 587,
            'use_tls': True,
            'username': '',
            'password': ''
        }
    
    def add_target(self, target: NotificationTarget):
        """Add notification target"""
        self.targets[target.target_id] = target
        logger.info(f"Added notification target: {target.name} ({target.channel.value})")
    
    def configure_smtp(self, host: str, port: int, username: str, password: str, use_tls: bool = True):
        """Configure SMTP settings for email notifications"""
        self.smtp_config = {
            'host': host,
            'port': port,
            'use_tls': use_tls,
            'username': username,
            'password': password
        }
    
    async def send_alert_notification(self, alert: Alert, targets: List[str] = None) -> Dict[str, bool]:
        """Send alert notification to specified targets"""
        results = {}
        
        # Use all targets if none specified
        if targets is None:
            targets = list(self.targets.keys())
        
        for target_id in targets:
            if target_id not in self.targets:
                logger.warning(f"Unknown notification target: {target_id}")
                continue
            
            target = self.targets[target_id]
            
            # Check if target should receive this alert
            if not self._should_notify(alert, target):
                continue
            
            # Check rate limiting
            if not self._check_rate_limit(target):
                logger.warning(f"Rate limit exceeded for target: {target.name}")
                continue
            
            # Send notification
            try:
                success = await self._send_notification(alert, target)
                results[target_id] = success
                
                if success:
                    # Record notification
                    notification_record = {
                        'alert_id': alert.alert_id,
                        'target_id': target_id,
                        'channel': target.channel.value,
                        'timestamp': time.time(),
                        'success': True
                    }
                    
                    alert.notifications_sent.append(notification_record)
                    self.notification_history.append(notification_record)
                    
                    # Update rate limiter
                    self.rate_limiters[target_id].append(time.time())
                
            except Exception as e:
                logger.error(f"Error sending notification to {target.name}: {e}")
                results[target_id] = False
        
        return results
    
    def _should_notify(self, alert: Alert, target: NotificationTarget) -> bool:
        """Check if target should receive this alert"""
        if not target.enabled:
            return False
        
        # Check alert levels
        if target.alert_levels and alert.level not in target.alert_levels:
            return False
        
        # Check alert priorities
        if target.alert_priorities and alert.priority not in target.alert_priorities:
            return False
        
        # Check metric patterns
        if target.metric_patterns:
            matches = False
            for pattern in target.metric_patterns:
                if pattern in alert.metric_name or pattern == "*":
                    matches = True
                    break
            if not matches:
                return False
        
        # Check time windows (simplified - would need proper time zone handling)
        if target.time_windows:
            current_hour = datetime.now().hour
            in_window = False
            for window in target.time_windows:
                start_hour = int(window.get('start', '0'))
                end_hour = int(window.get('end', '23'))
                if start_hour <= current_hour <= end_hour:
                    in_window = True
                    break
            if not in_window:
                return False
        
        return True
    
    def _check_rate_limit(self, target: NotificationTarget) -> bool:
        """Check if target is within rate limits"""
        current_time = time.time()
        window_start = current_time - target.rate_limit_window
        
        # Remove old entries
        target_history = self.rate_limiters[target.target_id]
        while target_history and target_history[0] < window_start:
            target_history.popleft()
        
        # Check if under limit
        return len(target_history) < target.rate_limit_count
    
    async def _send_notification(self, alert: Alert, target: NotificationTarget) -> bool:
        """Send notification through specific channel"""
        try:
            if target.channel == NotificationChannel.EMAIL:
                return await self._send_email(alert, target)
            elif target.channel == NotificationChannel.WEBHOOK:
                return await self._send_webhook(alert, target)
            elif target.channel == NotificationChannel.DASHBOARD:
                return await self._send_dashboard(alert, target)
            else:
                logger.warning(f"Unsupported notification channel: {target.channel}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending {target.channel.value} notification: {e}")
            return False
    
    async def _send_email(self, alert: Alert, target: NotificationTarget) -> bool:
        """Send email notification"""
        try:
            # Create message
            msg = MimeMultipart()
            msg['From'] = self.smtp_config['username']
            msg['To'] = target.address
            msg['Subject'] = f"[{alert.level.value.upper()}] {alert.name}"
            
            # Create email body
            body = self._format_alert_message(alert, target)
            msg.attach(MimeText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port'])
            if self.smtp_config['use_tls']:
                server.starttls()
            if self.smtp_config['username']:
                server.login(self.smtp_config['username'], self.smtp_config['password'])
            
            text = msg.as_string()
            server.sendmail(self.smtp_config['username'], target.address, text)
            server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def _send_webhook(self, alert: Alert, target: NotificationTarget) -> bool:
        """Send webhook notification"""
        try:
            import aiohttp
            
            payload = {
                'alert_id': alert.alert_id,
                'name': alert.name,
                'level': alert.level.value,
                'priority': alert.priority.value,
                'state': alert.state.value,
                'metric_name': alert.metric_name,
                'metric_value': alert.metric_value,
                'created_at': alert.created_at,
                'message': self._format_alert_message(alert, target, format_type='text')
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(target.address, json=payload, timeout=10) as response:
                    return response.status < 400
                    
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False
    
    async def _send_dashboard(self, alert: Alert, target: NotificationTarget) -> bool:
        """Send dashboard notification (internal)"""
        # This would integrate with the dashboard server
        # For now, just log the notification
        logger.info(f"Dashboard notification: {alert.name} - {alert.level.value}")
        return True
    
    def _format_alert_message(self, alert: Alert, target: NotificationTarget, format_type: str = 'html') -> str:
        """Format alert message for notification"""
        if target.message_template:
            # Use custom template
            template = target.message_template
            template = template.replace('{alert_name}', alert.name)
            template = template.replace('{alert_level}', alert.level.value)
            template = template.replace('{metric_name}', alert.metric_name)
            template = template.replace('{metric_value}', str(alert.metric_value))
            template = template.replace('{created_at}', datetime.fromtimestamp(alert.created_at).strftime('%Y-%m-%d %H:%M:%S'))
            return template
        
        # Default template
        if format_type == 'html':
            return f"""
            <html>
            <body>
                <h2 style="color: {'red' if alert.level in [AlertLevel.CRITICAL, AlertLevel.ERROR] else 'orange' if alert.level == AlertLevel.WARNING else 'blue'};">
                    Alert: {alert.name}
                </h2>
                <p><strong>Level:</strong> {alert.level.value.upper()}</p>
                <p><strong>Priority:</strong> {alert.priority.value}</p>
                <p><strong>Metric:</strong> {alert.metric_name}</p>
                <p><strong>Value:</strong> {alert.metric_value}</p>
                <p><strong>Time:</strong> {datetime.fromtimestamp(alert.created_at).strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Description:</strong> {alert.description}</p>
                {f'<p><strong>Tags:</strong> {", ".join(f"{k}={v}" for k, v in alert.tags.items())}</p>' if alert.tags else ''}
            </body>
            </html>
            """
        else:
            return f"""
Alert: {alert.name}
Level: {alert.level.value.upper()}
Priority: {alert.priority.value}
Metric: {alert.metric_name}
Value: {alert.metric_value}
Time: {datetime.fromtimestamp(alert.created_at).strftime('%Y-%m-%d %H:%M:%S')}
Description: {alert.description}
{f'Tags: {", ".join(f"{k}={v}" for k, v in alert.tags.items())}' if alert.tags else ''}
            """

class IntelligentAlertManager:
    """Main alert manager with intelligent correlation and escalation"""
    
    def __init__(self):
        self.alert_rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        
        # Components
        self.evaluator = AlertEvaluator()
        self.correlator = AlertCorrelator()
        self.notification_manager = NotificationManager()
        
        # Processing
        self.running = False
        self.evaluation_thread: Optional[threading.Thread] = None
        self.metric_queue = deque(maxlen=10000)
        
        # Statistics
        self.stats = {
            'alerts_created': 0,
            'alerts_resolved': 0,
            'alerts_escalated': 0,
            'notifications_sent': 0,
            'correlations_found': 0,
            'false_positives': 0
        }
        
        # Initialize default rules
        self._initialize_default_rules()
        self._initialize_default_targets()
        
        logger.info("Initialized intelligent alert manager")
    
    def _initialize_default_rules(self):
        """Initialize default alert rules"""
        
        # System resource alerts
        self.add_alert_rule(AlertRule(
            rule_id="high_cpu_usage",
            name="High CPU Usage",
            description="CPU usage is above 85%",
            condition="metric_value > 85",
            level=AlertLevel.WARNING,
            priority=AlertPriority.HIGH,
            metric_patterns=["cpu_usage_percent", "system.cpu_usage"],
            evaluation_window=300,
            threshold_count=3
        ))
        
        self.add_alert_rule(AlertRule(
            rule_id="critical_cpu_usage",
            name="Critical CPU Usage",
            description="CPU usage is above 95%",
            condition="metric_value > 95",
            level=AlertLevel.CRITICAL,
            priority=AlertPriority.CRITICAL,
            metric_patterns=["cpu_usage_percent", "system.cpu_usage"],
            evaluation_window=60,
            threshold_count=2,
            escalation_enabled=True,
            escalation_after=600,
            escalation_levels=[AlertLevel.EMERGENCY]
        ))
        
        self.add_alert_rule(AlertRule(
            rule_id="high_memory_usage",
            name="High Memory Usage",
            description="Memory usage is above 90%",
            condition="metric_value > 90",
            level=AlertLevel.WARNING,
            priority=AlertPriority.HIGH,
            metric_patterns=["memory_usage_percent", "memory_percent"],
            evaluation_window=300,
            threshold_count=3
        ))
        
        self.add_alert_rule(AlertRule(
            rule_id="disk_space_critical",
            name="Disk Space Critical",
            description="Disk usage is above 95%",
            condition="metric_value > 95",
            level=AlertLevel.CRITICAL,
            priority=AlertPriority.CRITICAL,
            metric_patterns=["disk_usage_percent"],
            evaluation_window=60,
            threshold_count=1
        ))
        
        # Application performance alerts
        self.add_alert_rule(AlertRule(
            rule_id="slow_response_time",
            name="Slow Response Time",
            description="Response time is above 5 seconds",
            condition="metric_value > 5000",
            level=AlertLevel.WARNING,
            priority=AlertPriority.MEDIUM,
            metric_patterns=["response_time", "query_time"],
            evaluation_window=300,
            threshold_count=5
        ))
        
        self.add_alert_rule(AlertRule(
            rule_id="high_error_rate",
            name="High Error Rate",
            description="Error rate is above 5%",
            condition="metric_value > 5",
            level=AlertLevel.WARNING,
            priority=AlertPriority.HIGH,
            metric_patterns=["error_rate", "failure_rate"],
            evaluation_window=300,
            threshold_count=3
        ))
        
        # Circle of Experts alerts
        self.add_alert_rule(AlertRule(
            rule_id="expert_offline",
            name="Expert Offline",
            description="Expert is not responding",
            condition="metric_value == 0",
            level=AlertLevel.CRITICAL,
            priority=AlertPriority.HIGH,
            metric_patterns=["expert_status", "expert_availability"],
            evaluation_window=60,
            threshold_count=2
        ))
        
        self.add_alert_rule(AlertRule(
            rule_id="low_consensus_rate",
            name="Low Consensus Rate",
            description="Expert consensus rate is below 80%",
            condition="metric_value < 0.8",
            level=AlertLevel.WARNING,
            priority=AlertPriority.MEDIUM,
            metric_patterns=["consensus_success_rate"],
            evaluation_window=600,
            threshold_count=3
        ))
    
    def _initialize_default_targets(self):
        """Initialize default notification targets"""
        
        # Dashboard notifications
        self.notification_manager.add_target(NotificationTarget(
            target_id="dashboard",
            name="Dashboard Notifications",
            channel=NotificationChannel.DASHBOARD,
            address="dashboard",
            alert_levels=[AlertLevel.WARNING, AlertLevel.CRITICAL, AlertLevel.EMERGENCY],
            rate_limit_count=50,
            rate_limit_window=300
        ))
        
        # Email notifications for critical alerts
        self.notification_manager.add_target(NotificationTarget(
            target_id="admin_email",
            name="Administrator Email",
            channel=NotificationChannel.EMAIL,
            address="admin@example.com",
            alert_levels=[AlertLevel.CRITICAL, AlertLevel.EMERGENCY],
            alert_priorities=[AlertPriority.CRITICAL, AlertPriority.EMERGENCY],
            rate_limit_count=10,
            rate_limit_window=3600
        ))
    
    def add_alert_rule(self, rule: AlertRule):
        """Add an alert rule"""
        self.alert_rules[rule.rule_id] = rule
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_id: str):
        """Remove an alert rule"""
        if rule_id in self.alert_rules:
            del self.alert_rules[rule_id]
            logger.info(f"Removed alert rule: {rule_id}")
    
    def start(self):
        """Start alert processing"""
        if self.running:
            logger.warning("Alert manager already running")
            return
        
        self.running = True
        self.evaluation_thread = threading.Thread(target=self._evaluation_loop, daemon=True)
        self.evaluation_thread.start()
        
        logger.info("Started intelligent alert manager")
    
    def stop(self):
        """Stop alert processing"""
        self.running = False
        
        if self.evaluation_thread and self.evaluation_thread.is_alive():
            self.evaluation_thread.join(timeout=5)
        
        logger.info("Stopped intelligent alert manager")
    
    def process_metric(self, metric: MetricValue):
        """Process a metric for alert evaluation"""
        self.metric_queue.append(metric)
    
    def _evaluation_loop(self):
        """Main evaluation loop"""
        while self.running:
            try:
                # Process metrics from queue
                processed_count = 0
                while self.metric_queue and processed_count < 100:
                    metric = self.metric_queue.popleft()
                    self._evaluate_metric(metric)
                    processed_count += 1
                
                # Perform periodic tasks
                self._check_escalations()
                self._check_auto_resolution()
                self._perform_correlation()
                
                # Sleep
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Evaluation loop error: {e}")
                time.sleep(5)
    
    def _evaluate_metric(self, metric: MetricValue):
        """Evaluate metric against all relevant alert rules"""
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue
            
            # Check if metric matches rule patterns
            matches_pattern = False
            for pattern in rule.metric_patterns:
                if pattern in metric.name or pattern == "*":
                    matches_pattern = True
                    break
            
            if not matches_pattern:
                continue
            
            # Evaluate condition
            try:
                condition_met = self.evaluator.evaluate_condition(rule.condition, metric)
                
                if condition_met:
                    self._handle_condition_met(rule, metric)
                else:
                    self._handle_condition_not_met(rule, metric)
                    
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
    
    def _handle_condition_met(self, rule: AlertRule, metric: MetricValue):
        """Handle when alert condition is met"""
        alert_id = f"{rule.rule_id}_{metric.name}_{int(time.time())}"
        
        # Check for existing active alert for this rule and metric
        existing_alert = None
        for alert in self.active_alerts.values():
            if (alert.rule_id == rule.rule_id and 
                alert.metric_name == metric.name and 
                alert.state == AlertState.ACTIVE):
                existing_alert = alert
                break
        
        if existing_alert:
            # Update existing alert
            existing_alert.updated_at = time.time()
            existing_alert.metric_value = metric.value
            return
        
        # Create new alert
        alert = Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            name=rule.name,
            description=rule.description,
            level=rule.level,
            priority=rule.priority,
            state=AlertState.ACTIVE,
            created_at=time.time(),
            updated_at=time.time(),
            metric_name=metric.name,
            metric_value=metric.value,
            tags=metric.tags.copy(),
            context={'rule': rule, 'metric': metric}
        )
        
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        self.stats['alerts_created'] += 1
        
        logger.warning(f"Alert created: {alert.name} - {metric.name}={metric.value}")
        
        # Send notifications
        asyncio.create_task(self._send_alert_notifications(alert))
    
    def _handle_condition_not_met(self, rule: AlertRule, metric: MetricValue):
        """Handle when alert condition is not met"""
        # Check for auto-resolution
        if rule.auto_resolve:
            for alert in list(self.active_alerts.values()):
                if (alert.rule_id == rule.rule_id and 
                    alert.metric_name == metric.name and 
                    alert.state == AlertState.ACTIVE):
                    self._resolve_alert(alert.alert_id, "Condition no longer met")
    
    def _check_escalations(self):
        """Check for alerts that need escalation"""
        current_time = time.time()
        
        for alert in self.active_alerts.values():
            if alert.state != AlertState.ACTIVE:
                continue
            
            rule = self.alert_rules.get(alert.rule_id)
            if not rule or not rule.escalation_enabled:
                continue
            
            # Check if escalation time has passed
            if current_time - alert.created_at >= rule.escalation_after:
                self._escalate_alert(alert)
    
    def _check_auto_resolution(self):
        """Check for alerts that should be auto-resolved"""
        current_time = time.time()
        
        for alert in list(self.active_alerts.values()):
            if alert.state != AlertState.ACTIVE:
                continue
            
            rule = self.alert_rules.get(alert.rule_id)
            if not rule or not rule.auto_resolve:
                continue
            
            # Check if auto-resolve time has passed
            if current_time - alert.updated_at >= rule.auto_resolve_after:
                self._resolve_alert(alert.alert_id, "Auto-resolved after timeout")
    
    def _perform_correlation(self):
        """Perform alert correlation"""
        active_alerts = [alert for alert in self.active_alerts.values() 
                        if alert.state == AlertState.ACTIVE]
        
        if len(active_alerts) < 2:
            return
        
        correlated_groups = self.correlator.correlate_alerts(active_alerts)
        
        for group in correlated_groups:
            if len(group) > 1:
                self._handle_correlated_alerts(group)
                self.stats['correlations_found'] += 1
    
    def _handle_correlated_alerts(self, alerts: List[Alert]):
        """Handle a group of correlated alerts"""
        # Find the root cause alert (highest priority or earliest)
        root_alert = max(alerts, key=lambda a: (a.priority.value, -a.created_at))
        
        # Link other alerts to root cause
        for alert in alerts:
            if alert.alert_id != root_alert.alert_id:
                alert.root_cause_alert = root_alert.alert_id
                root_alert.correlated_alerts.append(alert.alert_id)
        
        logger.info(f"Correlated {len(alerts)} alerts with root cause: {root_alert.name}")
    
    def _escalate_alert(self, alert: Alert):
        """Escalate an alert"""
        rule = self.alert_rules.get(alert.rule_id)
        if not rule or not rule.escalation_levels:
            return
        
        if alert.escalation_level < len(rule.escalation_levels):
            new_level = rule.escalation_levels[alert.escalation_level]
            old_level = alert.level
            
            alert.level = new_level
            alert.escalation_level += 1
            alert.updated_at = time.time()
            alert.state = AlertState.ESCALATED
            
            self.stats['alerts_escalated'] += 1
            
            logger.warning(f"Alert escalated: {alert.name} from {old_level.value} to {new_level.value}")
            
            # Send escalation notifications
            asyncio.create_task(self._send_alert_notifications(alert))
    
    def _resolve_alert(self, alert_id: str, reason: str = ""):
        """Resolve an alert"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.state = AlertState.RESOLVED
            alert.resolved_at = time.time()
            alert.updated_at = time.time()
            
            if reason:
                alert.context['resolution_reason'] = reason
            
            del self.active_alerts[alert_id]
            self.stats['alerts_resolved'] += 1
            
            logger.info(f"Alert resolved: {alert.name} - {reason}")
    
    async def _send_alert_notifications(self, alert: Alert):
        """Send notifications for an alert"""
        try:
            results = await self.notification_manager.send_alert_notification(alert)
            
            successful_notifications = sum(1 for success in results.values() if success)
            self.stats['notifications_sent'] += successful_notifications
            
            logger.info(f"Sent {successful_notifications}/{len(results)} notifications for alert: {alert.name}")
            
        except Exception as e:
            logger.error(f"Error sending notifications for alert {alert.alert_id}: {e}")
    
    def acknowledge_alert(self, alert_id: str, user: str = "system") -> bool:
        """Acknowledge an alert"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.state = AlertState.ACKNOWLEDGED
            alert.acknowledged_at = time.time()
            alert.updated_at = time.time()
            alert.context['acknowledged_by'] = user
            
            logger.info(f"Alert acknowledged: {alert.name} by {user}")
            return True
        
        return False
    
    def suppress_alert(self, alert_id: str, duration: int = 3600, reason: str = "") -> bool:
        """Suppress an alert for a specified duration"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.state = AlertState.SUPPRESSED
            alert.updated_at = time.time()
            alert.context['suppressed_until'] = time.time() + duration
            alert.context['suppression_reason'] = reason
            
            logger.info(f"Alert suppressed: {alert.name} for {duration}s - {reason}")
            return True
        
        return False
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return list(self.active_alerts.values())
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics"""
        active_by_level = defaultdict(int)
        active_by_priority = defaultdict(int)
        
        for alert in self.active_alerts.values():
            active_by_level[alert.level.value] += 1
            active_by_priority[alert.priority.value] += 1
        
        return {
            'stats': self.stats.copy(),
            'active_alerts_count': len(self.active_alerts),
            'active_by_level': dict(active_by_level),
            'active_by_priority': dict(active_by_priority),
            'alert_rules_count': len(self.alert_rules),
            'notification_targets_count': len(self.notification_manager.targets),
            'running': self.running
        }

# Example usage
async def main():
    """Example usage of the intelligent alert manager"""
    
    # Create alert manager
    alert_manager = IntelligentAlertManager()
    
    # Configure email notifications
    alert_manager.notification_manager.configure_smtp(
        host="smtp.example.com",
        port=587,
        username="alerts@example.com",
        password="password123"
    )
    
    # Start alert manager
    alert_manager.start()
    
    try:
        # Simulate some metrics that trigger alerts
        from metrics_collector import MetricValue
        
        # High CPU usage
        cpu_metric = MetricValue(
            name="cpu_usage_percent_total",
            value=92.5,
            timestamp=time.time(),
            source="system",
            tags={"type": "cpu"}
        )
        alert_manager.process_metric(cpu_metric)
        
        # High memory usage
        memory_metric = MetricValue(
            name="memory_usage_percent",
            value=94.2,
            timestamp=time.time(),
            source="system",
            tags={"type": "memory"}
        )
        alert_manager.process_metric(memory_metric)
        
        # Wait for processing
        await asyncio.sleep(5)
        
        # Print active alerts
        active_alerts = alert_manager.get_active_alerts()
        print(f"\n=== Active Alerts ({len(active_alerts)}) ===")
        for alert in active_alerts:
            print(f"- {alert.name}: {alert.level.value} - {alert.metric_name}={alert.metric_value}")
        
        # Print statistics
        stats = alert_manager.get_alert_stats()
        print(f"\n=== Alert Manager Statistics ===")
        print(json.dumps(stats, indent=2, default=str))
        
        # Resolve an alert
        if active_alerts:
            alert_manager._resolve_alert(active_alerts[0].alert_id, "Test resolution")
        
        await asyncio.sleep(2)
        
    finally:
        alert_manager.stop()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())