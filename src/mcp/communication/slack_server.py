"""
Enhanced Communication Hub MCP Server for enterprise messaging and alert management.

Provides multi-channel communication (Slack, Teams, Email, SMS, Webhooks) with
enterprise features including rate limiting, circuit breaker, and audit logging.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
import json
import time
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from collections import defaultdict, deque
from enum import Enum
from dataclasses import dataclass

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer
from src.core.retry import retry_network, RetryConfig
from src.core.ssrf_protection import SSRFProtectedSession, get_ssrf_protector, MODERATE_SSRF_CONFIG

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error,
    ServiceUnavailableError,
    ExternalServiceError,
    ValidationError,
    ConfigurationError,
    CircuitBreakerError,
    RateLimitError
)

__all__ = [
    "AlertPriority",
    "RateLimitConfig",
    "CircuitBreakerConfig",
    "SlackNotificationMCPServer"
]


logger = logging.getLogger(__name__)


class AlertPriority(Enum):
    """Alert priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    max_requests: int = 100
    window_seconds: int = 60
    burst_size: int = 20


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    recovery_timeout: int = 60
    half_open_requests: int = 3


class SlackNotificationMCPServer(MCPServer):
    """
    Enhanced Communication Hub MCP Server for enterprise messaging.
    
    Features:
    - Multi-channel support (Slack, Teams, Email, SMS, Webhooks)
    - Alert management with escalation and suppression
    - Rate limiting and circuit breaker patterns
    - Audit logging and compliance
    - Integration with monitoring and deployment systems
    """
    
    def __init__(
        self,
        slack_token: Optional[str] = None,
        teams_webhook: Optional[str] = None,
        smtp_config: Optional[Dict[str, Any]] = None,
        sms_config: Optional[Dict[str, Any]] = None,
        rate_limit_config: Optional[RateLimitConfig] = None,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    ):
        """Initialize Communication Hub MCP Server."""
        self.slack_token = slack_token or os.getenv("SLACK_BOT_TOKEN")
        self.teams_webhook = teams_webhook or os.getenv("TEAMS_WEBHOOK_URL")
        self.smtp_config = smtp_config or self._get_smtp_config()
        self.sms_config = sms_config or self._get_sms_config()
        
        self.rate_limit = rate_limit_config or RateLimitConfig()
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque())
        
        self.circuit_breaker = circuit_breaker_config or CircuitBreakerConfig()
        self.circuit_state: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"failures": 0, "last_failure": None, "state": "closed"}
        )
        
        self.alert_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.escalation_timers: Dict[str, asyncio.Task] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self._ssrf_session: Optional[SSRFProtectedSession] = None
        self.audit_log: List[Dict[str, Any]] = []
        
        # Initialize SSRF protector with moderate config for communication
        from src.core.ssrf_protection import SSRFProtector
        self._ssrf_protector = SSRFProtector(**MODERATE_SSRF_CONFIG)
    
    async def _make_safe_request(self, method: str, url: str, **kwargs):
        """Make HTTP request with SSRF protection."""
        if not self._ssrf_session:
            self._ssrf_session = SSRFProtectedSession(self._ssrf_protector)
            await self._ssrf_session.__aenter__()
            self.session = self._ssrf_session.session
        
        # Validate URL before making request
        validation = self._ssrf_protector.validate_url(url)
        if not validation.is_safe:
            logger.error(f"SSRF protection blocked request to {url}: {validation.reason}")
            raise Exception(f"SSRF protection: {validation.reason}")
        
        # Log suspicious URLs
        if validation.threat_level.value == "suspicious":
            logger.warning(f"Suspicious URL detected in communication: {url} - {validation.reason}")
        
        # Make the request
        return await self._ssrf_session._validate_and_request(method, url, **kwargs)
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Communication Hub server information."""
        return MCPServerInfo(
            name="communication-hub",
            version="2.0.0",
            description="Enterprise Communication Hub with multi-channel support and alert management",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "multi_channel": True,
                    "alert_management": True,
                    "rate_limiting": True,
                    "circuit_breaker": True,
                    "audit_logging": True,
                    "escalation": True,
                    "suppression": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available communication tools."""
        return [
            MCPTool(
                name="send_notification",
                description="Send multi-channel notification with smart routing",
                parameters=[
                    MCPToolParameter(name="message", type="string", description="Notification message content", required=True),
                    MCPToolParameter(name="channels", type="array", description="Target channels", required=False, default=["slack"]),
                    MCPToolParameter(name="priority", type="string", description="Message priority", required=False, 
                                   enum=["low", "medium", "high", "critical"], default="medium"),
                    MCPToolParameter(name="metadata", type="object", description="Additional metadata", required=False)
                ]
            ),
            MCPTool(
                name="send_alert",
                description="Send critical alert with escalation and suppression",
                parameters=[
                    MCPToolParameter(name="alert_type", type="string", description="Type of alert", required=True,
                                   enum=["security", "performance", "deployment", "error", "incident"]),
                    MCPToolParameter(name="severity", type="string", description="Alert severity", required=True,
                                   enum=["low", "medium", "high", "critical"]),
                    MCPToolParameter(name="title", type="string", description="Alert title", required=True),
                    MCPToolParameter(name="description", type="string", description="Alert description", required=True),
                    MCPToolParameter(name="escalation_policy", type="object", description="Custom escalation", required=False),
                    MCPToolParameter(name="suppress_duplicate", type="boolean", description="Suppress duplicates", 
                                   required=False, default=True)
                ]
            ),
            MCPTool(
                name="post_message",
                description="Direct message posting to specific channel",
                parameters=[
                    MCPToolParameter(name="channel_type", type="string", description="Channel type", required=True,
                                   enum=["slack", "teams", "email"]),
                    MCPToolParameter(name="recipient", type="string", description="Recipient identifier", required=True),
                    MCPToolParameter(name="message", type="string", description="Message content", required=True),
                    MCPToolParameter(name="attachments", type="array", description="Message attachments", required=False)
                ]
            ),
            MCPTool(
                name="create_channel",
                description="Create communication channel dynamically",
                parameters=[
                    MCPToolParameter(name="channel_type", type="string", description="Channel type", required=True,
                                   enum=["slack", "teams"]),
                    MCPToolParameter(name="channel_name", type="string", description="Channel name", required=True),
                    MCPToolParameter(name="description", type="string", description="Channel description", required=False),
                    MCPToolParameter(name="members", type="array", description="Initial members", required=False)
                ]
            ),
            MCPTool(
                name="update_status",
                description="Update status board or dashboard",
                parameters=[
                    MCPToolParameter(name="component", type="string", description="Component name", required=True),
                    MCPToolParameter(name="status", type="string", description="Component status", required=True,
                                   enum=["operational", "degraded", "partial_outage", "major_outage"]),
                    MCPToolParameter(name="message", type="string", description="Status message", required=True),
                    MCPToolParameter(name="incident_id", type="string", description="Related incident", required=False)
                ]
            ),
            MCPTool(
                name="broadcast_deployment",
                description="Broadcast deployment notification across channels",
                parameters=[
                    MCPToolParameter(name="environment", type="string", description="Deployment environment", required=True,
                                   enum=["development", "staging", "production"]),
                    MCPToolParameter(name="service", type="string", description="Service being deployed", required=True),
                    MCPToolParameter(name="version", type="string", description="Version being deployed", required=True),
                    MCPToolParameter(name="status", type="string", description="Deployment status", required=True,
                                   enum=["started", "in_progress", "completed", "failed", "rolled_back"]),
                    MCPToolParameter(name="details", type="object", description="Additional details", required=False)
                ]
            ),
            MCPTool(
                name="escalate_incident",
                description="Escalate incident with automated notification chain",
                parameters=[
                    MCPToolParameter(name="incident_id", type="string", description="Incident identifier", required=True),
                    MCPToolParameter(name="severity", type="string", description="Incident severity", required=True,
                                   enum=["low", "medium", "high", "critical"]),
                    MCPToolParameter(name="description", type="string", description="Incident description", required=True),
                    MCPToolParameter(name="escalation_chain", type="array", description="Custom chain", required=False),
                    MCPToolParameter(name="runbook_url", type="string", description="Runbook link", required=False)
                ]
            ),
            MCPTool(
                name="list_channels",
                description="List available communication channels",
                parameters=[]
            )
        ]
    
    def _get_smtp_config(self) -> Dict[str, Any]:
        """Get SMTP configuration from environment."""
        return {
            "host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
            "port": int(os.getenv("SMTP_PORT", "587")),
            "username": os.getenv("SMTP_USERNAME"),
            "password": os.getenv("SMTP_PASSWORD"),
            "use_tls": os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        }
    
    def _get_sms_config(self) -> Dict[str, Any]:
        """Get SMS configuration from environment."""
        return {
            "provider": os.getenv("SMS_PROVIDER", "twilio"),
            "account_sid": os.getenv("SMS_ACCOUNT_SID"),
            "auth_token": os.getenv("SMS_AUTH_TOKEN"),
            "from_number": os.getenv("SMS_FROM_NUMBER")
        }
    
    async def _check_rate_limit(self, key: str) -> bool:
        """Check if request is within rate limits."""
        now = time.time()
        history = self.request_history[key]
        
        while history and history[0] < now - self.rate_limit.window_seconds:
            history.popleft()
        
        if len(history) >= self.rate_limit.max_requests:
            return False
        
        recent_count = sum(1 for t in history if t > now - 10)
        if recent_count >= self.rate_limit.burst_size:
            return False
        
        history.append(now)
        return True
    
    async def _check_circuit_breaker(self, channel: str) -> bool:
        """Check circuit breaker state for channel."""
        state = self.circuit_state[channel]
        
        if state["state"] == "open":
            if state["last_failure"] and \
               time.time() - state["last_failure"] > self.circuit_breaker.recovery_timeout:
                state["state"] = "half_open"
                state["half_open_requests"] = 0
            else:
                return False
        
        elif state["state"] == "half_open":
            if state.get("half_open_requests", 0) >= self.circuit_breaker.half_open_requests:
                return False
            state["half_open_requests"] = state.get("half_open_requests", 0) + 1
        
        return True
    
    async def _record_failure(self, channel: str):
        """Record channel failure for circuit breaker."""
        state = self.circuit_state[channel]
        state["failures"] += 1
        state["last_failure"] = time.time()
        
        if state["failures"] >= self.circuit_breaker.failure_threshold:
            state["state"] = "open"
            logger.warning(f"Circuit breaker opened for channel: {channel}")
    
    async def _record_success(self, channel: str):
        """Record channel success for circuit breaker."""
        state = self.circuit_state[channel]
        
        if state["state"] == "half_open":
            state["state"] = "closed"
            state["failures"] = 0
            logger.info(f"Circuit breaker closed for channel: {channel}")
    
    def _generate_alert_hash(self, alert_type: str, title: str) -> str:
        """Generate hash for alert deduplication."""
        return hashlib.sha256(f"{alert_type}:{title}".encode()).hexdigest()
    
    async def _should_suppress_alert(self, alert_hash: str, window: int = 300) -> bool:
        """Check if alert should be suppressed."""
        now = time.time()
        return any(now - alert["timestamp"] < window for alert in self.alert_history[alert_hash])
    
    async def _audit_log_entry(self, action: str, channel: str, status: str, details: Dict[str, Any]):
        """Add entry to audit log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "channel": channel,
            "status": status,
            "details": details
        }
        
        self.audit_log.append(entry)
        
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a communication tool."""
        if not self._ssrf_session:
            self._ssrf_session = SSRFProtectedSession(self._ssrf_protector)
            await self._ssrf_session.__aenter__()
            self.session = self._ssrf_session.session
        
        try:
            if not await self._check_rate_limit(tool_name):
                raise MCPError(-32000, "Rate limit exceeded")
            
            tool_methods = {
                "send_notification": self._send_notification,
                "send_alert": self._send_alert,
                "post_message": self._post_message,
                "create_channel": self._create_channel,
                "update_status": self._update_status,
                "broadcast_deployment": self._broadcast_deployment,
                "escalate_incident": self._escalate_incident,
                "list_channels": self._list_channels
            }
            
            if tool_name in tool_methods:
                return await tool_methods[tool_name](**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling communication tool {tool_name}: {e}")
            raise
    
    async def _send_notification(
        self,
        message: str,
        channels: List[str] = None,
        priority: str = "medium",
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Send multi-channel notification."""
        channels = channels or ["slack"]
        results = {}
        
        for channel in channels:
            try:
                if not await self._check_circuit_breaker(channel):
                    results[channel] = {"success": False, "error": "Circuit breaker open"}
                    continue
                
                result = await self._send_to_channel(channel, message, priority, metadata)
                results[channel] = result
                
                if result.get("success"):
                    await self._record_success(channel)
                else:
                    await self._record_failure(channel)
                
                await self._audit_log_entry(
                    "send_notification", channel,
                    "success" if result.get("success") else "failure",
                    {"priority": priority, "metadata": metadata}
                )
                
            except Exception as e:
                logger.error(f"Error sending to {channel}: {e}")
                results[channel] = {"success": False, "error": str(e)}
                await self._record_failure(channel)
        
        return {
            "channels": results,
            "message": message,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _send_to_channel(
        self, channel: str, message: str, priority: str, metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Send message to specific channel type."""
        channel_handlers = {
            "slack": self._send_slack_message,
            "teams": self._send_teams_message,
            "email": self._send_email,
            "sms": self._send_sms,
            "webhook": self._send_webhook
        }
        
        handler = channel_handlers.get(channel)
        if handler:
            return await handler(message, priority, metadata)
        else:
            return {"success": False, "error": "Unknown channel type"}
    
    async def _send_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        escalation_policy: Dict[str, Any] = None,
        suppress_duplicate: bool = True
    ) -> Dict[str, Any]:
        """Send alert with escalation and suppression."""
        alert_hash = self._generate_alert_hash(alert_type, title)
        
        if suppress_duplicate and await self._should_suppress_alert(alert_hash):
            return {
                "status": "suppressed",
                "alert_hash": alert_hash,
                "reason": "Duplicate alert within suppression window"
            }
        
        alert_record = {
            "timestamp": time.time(),
            "type": alert_type,
            "severity": severity,
            "title": title,
            "description": description
        }
        self.alert_history[alert_hash].append(alert_record)
        
        priority = AlertPriority(severity)
        channels = self._get_alert_channels(priority)
        
        alert_message = self._format_alert_message(alert_type, severity, title, description)
        
        result = await self._send_notification(
            message=alert_message,
            channels=channels,
            priority=severity,
            metadata={"alert_type": alert_type, "alert_hash": alert_hash}
        )
        
        if priority in [AlertPriority.HIGH, AlertPriority.CRITICAL]:
            escalation_task = asyncio.create_task(
                self._handle_escalation(alert_hash, alert_type, severity, title, description, escalation_policy)
            )
            self.escalation_timers[alert_hash] = escalation_task
        
        return {
            "status": "sent",
            "alert_hash": alert_hash,
            "channels": result["channels"],
            "escalation": priority.value in ["high", "critical"]
        }
    
    async def _handle_escalation(
        self, alert_hash: str, alert_type: str, severity: str, 
        title: str, description: str, escalation_policy: Dict[str, Any] = None
    ):
        """Handle alert escalation."""
        policy = escalation_policy or self._get_default_escalation_policy(severity)
        
        for level in policy.get("levels", []):
            await asyncio.sleep(level["delay"])
            
            if alert_hash not in self.escalation_timers:
                break
            
            escalation_message = self._format_escalation_message(
                alert_type, severity, title, description, level["name"]
            )
            
            await self._send_notification(
                message=escalation_message,
                channels=level["channels"],
                priority="critical",
                metadata={"alert_hash": alert_hash, "escalation_level": level["name"]}
            )
    
    def _get_alert_channels(self, priority: AlertPriority) -> List[str]:
        """Get channels based on alert priority."""
        channel_map = {
            AlertPriority.LOW: ["slack"],
            AlertPriority.MEDIUM: ["slack", "email"],
            AlertPriority.HIGH: ["slack", "email", "teams"],
            AlertPriority.CRITICAL: ["slack", "email", "teams", "sms"]
        }
        return channel_map.get(priority, ["slack"])
    
    def _format_alert_message(self, alert_type: str, severity: str, title: str, description: str) -> str:
        """Format alert message."""
        severity_emoji = {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
        
        return (
            f"{severity_emoji.get(severity, '❓')} **{severity.upper()} ALERT**
"
            f"**Type**: {alert_type}
**Title**: {title}
"
            f"**Description**: {description}
"
            f"**Time**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
    
    def _format_escalation_message(
        self, alert_type: str, severity: str, title: str, description: str, escalation_level: str
    ) -> str:
        """Format escalation message."""
        return (
            f"🔴 **ESCALATION: {escalation_level}**
"
            f"**Original Alert**: {title}
**Type**: {alert_type}
"
            f"**Severity**: {severity}
**Description**: {description}
"
            f"**Action Required**: Immediate attention needed
"
            f"**Escalated At**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
    
    def _get_default_escalation_policy(self, severity: str) -> Dict[str, Any]:
        """Get default escalation policy based on severity."""
        policies = {
            "high": {
                "levels": [
                    {"name": "Level 1 - Team Lead", "delay": 300, "channels": ["slack", "email"]},
                    {"name": "Level 2 - Manager", "delay": 600, "channels": ["slack", "email", "sms"]}
                ]
            },
            "critical": {
                "levels": [
                    {"name": "Level 1 - On-Call Engineer", "delay": 60, "channels": ["slack", "sms"]},
                    {"name": "Level 2 - Team Lead", "delay": 180, "channels": ["slack", "email", "sms"]},
                    {"name": "Level 3 - CTO", "delay": 300, "channels": ["sms"]}
                ]
            }
        }
        return policies.get(severity, {"levels": []})
    
    @retry_network(max_attempts=3, timeout=30)
    async def _send_slack_message(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via Slack."""
        if not self.slack_token:
            return {"success": False, "error": "Slack token not configured"}
        
        headers = {"Authorization": f"Bearer {self.slack_token}", "Content-Type": "application/json"}
        channel = metadata.get("slack_channel", "#general") if metadata else "#general"
        
        payload = {
            "channel": channel,
            "text": message,
            "username": "CODE Communication Hub",
            "icon_emoji": ":satellite:"
        }
        
        try:
            response = await self._make_safe_request(
                "POST", "https://slack.com/api/chat.postMessage", headers=headers, json=payload
            )
            data = await response.json()
            return {"success": data.get("ok", False), "channel": channel, "ts": data.get("ts")}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @retry_network(max_attempts=3, timeout=30)
    async def _send_teams_message(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via Microsoft Teams."""
        if not self.teams_webhook:
            return {"success": False, "error": "Teams webhook not configured"}
        
        color = {"low": "0078D4", "medium": "FFA500", "high": "FF6347", "critical": "DC143C"}.get(priority, "808080")
        
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": "CODE Communication Hub",
            "sections": [{
                "activityTitle": "CODE Notification",
                "text": message,
                "markdown": True
            }]
        }
        
        try:
            response = await self._make_safe_request("POST", self.teams_webhook, json=payload)
            return {"success": response.status == 200, "status": response.status}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_email(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via email."""
        if not self.smtp_config.get("username"):
            return {"success": False, "error": "SMTP not configured"}
        
        try:
            recipients = metadata.get("email_recipients", []) if metadata else []
            if not recipients:
                return {"success": False, "error": "No email recipients specified"}
            
            msg = MIMEMultipart()
            msg["From"] = self.smtp_config["username"]
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"[{priority.upper()}] CODE Notification"
            
            msg.attach(MIMEText(message, "plain"))
            
            with smtplib.SMTP(self.smtp_config["host"], self.smtp_config["port"]) as server:
                if self.smtp_config.get("use_tls"):
                    server.starttls()
                server.login(self.smtp_config["username"], self.smtp_config["password"])
                server.send_message(msg)
            
            return {"success": True, "recipients": recipients}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_sms(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via SMS."""
        if not self.sms_config.get("auth_token"):
            return {"success": False, "error": "SMS not configured"}
        
        sms_message = message[:160] if len(message) > 160 else message
        
        return {"success": True, "message": "SMS integration placeholder", "truncated": len(message) > 160}
    
    async def _send_webhook(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via webhook."""
        webhook_url = metadata.get("webhook_url") if metadata else None
        if not webhook_url:
            return {"success": False, "error": "Webhook URL not provided"}
        
        payload = {
            "message": message,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "CODE Communication Hub"
        }
        
        try:
            response = await self._make_safe_request("POST", webhook_url, json=payload)
            return {"success": response.status in [200, 201, 202], "status": response.status}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _post_message(
        self, channel_type: str, recipient: str, message: str, attachments: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Direct message posting."""
        metadata = {
            f"{channel_type}_channel": recipient if channel_type == "slack" else None,
            "email_recipients": [recipient] if channel_type == "email" else None
        }
        
        return await self._send_to_channel(channel_type, message, "medium", metadata)
    
    async def _create_channel(
        self, channel_type: str, channel_name: str, description: str = None, members: List[str] = None
    ) -> Dict[str, Any]:
        """Create communication channel."""
        if channel_type == "slack" and self.slack_token:
            headers = {"Authorization": f"Bearer {self.slack_token}", "Content-Type": "application/json"}
            payload = {"name": channel_name, "is_private": False}
            
            response = await self._make_safe_request(
                "POST", "https://slack.com/api/conversations.create", headers=headers, json=payload
            )
            data = await response.json()
            return {
                "success": data.get("ok", False),
                "channel_id": data.get("channel", {}).get("id"),
                "channel_name": channel_name
            }
        
        return {"success": False, "error": f"Channel creation not supported for {channel_type}"}
    
    async def _update_status(
        self, component: str, status: str, message: str, incident_id: str = None
    ) -> Dict[str, Any]:
        """Update status board."""
        status_message = f"**Status Update**
Component: {component}
Status: {status}
Message: {message}"
        
        if incident_id:
            status_message += f"\nIncident ID: {incident_id}"\n\n        result = await self._send_notification(\n            message=status_message,\n            channels=["slack", "teams"],\n            priority="high" if status in ["partial_outage", "major_outage"] else "medium",\n            metadata={"component": component, "status": status}\n        )\n\n        return {"component": component, "status": status, "notification_sent": result["channels"]}\n\n    async def _broadcast_deployment(\n        self, environment: str, service: str, version: str, status: str, details: Dict[str, Any] = None\n    ) -> Dict[str, Any]:\n        """Broadcast deployment notification."""\n        status_emoji = {\n            "started": "🚀", "in_progress": "⏳", "completed": "✅",\n            "failed": "❌", "rolled_back": "↩️"\n        }.get(status, "📦")\n\n        deployment_message = (\n            f"{status_emoji} **Deployment {status.replace('_', ' ').title()}**\n"\n            f"Environment: {environment}\nService: {service}\nVersion: {version}"\n        )\n\n        if details:\n            for key, value in details.items():\n                deployment_message += f"\n{key}: {value}"\n\n        channels = ["slack"] if environment == "development" else ["slack", "teams", "email"]\n\n        result = await self._send_notification(\n            message=deployment_message,\n            channels=channels,\n            priority="high" if status in ["failed", "rolled_back"] else "medium",\n            metadata={"deployment": True, "environment": environment, "service": service, "version": version}\n        )\n\n        return {\n            "broadcast_sent": True,\n            "channels": result["channels"],\n            "environment": environment,\n            "service": service,\n            "version": version,\n            "status": status\n        }\n\n    async def _escalate_incident(\n        self, incident_id: str, severity: str, description: str,\n        escalation_chain: List[Dict[str, Any]] = None, runbook_url: str = None\n    ) -> Dict[str, Any]:\n        """Escalate incident with notification chain."""\n        incident_message = (\n            f"🚨 **INCIDENT ESCALATION**\nIncident ID: {incident_id}\n"\n            f"Severity: {severity.upper()}\nDescription: {description}"\n        )\n\n        if runbook_url:\n            incident_message += f"\nRunbook: {runbook_url}"\n\n        chain = escalation_chain or self._get_default_escalation_policy(severity).get("levels", [])\n\n        initial_result = await self._send_notification(\n            message=incident_message,\n            channels=["slack", "teams", "sms"] if severity == "critical" else ["slack", "teams"],\n            priority=severity,\n            metadata={"incident_id": incident_id}\n        )\n\n        if chain:\n            escalation_task = asyncio.create_task(\n                self._handle_incident_escalation(incident_id, severity, description, chain, runbook_url)\n            )\n            self.escalation_timers[f"incident_{incident_id}"] = escalation_task\n\n        return {\n            "incident_id": incident_id,\n            "initial_notification": initial_result["channels"],\n            "escalation_setup": bool(chain),\n            "severity": severity\n        }\n\n    async def _handle_incident_escalation(\n        self, incident_id: str, severity: str, description: str,\n        escalation_chain: List[Dict[str, Any]], runbook_url: str = None\n    ):\n        """Handle incident escalation chain."""\n        for level in escalation_chain:\n            await asyncio.sleep(level.get("delay", 300))\n\n            if f"incident_{incident_id}" not in self.escalation_timers:\n                break\n\n            escalation_message = (\n                f"🔴 **INCIDENT ESCALATION - {level.get('name', 'Next Level')}**\n"\n                f"Incident ID: {incident_id}\nSeverity: {severity.upper()}\n"\n                f"Description: {description}\n"\n                f"Escalation Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"\n            )\n\n            if runbook_url:\n                escalation_message += f"\nRunbook: {runbook_url}"\n\n            await self._send_notification(\n                message=escalation_message,\n                channels=level.get("channels", ["slack", "email"]),\n                priority="critical",\n                metadata={"incident_id": incident_id, "escalation_level": level.get("name")}\n            )\n\n    async def _list_channels(self) -> Dict[str, Any]:\n        """List available communication channels."""\n        channels = []\n\n        # List Slack channels if configured\n        if self.slack_token:\n            channels.append({\n                "type": "slack",\n                "name": "slack",\n                "status": "configured",\n                "capabilities": ["text", "attachments", "threads"]\n            })\n\n        # List other configured channels\n        if self.smtp_config.get("host"):\n            channels.append({\n                "type": "email",\n                "name": "email",\n                "status": "configured",\n                "capabilities": ["text", "html", "attachments"]\n            })\n\n        # Always available channels\n        channels.extend([\n            {\n                "type": "teams",\n                "name": "teams",\n                "status": "available",\n                "capabilities": ["text", "cards", "mentions"]\n            },\n            {\n                "type": "sms",\n                "name": "sms",\n                "status": "available",\n                "capabilities": ["text"]\n            },\n            {\n                "type": "webhook",\n                "name": "webhook",\n                "status": "available",\n                "capabilities": ["json", "custom"]\n            }\n        ])\n\n        return {\n            "channels": channels,\n            "total": len(channels),\n            "configured": sum(1 for c in channels if c["status"] == "configured")\n        }\n\n    async def close(self):\n        """Close the communication hub."""\n        for task in self.escalation_timers.values():\n            task.cancel()\n        if self._ssrf_session:\n            await self._ssrf_session.__aexit__(None, None, None)\n            self._ssrf_session = None\n        if self.session:\n            await self.session.close()\n            self.session = None\n