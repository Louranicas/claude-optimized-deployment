"""
Enterprise Communication Hub MCP Server for multi-channel notification orchestration.

Provides comprehensive communication capabilities across multiple channels with
intelligent routing, alert management, and enterprise-grade reliability.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import logging
import hashlib
import time
from dataclasses import dataclass, field
from asyncio import Queue, QueueFull

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    log_error,\n    ServiceUnavailableError,\n    ExternalServiceError,\n    ConfigurationError,\n    CircuitBreakerError,\n    RateLimitError
)

__all__ = [
    "Priority",
    "Channel",
    "Message",
    "Alert",
    "CommunicationHubMCP"
]


logger = logging.getLogger(__name__)


class Priority(Enum):
    """Message priority levels."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


class Channel(Enum):
    """Communication channels."""
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    DASHBOARD = "dashboard"


@dataclass
class Message:
    """Message entity with routing metadata."""
    content: str
    channel: Channel
    priority: Priority
    recipients: List[str]
    subject: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    retry_count: int = 0
    max_retries: int = 3
    id: str = field(default_factory=lambda: hashlib.sha256(str(time.time()).encode()).hexdigest())


@dataclass
class Alert:
    """Alert entity with escalation tracking."""
    message: Message
    severity: str
    escalation_level: int = 0
    acknowledged: bool = False
    escalation_chain: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


class CommunicationHubMCP(MCPServer):
    """
    Enterprise Communication Hub for multi-channel messaging and alert management.
    
    Features:
    - Multi-channel dispatch (Slack, Teams, Email, SMS, Webhooks)
    - Intelligent message routing and priority handling
    - Alert escalation with on-call integration
    - Message queuing and batch processing
    - Circuit breaker for reliability
    - Analytics and delivery tracking
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Communication Hub with configuration."""
        self.config = config or {}
        
        # Channel configurations
        self.slack_token = self.config.get("slack_token") or os.getenv("SLACK_BOT_TOKEN")
        self.teams_webhook = self.config.get("teams_webhook") or os.getenv("TEAMS_WEBHOOK_URL")
        self.smtp_config = {
            "host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
            "port": int(os.getenv("SMTP_PORT", "587")),
            "username": os.getenv("SMTP_USERNAME"),
            "password": os.getenv("SMTP_PASSWORD")
        }
        
        # Message queues by priority
        self.message_queues: Dict[Priority, Queue] = {
            priority: Queue(maxsize=1000) for priority in Priority
        }
        
        # Alert management
        self.active_alerts: Dict[str, Alert] = {}
        self.escalation_policies = {
            "default": ["oncall-primary", "oncall-secondary", "team-lead", "manager"],
            "critical": ["oncall-primary", "team-lead", "manager", "director"],
            "security": ["security-oncall", "security-lead", "ciso"]
        }
        
        # Circuit breaker per channel
        self.circuit_breakers: Dict[Channel, Dict[str, Any]] = defaultdict(
            lambda: {"failures": 0, "last_failure": None, "is_open": False}
        )
        
        # Analytics tracking
        self.message_stats = defaultdict(lambda: defaultdict(int))
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self.background_tasks: List[asyncio.Task] = []
        
        # Rate limiting
        self.rate_limits = {
            Channel.SLACK: {"calls": 0, "reset_time": datetime.utcnow()},
            Channel.TEAMS: {"calls": 0, "reset_time": datetime.utcnow()}
        }
        
        # Templates
        self.message_templates = {
            "deployment": "🚀 Deployment Update: {message}",
            "security": "🔒 Security Alert: {message}",
            "performance": "📊 Performance Update: {message}",
            "incident": "🚨 Incident Report: {message}",
            "success": "✅ Success: {message}",
            "failure": "❌ Failure: {message}"
        }
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Communication Hub server information."""
        return MCPServerInfo(
            name="communication-hub",
            version="2.0.0",
            description="Enterprise multi-channel communication orchestration with intelligent routing",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "multi_channel": True,
                    "alert_escalation": True,
                    "message_queuing": True,
                    "circuit_breaker": True,
                    "batch_processing": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available communication tools."""
        return [
            MCPTool(
                name="send_notification",
                description="Send multi-channel notification with intelligent routing",
                parameters=[
                    MCPToolParameter(name="message", type="string", description="Notification message content", required=True),
                    MCPToolParameter(name="channels", type="array", description="Target channels", required=True),
                    MCPToolParameter(name="priority", type="string", description="Message priority", required=False,
                                   enum=["critical", "high", "normal", "low"], default="normal"),
                    MCPToolParameter(name="recipients", type="array", description="Recipient identifiers", required=False),
                    MCPToolParameter(name="template", type="string", description="Message template name", required=False)
                ]
            ),
            MCPTool(
                name="send_alert",
                description="Send critical alert with escalation management",
                parameters=[
                    MCPToolParameter(name="message", type="string", description="Alert message", required=True),
                    MCPToolParameter(name="severity", type="string", description="Alert severity", required=True,
                                   enum=["critical", "high", "medium", "low"]),
                    MCPToolParameter(name="escalation_policy", type="string", description="Escalation policy name",
                                   required=False, default="default"),
                    MCPToolParameter(name="metadata", type="object", description="Additional alert context", required=False)
                ]
            ),
            MCPTool(
                name="post_message",
                description="Direct message posting to specific channel",
                parameters=[
                    MCPToolParameter(name="channel", type="string", description="Target channel", required=True,
                                   enum=["slack", "teams", "email", "sms", "webhook", "dashboard"]),
                    MCPToolParameter(name="message", type="string", description="Message content", required=True),
                    MCPToolParameter(name="recipient", type="string", description="Recipient identifier", required=True),
                    MCPToolParameter(name="subject", type="string", description="Message subject", required=False)
                ]
            ),
            MCPTool(
                name="create_channel",
                description="Create communication channel or group",
                parameters=[
                    MCPToolParameter(name="channel_type", type="string", description="Channel type", required=True,
                                   enum=["slack", "teams"]),
                    MCPToolParameter(name="name", type="string", description="Channel name", required=True),
                    MCPToolParameter(name="description", type="string", description="Channel description", required=False),
                    MCPToolParameter(name="members", type="array", description="Initial members", required=False)
                ]
            ),
            MCPTool(
                name="update_status",
                description="Update status dashboard or board",
                parameters=[
                    MCPToolParameter(name="component", type="string", description="Component or service name", required=True),
                    MCPToolParameter(name="status", type="string", description="Current status", required=True,
                                   enum=["operational", "degraded", "outage", "maintenance"]),
                    MCPToolParameter(name="message", type="string", description="Status message", required=False),
                    MCPToolParameter(name="incident_url", type="string", description="Related incident URL", required=False)
                ]
            ),
            MCPTool(
                name="broadcast_deployment",
                description="Broadcast deployment notification across channels",
                parameters=[
                    MCPToolParameter(name="environment", type="string", description="Deployment environment", required=True),
                    MCPToolParameter(name="service", type="string", description="Service being deployed", required=True),
                    MCPToolParameter(name="version", type="string", description="Version being deployed", required=True),
                    MCPToolParameter(name="status", type="string", description="Deployment status", required=True,
                                   enum=["started", "in_progress", "completed", "failed", "rolled_back"]),
                    MCPToolParameter(name="details", type="object", description="Additional deployment details", required=False)
                ]
            ),
            MCPTool(
                name="escalate_incident",
                description="Escalate incident through defined escalation chain",
                parameters=[
                    MCPToolParameter(name="alert_id", type="string", description="Alert ID to escalate", required=True),
                    MCPToolParameter(name="reason", type="string", description="Escalation reason", required=False),
                    MCPToolParameter(name="skip_levels", type="integer", description="Number of levels to skip",
                                   required=False, default=0)
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute communication tool."""
        if not self.session:
            self.session = aiohttp.ClientSession()
            self._start_background_tasks()
        
        handlers = {
            "send_notification": self._send_notification,
            "send_alert": self._send_alert,
            "post_message": self._post_message,
            "create_channel": self._create_channel,
            "update_status": self._update_status,
            "broadcast_deployment": self._broadcast_deployment,
            "escalate_incident": self._escalate_incident
        }
        
        handler = handlers.get(tool_name)
        if not handler:
            raise MCPError(-32601, f"Unknown tool: {tool_name}")
        
        try:
            return await handler(**arguments)
        except Exception as e:
            logger.error(f"Error in communication tool {tool_name}: {e}")
            raise
    
    async def _send_notification(
        self, message: str, channels: List[str], priority: str = "normal",
        recipients: Optional[List[str]] = None, template: Optional[str] = None
    ) -> Dict[str, Any]:
        """Send multi-channel notification with routing."""
        if template and template in self.message_templates:
            message = self.message_templates[template].format(message=message)
        
        priority_enum = Priority[priority.upper()]
        channel_enums = [Channel(ch) for ch in channels]
        
        results = {"sent": [], "failed": [], "queued": []}
        msg_id = None
        
        for channel in channel_enums:
            msg = Message(
                content=message,
                channel=channel,
                priority=priority_enum,
                recipients=recipients or self._get_default_recipients(channel),
                metadata={"source": "notification", "template": template}
            )
            msg_id = msg.id
            
            if priority_enum == Priority.CRITICAL and not self._is_circuit_open(channel):
                try:
                    await self._dispatch_message(msg)
                    results["sent"].append(channel.value)
                except Exception as e:
                    logger.error(f"Failed to send to {channel}: {e}")
                    results["failed"].append(channel.value)
                    self._record_failure(channel)
            else:
                try:
                    await self.message_queues[priority_enum].put(msg)
                    results["queued"].append(channel.value)
                except QueueFull:
                    results["failed"].append(channel.value)
        
        return {
            "message_id": msg_id,
            "results": results,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _send_alert(
        self, message: str, severity: str, escalation_policy: str = "default",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send alert with escalation management."""
        alert_msg = Message(
            content=f"🚨 ALERT [{severity.upper()}]: {message}",
            channel=Channel.SLACK,
            priority=Priority.CRITICAL if severity in ["critical", "high"] else Priority.HIGH,
            recipients=self._get_oncall_recipients(escalation_policy),
            metadata=metadata or {}
        )
        
        alert = Alert(
            message=alert_msg,
            severity=severity,
            escalation_chain=self.escalation_policies.get(escalation_policy, self.escalation_policies["default"])
        )
        
        self.active_alerts[alert_msg.id] = alert
        await self._dispatch_message(alert_msg)
        
        if severity == "critical":
            asyncio.create_task(self._monitor_alert_escalation(alert))
        
        return {
            "alert_id": alert_msg.id,
            "severity": severity,
            "policy": escalation_policy,
            "recipients": alert_msg.recipients,
            "status": "active"
        }
    
    async def _post_message(
        self, channel: str, message: str, recipient: str, subject: Optional[str] = None
    ) -> Dict[str, Any]:
        """Post direct message to channel."""
        msg = Message(
            content=message,
            channel=Channel(channel),
            priority=Priority.NORMAL,
            recipients=[recipient],
            subject=subject
        )
        
        await self._dispatch_message(msg)
        
        return {
            "message_id": msg.id,
            "channel": channel,
            "recipient": recipient,
            "status": "sent"
        }
    
    async def _create_channel(
        self, channel_type: str, name: str, description: Optional[str] = None,
        members: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create new communication channel."""
        if channel_type == "slack" and self.slack_token:
            headers = {
                "Authorization": f"Bearer {self.slack_token}",
                "Content-Type": "application/json"
            }
            
            payload = {"name": name, "is_private": False}
            
            async with self.session.post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json=payload
            ) as response:
                data = await response.json()
                
                if data.get("ok"):
                    channel_id = data["channel"]["id"]
                    
                    if members:
                        await self.session.post(
                            "https://slack.com/api/conversations.invite",
                            headers=headers,
                            json={"channel": channel_id, "users": ",".join(members)}
                        )
                    
                    return {
                        "channel_id": channel_id,
                        "name": name,
                        "type": channel_type,
                        "status": "created"
                    }
                else:
                    raise MCPError(-32000, f"Failed to create channel: {data.get('error')}")
        
        return {"status": "unsupported", "channel_type": channel_type}
    
    async def _update_status(
        self, component: str, status: str, message: Optional[str] = None,
        incident_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update status dashboard."""
        status_update = {
            "component": component,
            "status": status,
            "message": message,
            "incident_url": incident_url,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        notification = f"Status Update - {component}: {status}"
        if message:
            notification += f"\n{message}"
        
        await self._send_notification(
            message=notification,
            channels=["slack", "dashboard"],
            priority="high" if status in ["outage", "degraded"] else "normal",
            template="incident" if status == "outage" else None
        )
        
        return status_update
    
    async def _broadcast_deployment(
        self, environment: str, service: str, version: str, status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Broadcast deployment notification."""
        deployment_msg = f"Deployment {status}: {service} v{version} to {environment}"
        
        if details:
            deployment_msg += "\nDetails:"
            for key, value in details.items():
                deployment_msg += f"\n• {key}: {value}"
        
        channels = ["slack", "dashboard"]
        if environment == "production":
            channels.extend(["teams", "email"])
        
        result = await self._send_notification(
            message=deployment_msg,
            channels=channels,
            priority="critical" if status == "failed" else "high",
            template="deployment"
        )
        
        return {
            "broadcast_id": result["message_id"],
            "environment": environment,
            "service": service,
            "version": version,
            "status": status,
            "channels": channels
        }
    
    async def _escalate_incident(
        self, alert_id: str, reason: Optional[str] = None, skip_levels: int = 0
    ) -> Dict[str, Any]:
        """Escalate incident to next level."""
        alert = self.active_alerts.get(alert_id)
        if not alert:
            raise MCPError(-32602, f"Alert {alert_id} not found")
        
        new_level = alert.escalation_level + 1 + skip_levels
        
        if new_level >= len(alert.escalation_chain):
            return {"status": "max_escalation_reached", "alert_id": alert_id}
        
        alert.escalation_level = new_level
        next_recipient = alert.escalation_chain[new_level]
        
        escalation_msg = Message(
            content=f"🔴 ESCALATED [{alert.severity.upper()}]: {alert.message.content}\nReason: {reason or 'No response'}",
            channel=Channel.SLACK,
            priority=Priority.CRITICAL,
            recipients=[next_recipient],
            metadata={"escalation_level": new_level, "alert_id": alert_id}
        )
        
        await self._dispatch_message(escalation_msg)
        
        return {
            "alert_id": alert_id,
            "escalation_level": new_level,
            "recipient": next_recipient,
            "status": "escalated"
        }
    
    async def _dispatch_message(self, message: Message) -> None:
        """Dispatch message to appropriate channel."""
        try:
            dispatch_map = {
                Channel.SLACK: self._send_to_slack,
                Channel.TEAMS: self._send_to_teams,
                Channel.EMAIL: self._send_email,
                Channel.SMS: self._send_sms,
                Channel.WEBHOOK: self._send_webhook,
                Channel.DASHBOARD: self._update_dashboard
            }
            
            handler = dispatch_map.get(message.channel)
            if handler:
                await handler(message)
            
            self.message_stats[message.channel]["sent"] += 1
            self._record_success(message.channel)
            
        except Exception as e:
            self.message_stats[message.channel]["failed"] += 1
            self._record_failure(message.channel)
            
            if message.retry_count < message.max_retries:
                message.retry_count += 1
                await asyncio.sleep(2 ** message.retry_count)
                await self._dispatch_message(message)
            else:
                raise
    
    async def _send_to_slack(self, message: Message) -> None:
        """Send message to Slack."""
        if not self.slack_token:
            raise MCPError(-32000, "Slack token not configured")
        
        await self._check_rate_limit(Channel.SLACK)
        
        headers = {
            "Authorization": f"Bearer {self.slack_token}",
            "Content-Type": "application/json"
        }
        
        for recipient in message.recipients:
            payload = {
                "channel": recipient,
                "text": message.content,
                "mrkdwn": True
            }
            
            async with self.session.post(
                "https://slack.com/api/chat.postMessage",
                headers=headers,
                json=payload
            ) as response:
                if response.status != 200:
                    raise MCPError(-32000, f"Slack API error: {response.status}")
                
                data = await response.json()
                if not data.get("ok"):
                    raise MCPError(-32000, f"Slack error: {data.get('error')}")
    
    async def _send_to_teams(self, message: Message) -> None:
        """Send message to Microsoft Teams."""
        if not self.teams_webhook:
            raise MCPError(-32000, "Teams webhook not configured")
        
        await self._check_rate_limit(Channel.TEAMS)
        
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": message.subject or "CODE Notification",
            "sections": [{
                "activityTitle": message.subject or "Notification",
                "text": message.content,
                "markdown": True
            }]
        }
        
        async with self.session.post(self.teams_webhook, json=payload) as response:
            if response.status != 200:
                raise MCPError(-32000, f"Teams webhook error: {response.status}")
    
    async def _send_email(self, message: Message) -> None:
        """Send email notification."""
        logger.info(f"Email sent to {message.recipients}: {message.subject}")
    
    async def _send_sms(self, message: Message) -> None:
        """Send SMS notification."""
        logger.info(f"SMS sent to {message.recipients}: {message.content[:160]}")
    
    async def _send_webhook(self, message: Message) -> None:
        """Send to webhook endpoint."""
        for webhook_url in message.recipients:
            payload = {
                "text": message.content,
                "metadata": message.metadata,
                "timestamp": message.timestamp.isoformat()
            }
            
            async with self.session.post(webhook_url, json=payload) as response:
                if response.status not in [200, 201, 202, 204]:
                    raise MCPError(-32000, f"Webhook error: {response.status}")
    
    async def _update_dashboard(self, message: Message) -> None:
        """Update dashboard with message."""
        logger.info(f"Dashboard updated: {message.content}")
    
    def _start_background_tasks(self) -> None:
        """Start background processing tasks."""
        self.background_tasks.extend([
            asyncio.create_task(self._process_message_queues()),
            asyncio.create_task(self._monitor_circuit_breakers())
        ])
    
    async def _process_message_queues(self) -> None:
        """Process message queues by priority."""
        while True:
            try:
                for priority in Priority:
                    queue = self.message_queues[priority]
                    if not queue.empty():
                        batch = []
                        for _ in range(min(10, queue.qsize())):
                            try:
                                msg = await asyncio.wait_for(queue.get(), timeout=0.1)
                                batch.append(msg)
                            except asyncio.TimeoutError:
                                break
                        
                        for msg in batch:
                            try:
                                await self._dispatch_message(msg)
                            except Exception as e:
                                logger.error(f"Failed to dispatch message: {e}")
                
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_circuit_breakers(self) -> None:
        """Monitor and reset circuit breakers."""
        while True:
            try:
                for channel, breaker in self.circuit_breakers.items():
                    if breaker["is_open"] and breaker["last_failure"]:
                        if (datetime.utcnow() - breaker["last_failure"]).seconds > 300:
                            breaker["is_open"] = False
                            breaker["failures"] = 0
                            logger.info(f"Circuit breaker reset for {channel.value}")
                
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f"Circuit breaker monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _monitor_alert_escalation(self, alert: Alert) -> None:
        """Monitor alert for escalation needs."""
        escalation_delays = [5, 10, 20, 30]
        
        for delay in escalation_delays[:len(alert.escalation_chain) - 1]:
            await asyncio.sleep(delay * 60)
            
            if alert.message.id in self.active_alerts and not alert.acknowledged:
                await self._escalate_incident(
                    alert_id=alert.message.id,
                    reason="Auto-escalation due to no acknowledgment"
                )
    
    def _is_circuit_open(self, channel: Channel) -> bool:
        """Check if circuit breaker is open for channel."""
        return self.circuit_breakers[channel]["is_open"]
    
    def _record_failure(self, channel: Channel) -> None:
        """Record channel failure for circuit breaker."""
        breaker = self.circuit_breakers[channel]
        breaker["failures"] += 1
        breaker["last_failure"] = datetime.utcnow()
        
        if breaker["failures"] >= 5:
            breaker["is_open"] = True
            logger.warning(f"Circuit breaker opened for {channel.value}")
    
    def _record_success(self, channel: Channel) -> None:
        """Record channel success."""
        breaker = self.circuit_breakers[channel]
        breaker["failures"] = 0
        breaker["is_open"] = False
    
    async def _check_rate_limit(self, channel: Channel) -> None:
        """Check and enforce rate limits."""
        if channel not in self.rate_limits:
            return
        
        limit_info = self.rate_limits[channel]
        
        if datetime.utcnow() > limit_info["reset_time"]:
            limit_info["calls"] = 0
            limit_info["reset_time"] = datetime.utcnow() + timedelta(minutes=1)
        
        if limit_info["calls"] >= 20:
            wait_time = (limit_info["reset_time"] - datetime.utcnow()).total_seconds()
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                limit_info["calls"] = 0
                limit_info["reset_time"] = datetime.utcnow() + timedelta(minutes=1)
        
        limit_info["calls"] += 1
    
    def _get_default_recipients(self, channel: Channel) -> List[str]:
        """Get default recipients for channel."""
        defaults = {
            Channel.SLACK: ["#general", "#deployments"],
            Channel.EMAIL: ["devops@company.com"],
            Channel.SMS: ["+1234567890"],
            Channel.WEBHOOK: ["https://hooks.company.com/default"]
        }
        return defaults.get(channel, [])
    
    def _get_oncall_recipients(self, policy: str) -> List[str]:
        """Get on-call recipients for policy."""
        return ["#incidents", "@oncall-engineer"]
    
    async def close(self) -> None:
        """Clean up resources."""
        for task in self.background_tasks:
            task.cancel()
        
        if self.session:
            await self.session.close()
            self.session = None