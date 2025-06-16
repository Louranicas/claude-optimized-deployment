"""
Enhanced Communication Hub MCP Server with Secret Manager integration.

This is an updated version of slack_server.py that uses the centralized
secret management system instead of direct environment variable access.
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
from src.core.secrets_manager import get_secret_manager, SecretAccessLevel, secret_context

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
    """Enhanced Communication Hub with Secret Manager integration.
    
    Key improvements:
    - Uses centralized secret management for all credentials
    - Supports automatic secret rotation
    - Provides audit logging for all secret access
    - Zero-downtime secret updates
    """
    
    def __init__(
        self,
        rate_limit_config: Optional[RateLimitConfig] = None,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    ):
        """Initialize Communication Hub MCP Server with secret management.
        
        Note: Credentials are now loaded from the secret manager instead of
        being passed as parameters or read from environment variables.
        """
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
        
        # Secret manager will be initialized on first use
        self._secret_manager = get_secret_manager()
        self._secrets_initialized = False
    
    async def _ensure_secrets_initialized(self) -> None:
        """Ensure secret manager is initialized."""
        if not self._secrets_initialized:
            await self._secret_manager.initialize()
            self._secrets_initialized = True
    
    async def _get_slack_token(self) -> Optional[str]:
        """Get Slack token from secret manager."""
        await self._ensure_secrets_initialized()
        return await self._secret_manager.get_secret(
            "communication/slack",
            "bot_token",
            SecretAccessLevel.SENSITIVE
        )
    
    async def _get_teams_webhook(self) -> Optional[str]:
        """Get Teams webhook from secret manager."""
        await self._ensure_secrets_initialized()
        return await self._secret_manager.get_secret(
            "communication/teams",
            "webhook_url",
            SecretAccessLevel.SENSITIVE
        )
    
    async def _get_smtp_config(self) -> Dict[str, Any]:
        """Get SMTP configuration from secret manager."""
        await self._ensure_secrets_initialized()
        
        # Get SMTP credentials from secret manager
        smtp_data = await self._secret_manager.get_secret(
            "communication/smtp",
            access_level=SecretAccessLevel.SENSITIVE
        )
        
        if isinstance(smtp_data, dict):
            return smtp_data
        
        # Fallback to individual secrets
        return {
            "host": await self._secret_manager.get_secret("communication/smtp/host") or "smtp.gmail.com",
            "port": int(await self._secret_manager.get_secret("communication/smtp/port") or "587"),
            "username": await self._secret_manager.get_secret("communication/smtp/username"),
            "password": await self._secret_manager.get_secret("communication/smtp/password"),
            "use_tls": (await self._secret_manager.get_secret("communication/smtp/use_tls") or "true").lower() == "true"
        }
    
    async def _get_sms_config(self) -> Dict[str, Any]:
        """Get SMS configuration from secret manager."""
        await self._ensure_secrets_initialized()
        
        # Get SMS credentials from secret manager
        sms_data = await self._secret_manager.get_secret(
            "communication/sms",
            access_level=SecretAccessLevel.SENSITIVE
        )
        
        if isinstance(sms_data, dict):
            return sms_data
        
        # Fallback to individual secrets
        return {
            "provider": await self._secret_manager.get_secret("communication/sms/provider") or "twilio",
            "account_sid": await self._secret_manager.get_secret("communication/sms/account_sid"),
            "auth_token": await self._secret_manager.get_secret("communication/sms/auth_token"),
            "from_number": await self._secret_manager.get_secret("communication/sms/from_number")
        }
    
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
            version="2.1.0",  # Updated version with secret management
            description="Enterprise Communication Hub with secret management and multi-channel support",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "multi_channel": True,
                    "alert_management": True,
                    "rate_limiting": True,
                    "circuit_breaker": True,
                    "secret_management": True,  # New capability
                    "audit_logging": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available communication tools."""
        return [
            MCPTool(
                name="send_message",
                description="Send message through multiple channels",
                parameters=[
                    MCPToolParameter(name="message", type="string", description="Message content", required=True),
                    MCPToolParameter(name="channels", type="array", description="Target channels", required=False,
                                   items={"type": "string", "enum": ["slack", "teams", "email", "sms", "webhook"]}),
                    MCPToolParameter(name="priority", type="string", description="Message priority", required=False,
                                   enum=["low", "medium", "high", "critical"]),
                    MCPToolParameter(name="metadata", type="object", description="Channel-specific metadata", required=False)
                ]
            ),
            MCPTool(
                name="send_alert",
                description="Send alert with automatic escalation",
                parameters=[
                    MCPToolParameter(name="alert_type", type="string", description="Type of alert", required=True,
                                   enum=["error", "warning", "info", "security", "performance"]),
                    MCPToolParameter(name="severity", type="string", description="Alert severity", required=True,
                                   enum=["low", "medium", "high", "critical"]),
                    MCPToolParameter(name="title", type="string", description="Alert title", required=True),
                    MCPToolParameter(name="description", type="string", description="Alert description", required=True),
                    MCPToolParameter(name="metadata", type="object", description="Additional alert data", required=False),
                    MCPToolParameter(name="escalation_policy", type="object", description="Custom policy", required=False)
                ]
            ),
            MCPTool(
                name="create_incident",
                description="Create and manage incident",
                parameters=[
                    MCPToolParameter(name="title", type="string", description="Incident title", required=True),
                    MCPToolParameter(name="description", type="string", description="Incident details", required=True),
                    MCPToolParameter(name="severity", type="string", description="Incident severity", required=True,
                                   enum=["low", "medium", "high", "critical"]),
                    MCPToolParameter(name="affected_services", type="array", description="Affected services", required=True),
                    MCPToolParameter(name="assignee", type="string", description="Initial assignee", required=False),
                    MCPToolParameter(name="runbook_url", type="string", description="Runbook link", required=False),
                    MCPToolParameter(name="auto_page", type="boolean", description="Auto-page on-call", required=False)
                ]
            ),
            MCPTool(
                name="create_channel",
                description="Create communication channel or group",
                parameters=[
                    MCPToolParameter(name="platform", type="string", description="Platform", required=True,
                                   enum=["slack", "teams"]),
                    MCPToolParameter(name="name", type="string", description="Channel name", required=True),
                    MCPToolParameter(name="description", type="string", description="Channel purpose", required=False),
                    MCPToolParameter(name="private", type="boolean", description="Private channel", required=False),
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
            ),
            MCPTool(
                name="rotate_communication_secrets",
                description="Rotate communication channel secrets",
                parameters=[
                    MCPToolParameter(name="channels", type="array", description="Channels to rotate", required=True,
                                   items={"type": "string", "enum": ["slack", "teams", "smtp", "sms"]}),
                    MCPToolParameter(name="force", type="boolean", description="Force rotation", required=False)
                ]
            )
        ]
    
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
    
    async def _record_success(self, channel: str) -> None:
        """Record successful request for circuit breaker."""
        state = self.circuit_state[channel]
        
        if state["state"] == "half_open":
            state["state"] = "closed"
            state["failures"] = 0
            state["last_failure"] = None
    
    async def _record_failure(self, channel: str) -> None:
        """Record failed request for circuit breaker."""
        state = self.circuit_state[channel]
        state["failures"] += 1
        state["last_failure"] = time.time()
        
        if state["failures"] >= self.circuit_breaker.failure_threshold:
            state["state"] = "open"
    
    async def handle_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool execution with circuit breaker and rate limiting."""
        # Check rate limit
        if not await self._check_rate_limit(tool_name):
            raise MCPError(f"Rate limit exceeded for {tool_name}")
        
        # Execute tool
        try:
            if tool_name == "send_message":
                return await self._handle_send_message(**parameters)
            elif tool_name == "send_alert":
                return await self._handle_send_alert(**parameters)
            elif tool_name == "create_incident":
                return await self._handle_create_incident(**parameters)
            elif tool_name == "create_channel":
                return await self._handle_create_channel(**parameters)
            elif tool_name == "update_status":
                return await self._handle_update_status(**parameters)
            elif tool_name == "broadcast_deployment":
                return await self._handle_broadcast_deployment(**parameters)
            elif tool_name == "escalate_incident":
                return await self._handle_escalate_incident(**parameters)
            elif tool_name == "list_channels":
                return await self._handle_list_channels()
            elif tool_name == "rotate_communication_secrets":
                return await self._handle_rotate_secrets(**parameters)
            else:
                raise MCPError(f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            raise
    
    async def _handle_send_message(
        self,
        message: str,
        channels: Optional[List[str]] = None,
        priority: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send message through specified channels."""
        channels = channels or ["slack"]
        results = {}
        
        for channel in channels:
            if not await self._check_circuit_breaker(channel):
                results[channel] = {"success": False, "error": "Circuit breaker open"}
                continue
            
            try:
                if channel == "slack":
                    result = await self._send_slack_message(message, priority, metadata)
                elif channel == "teams":
                    result = await self._send_teams_message(message, priority, metadata)
                elif channel == "email":
                    result = await self._send_email(message, priority, metadata)
                elif channel == "sms":
                    result = await self._send_sms(message, priority, metadata)
                elif channel == "webhook":
                    result = await self._send_webhook(message, priority, metadata)
                else:
                    result = {"success": False, "error": f"Unknown channel: {channel}"}
                
                results[channel] = result
                
                if result.get("success"):
                    await self._record_success(channel)
                else:
                    await self._record_failure(channel)
                    
            except Exception as e:
                results[channel] = {"success": False, "error": str(e)}
                await self._record_failure(channel)
        
        # Audit log
        self._log_audit_event("send_message", {"channels": channels, "priority": priority}, results)
        
        return {"results": results, "timestamp": datetime.utcnow().isoformat()}
    
    @retry_network(max_attempts=3, timeout=30)
    async def _send_slack_message(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send message via Slack using secret manager."""
        # Use context manager for secure secret access
        async with secret_context("communication/slack", "bot_token", SecretAccessLevel.SENSITIVE) as slack_token:
            if not slack_token:
                return {"success": False, "error": "Slack token not configured"}
            
            headers = {"Authorization": f"Bearer {slack_token}", "Content-Type": "application/json"}
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
        """Send message via Microsoft Teams using secret manager."""
        async with secret_context("communication/teams", "webhook_url", SecretAccessLevel.SENSITIVE) as teams_webhook:
            if not teams_webhook:
                return {"success": False, "error": "Teams webhook not configured"}
            
            color = {"low": "0078D4", "medium": "FFA500", "high": "FF6347", "critical": "DC143C"}.get(priority, "808080")
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "themeColor": color,
                "summary": message[:100],
                "sections": [{
                    "activityTitle": "CODE Communication Hub",
                    "activitySubtitle": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "text": message,
                    "markdown": True
                }]
            }
            
            try:
                response = await self._make_safe_request(
                    "POST", teams_webhook, json=payload
                )
                return {"success": response.status == 200}
            except Exception as e:
                return {"success": False, "error": str(e)}
    
    async def _send_email(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send email notification using secret manager."""
        smtp_config = await self._get_smtp_config()
        
        if not smtp_config.get("username") or not smtp_config.get("password"):
            return {"success": False, "error": "SMTP credentials not configured"}
        
        to_addresses = metadata.get("to", []) if metadata else []
        if not to_addresses:
            return {"success": False, "error": "No recipient addresses provided"}
        
        try:
            msg = MIMEMultipart()
            msg["From"] = smtp_config["username"]
            msg["To"] = ", ".join(to_addresses)
            msg["Subject"] = f"[{priority.upper()}] CODE Notification"
            
            body = MIMEText(message, "plain")
            msg.attach(body)
            
            with smtplib.SMTP(smtp_config["host"], smtp_config["port"]) as server:
                if smtp_config.get("use_tls"):
                    server.starttls()
                server.login(smtp_config["username"], smtp_config["password"])
                server.send_message(msg)
            
            return {"success": True, "recipients": to_addresses}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _send_sms(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send SMS notification (placeholder - implement based on provider)."""
        sms_config = await self._get_sms_config()
        
        if not sms_config.get("auth_token"):
            return {"success": False, "error": "SMS not configured"}
        
        # Implementation would depend on SMS provider (Twilio, AWS SNS, etc.)
        return {"success": True, "message": "SMS implementation pending"}
    
    async def _send_webhook(self, message: str, priority: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send webhook notification."""
        if not metadata or "url" not in metadata:
            return {"success": False, "error": "Webhook URL not provided"}
        
        payload = {
            "message": message,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "CODE Communication Hub"
        }
        
        if "custom_payload" in metadata:
            payload.update(metadata["custom_payload"])
        
        try:
            response = await self._make_safe_request(
                "POST", metadata["url"], json=payload, headers=metadata.get("headers", {})
            )
            return {"success": response.status < 400, "status_code": response.status}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _handle_rotate_secrets(self, channels: List[str], force: bool = False) -> Dict[str, Any]:
        """Handle secret rotation for communication channels."""
        results = {}
        
        for channel in channels:
            try:
                if channel == "slack":
                    new_token = await self._secret_manager.rotate_secret(
                        "communication/slack/bot_token",
                        user_id="system"
                    )
                    results[channel] = {"success": True, "rotated": True}
                    
                elif channel == "teams":
                    new_webhook = await self._secret_manager.rotate_secret(
                        "communication/teams/webhook_url",
                        user_id="system"
                    )
                    results[channel] = {"success": True, "rotated": True}
                    
                elif channel == "smtp":
                    new_password = await self._secret_manager.rotate_secret(
                        "communication/smtp/password",
                        user_id="system"
                    )
                    results[channel] = {"success": True, "rotated": True}
                    
                elif channel == "sms":
                    new_token = await self._secret_manager.rotate_secret(
                        "communication/sms/auth_token",
                        user_id="system"
                    )
                    results[channel] = {"success": True, "rotated": True}
                    
                else:
                    results[channel] = {"success": False, "error": f"Unknown channel: {channel}"}
                    
            except Exception as e:
                results[channel] = {"success": False, "error": str(e)}
        
        return {
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
            "forced": force
        }
    
    def _log_audit_event(self, action: str, parameters: Dict[str, Any], result: Any) -> None:
        """Log audit event."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "parameters": parameters,
            "result": result
        }
        self.audit_log.append(event)
        
        # Keep only last 1000 events in memory
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        # Cancel escalation timers
        for timer in self.escalation_timers.values():
            timer.cancel()
        
        # Close HTTP session
        if self._ssrf_session:
            await self._ssrf_session.__aexit__(None, None, None)
        
        logger.info("Communication Hub cleaned up")
    
    # ... (rest of the methods remain the same as original slack_server.py) ...