"""Security Audit Logging System.

Implements comprehensive audit logging for all authentication and authorization
events following OWASP logging guidelines.
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import asyncio
import hashlib
import hmac
from collections import defaultdict
import threading
import queue


class AuditEventType(Enum):
    """Types of audit events."""
    # Authentication events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token.refresh"
    TOKEN_REVOKED = "auth.token.revoked"
    SESSION_EXPIRED = "auth.session.expired"
    
    # User management events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_LOCKED = "user.locked"
    USER_UNLOCKED = "user.unlocked"
    PASSWORD_CHANGED = "user.password.changed"
    PASSWORD_RESET_REQUESTED = "user.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "user.password.reset_completed"
    MFA_ENABLED = "user.mfa.enabled"
    MFA_DISABLED = "user.mfa.disabled"
    
    # Role and permission events
    ROLE_ASSIGNED = "rbac.role.assigned"
    ROLE_REMOVED = "rbac.role.removed"
    PERMISSION_GRANTED = "rbac.permission.granted"
    PERMISSION_REVOKED = "rbac.permission.revoked"
    PERMISSION_CHECK_SUCCESS = "rbac.permission.check.success"
    PERMISSION_CHECK_FAILED = "rbac.permission.check.failed"
    
    # API key events
    API_KEY_CREATED = "apikey.created"
    API_KEY_USED = "apikey.used"
    API_KEY_REVOKED = "apikey.revoked"
    API_KEY_EXPIRED = "apikey.expired"
    
    # MCP events
    MCP_TOOL_CALLED = "mcp.tool.called"
    MCP_TOOL_SUCCESS = "mcp.tool.success"
    MCP_TOOL_FAILED = "mcp.tool.failed"
    MCP_PERMISSION_DENIED = "mcp.permission.denied"
    
    # Expert events
    EXPERT_QUERY_STARTED = "expert.query.started"
    EXPERT_QUERY_SUCCESS = "expert.query.success"
    EXPERT_QUERY_FAILED = "expert.query.failed"
    EXPERT_PERMISSION_DENIED = "expert.permission.denied"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "security.suspicious"
    RATE_LIMIT_EXCEEDED = "security.rate_limit"
    IP_BLOCKED = "security.ip.blocked"
    BRUTE_FORCE_DETECTED = "security.brute_force"
    INJECTION_ATTEMPT = "security.injection"
    
    # System events
    CONFIG_CHANGED = "system.config.changed"
    AUDIT_EXPORTED = "system.audit.exported"
    AUDIT_PURGED = "system.audit.purged"


class AuditSeverity(Enum):
    """Audit event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    ALERT = "alert"
    EMERGENCY = "emergency"


@dataclass
class AuditEvent:
    """Represents an audit event."""
    
    id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str]
    actor_id: Optional[str]
    resource: Optional[str]
    action: Optional[str]
    result: str  # success, failure, error
    ip_address: Optional[str]
    user_agent: Optional[str]
    session_id: Optional[str]
    correlation_id: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "user_id": self.user_id,
            "actor_id": self.actor_id,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "details": self.details,
            "tags": self.tags
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Create from dictionary."""
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["event_type"] = AuditEventType(data["event_type"])
        data["severity"] = AuditSeverity(data["severity"])
        return cls(**data)


class AuditLogger:
    """Secure audit logging service."""
    
    def __init__(self, storage_backend: Optional[Any] = None,
                 signing_key: Optional[str] = None):
        """
        Initialize audit logger.
        
        Args:
            storage_backend: Backend for storing audit logs
            signing_key: Key for signing audit entries (for tamper detection)
        """
        self.storage_backend = storage_backend
        self.signing_key = signing_key or "default-signing-key"
        
        # In-memory buffer for performance
        self.buffer: List[AuditEvent] = []
        self.buffer_size = 100
        self.flush_interval = 5  # seconds
        
        # Async queue for background processing
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        
        # Statistics
        self.stats = defaultdict(int)
        self.last_flush = datetime.now(timezone.utc)
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        
        # Start background worker
        self._start_worker()
    
    def _start_worker(self) -> None:
        """Start background worker for processing events."""
        async def worker():
            while True:
                try:
                    # Process events from queue
                    event = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=self.flush_interval
                    )
                    self.buffer.append(event)
                    
                    # Flush if buffer is full
                    if len(self.buffer) >= self.buffer_size:
                        await self._flush_buffer()
                        
                except asyncio.TimeoutError:
                    # Flush on timeout
                    if self.buffer:
                        await self._flush_buffer()
                except Exception as e:
                    print(f"Audit worker error: {e}")
        
        # Create task in background
        asyncio.create_task(worker())
    
    async def log_event(self, event_type: AuditEventType,
                       severity: AuditSeverity = AuditSeverity.INFO,
                       user_id: Optional[str] = None,
                       actor_id: Optional[str] = None,
                       resource: Optional[str] = None,
                       action: Optional[str] = None,
                       result: str = "success",
                       ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None,
                       session_id: Optional[str] = None,
                       correlation_id: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None,
                       tags: Optional[List[str]] = None) -> str:
        """Log an audit event."""
        import uuid
        
        # Create event
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            actor_id=actor_id or user_id,
            resource=resource,
            action=action,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            correlation_id=correlation_id,
            details=details or {},
            tags=tags or []
        )
        
        # Add signature for tamper detection
        event.details["signature"] = self._sign_event(event)
        
        # Update statistics
        self.stats[event_type.value] += 1
        self.stats[f"severity.{severity.value}"] += 1
        
        # Check for alerts
        await self._check_alerts(event)
        
        # Queue for processing
        try:
            await self.event_queue.put(event)
        except asyncio.QueueFull:
            # If queue is full, flush immediately
            await self._flush_buffer()
            await self.event_queue.put(event)
        
        return event.id
    
    def _sign_event(self, event: AuditEvent) -> str:
        """Create HMAC signature for event."""
        # Create canonical representation
        canonical = json.dumps({
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "user_id": event.user_id,
            "resource": event.resource,
            "action": event.action,
            "result": event.result
        }, sort_keys=True)
        
        # Create HMAC
        signature = hmac.new(
            self.signing_key.encode(),
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_event(self, event: AuditEvent) -> bool:
        """Verify event signature."""
        stored_signature = event.details.get("signature")
        if not stored_signature:
            return False
        
        # Remove signature from details for verification
        original_signature = event.details.pop("signature", None)
        calculated_signature = self._sign_event(event)
        
        # Restore signature
        if original_signature:
            event.details["signature"] = original_signature
        
        return hmac.compare_digest(stored_signature, calculated_signature)
    
    async def _flush_buffer(self) -> None:
        """Flush buffered events to storage."""
        if not self.buffer:
            return
        
        events_to_flush = self.buffer.copy()
        self.buffer.clear()
        
        try:
            if self.storage_backend:
                await self.storage_backend.store_events(events_to_flush)
            else:
                # Default: print to console
                for event in events_to_flush:
                    print(f"AUDIT: {event.to_json()}")
            
            self.last_flush = datetime.now(timezone.utc)
            self.stats["flushes"] += 1
            
        except Exception as e:
            print(f"Failed to flush audit buffer: {e}")
            # Re-queue events
            for event in events_to_flush:
                await self.event_queue.put(event)
    
    async def _check_alerts(self, event: AuditEvent) -> None:
        """Check if event should trigger alerts."""
        # Alert on critical events
        if event.severity in [AuditSeverity.CRITICAL, AuditSeverity.ALERT, AuditSeverity.EMERGENCY]:
            await self._trigger_alert(event, "Critical security event")
        
        # Alert on specific event types
        alert_types = {
            AuditEventType.BRUTE_FORCE_DETECTED,
            AuditEventType.INJECTION_ATTEMPT,
            AuditEventType.SUSPICIOUS_ACTIVITY
        }
        
        if event.event_type in alert_types:
            await self._trigger_alert(event, f"Security alert: {event.event_type.value}")
        
        # Alert on repeated failures
        if event.result == "failure":
            failure_key = f"failures.{event.user_id}.{event.event_type.value}"
            self.stats[failure_key] += 1
            
            if self.stats[failure_key] >= 5:
                await self._trigger_alert(event, "Multiple failures detected")
                self.stats[failure_key] = 0
    
    async def _trigger_alert(self, event: AuditEvent, message: str) -> None:
        """Trigger alert callbacks."""
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, message)
                else:
                    callback(event, message)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add callback for security alerts."""
        self.alert_callbacks.append(callback)
    
    async def query_events(self, filters: Dict[str, Any],
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          limit: int = 100) -> List[AuditEvent]:
        """Query audit events."""
        if self.storage_backend:
            return await self.storage_backend.query_events(
                filters, start_time, end_time, limit
            )
        return []
    
    async def get_user_activity(self, user_id: str,
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None) -> List[AuditEvent]:
        """Get all activity for a specific user."""
        filters = {"user_id": user_id}
        return await self.query_events(filters, start_time, end_time)
    
    async def get_security_events(self, severity: AuditSeverity = AuditSeverity.WARNING,
                                start_time: Optional[datetime] = None) -> List[AuditEvent]:
        """Get security events above specified severity."""
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        events = await self.query_events({}, start_time)
        
        # Filter by severity
        severity_order = [s.value for s in AuditSeverity]
        min_severity_index = severity_order.index(severity.value)
        
        return [
            event for event in events
            if severity_order.index(event.severity.value) >= min_severity_index
        ]
    
    async def export_audit_log(self, start_time: datetime,
                             end_time: datetime,
                             format: str = "json") -> str:
        """Export audit logs for compliance."""
        events = await self.query_events({}, start_time, end_time, limit=10000)
        
        # Log the export action
        await self.log_event(
            event_type=AuditEventType.AUDIT_EXPORTED,
            details={
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "event_count": len(events),
                "format": format
            }
        )
        
        if format == "json":
            return json.dumps([e.to_dict() for e in events], indent=2)
        elif format == "csv":
            # Simple CSV export
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                "id", "timestamp", "event_type", "severity",
                "user_id", "resource", "action", "result", "ip_address"
            ])
            writer.writeheader()
            
            for event in events:
                writer.writerow({
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    "user_id": event.user_id,
                    "resource": event.resource,
                    "action": event.action,
                    "result": event.result,
                    "ip_address": event.ip_address
                })
            
            return output.getvalue()
        
        raise ValueError(f"Unsupported format: {format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit statistics."""
        return {
            "total_events": sum(v for k, v in self.stats.items() if "." not in k),
            "events_by_type": {k: v for k, v in self.stats.items() if "." not in k},
            "events_by_severity": {
                k.split(".")[-1]: v 
                for k, v in self.stats.items() 
                if k.startswith("severity.")
            },
            "buffer_size": len(self.buffer),
            "queue_size": self.event_queue.qsize(),
            "last_flush": self.last_flush.isoformat(),
            "flush_count": self.stats.get("flushes", 0)
        }
    
    async def cleanup_old_events(self, retention_days: int = 90) -> int:
        """Clean up old audit events."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        if self.storage_backend:
            deleted_count = await self.storage_backend.delete_events_before(cutoff_date)
            
            # Log the cleanup
            await self.log_event(
                event_type=AuditEventType.AUDIT_PURGED,
                details={
                    "retention_days": retention_days,
                    "cutoff_date": cutoff_date.isoformat(),
                    "deleted_count": deleted_count
                }
            )
            
            return deleted_count
        
        return 0


# Convenience decorators for audit logging
def audit_action(event_type: AuditEventType, severity: AuditSeverity = AuditSeverity.INFO):
    """Decorator for auditing function calls."""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            # Extract user context if available
            user_id = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'username'):
                    user_id = arg.id
                    break
            
            # Get audit logger (would be injected in real app)
            logger = AuditLogger()
            
            try:
                result = await func(*args, **kwargs)
                await logger.log_event(
                    event_type=event_type,
                    severity=severity,
                    user_id=user_id,
                    action=func.__name__,
                    result="success"
                )
                return result
                
            except Exception as e:
                await logger.log_event(
                    event_type=event_type,
                    severity=AuditSeverity.ERROR,
                    user_id=user_id,
                    action=func.__name__,
                    result="failure",
                    details={"error": str(e)}
                )
                raise
        
        def sync_wrapper(*args, **kwargs):
            # Similar for sync functions
            user_id = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'username'):
                    user_id = arg.id
                    break
            
            logger = AuditLogger()
            
            try:
                result = func(*args, **kwargs)
                # Use asyncio.create_task for async logging from sync context
                asyncio.create_task(logger.log_event(
                    event_type=event_type,
                    severity=severity,
                    user_id=user_id,
                    action=func.__name__,
                    result="success"
                ))
                return result
                
            except Exception as e:
                asyncio.create_task(logger.log_event(
                    event_type=event_type,
                    severity=AuditSeverity.ERROR,
                    user_id=user_id,
                    action=func.__name__,
                    result="failure",
                    details={"error": str(e)}
                ))
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator