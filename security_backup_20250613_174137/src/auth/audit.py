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
from collections import defaultdict, deque
import threading
import queue

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    AuthenticationError,\n    AuthorizationError,\n    ValidationError,\n    RateLimitError,\n    log_error
)

__all__ = [
    "AuditEventType",
    "AuditSeverity",
    "AuditEvent",
    "AuditLogger",
    "audit_action"
]


# Import bounded collections
try:
    from ..core.lru_cache import create_lru_cache, LRUCache
    from ..core.cleanup_scheduler import get_cleanup_scheduler
    HAS_BOUNDED_COLLECTIONS = True
except ImportError:
    HAS_BOUNDED_COLLECTIONS = False

# Import sanitization for log injection prevention
try:
    from ..core.log_sanitization import (
        sanitize_for_logging,
        sanitize_dict_for_logging,
        SanitizationLevel
    )
    HAS_SANITIZATION = True
except ImportError:
    # Fallback if core module not available
    HAS_SANITIZATION = False
    
    def sanitize_for_logging(value, level=None, context=None):
        return str(value) if value is not None else None
    
    def sanitize_dict_for_logging(data, level=None, context=None):
        return data if data else {}


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
        """Convert to dictionary for storage with sanitization."""
        # Use STRICT sanitization for audit logs due to their security-critical nature
        level = SanitizationLevel.STRICT if HAS_SANITIZATION else None
        
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "user_id": sanitize_for_logging(self.user_id, level, "audit.user_id"),
            "actor_id": sanitize_for_logging(self.actor_id, level, "audit.actor_id"),
            "resource": sanitize_for_logging(self.resource, level, "audit.resource"),
            "action": sanitize_for_logging(self.action, level, "audit.action"),
            "result": sanitize_for_logging(self.result, level, "audit.result"),
            "ip_address": sanitize_for_logging(self.ip_address, level, "audit.ip_address"),
            "user_agent": sanitize_for_logging(self.user_agent, level, "audit.user_agent"),
            "session_id": sanitize_for_logging(self.session_id, level, "audit.session_id"),
            "correlation_id": sanitize_for_logging(self.correlation_id, level, "audit.correlation_id"),
            "details": sanitize_dict_for_logging(self.details, level, "audit.details"),
            "tags": [sanitize_for_logging(tag, level, f"audit.tags[{i}]") for i, tag in enumerate(self.tags)]
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
                 signing_key: Optional[str] = None,
                 max_buffer_size: int = 100,
                 max_stats_entries: int = 1000,
                 stats_cleanup_interval: int = 3600):
        """
        Initialize audit logger.
        
        Args:
            storage_backend: Backend for storing audit logs
            signing_key: Key for signing audit entries (for tamper detection).
                        Required for production use to ensure audit log integrity.
            max_buffer_size: Maximum buffer size before forced flush
            max_stats_entries: Maximum number of statistics entries (sliding window)
            stats_cleanup_interval: Interval for statistics cleanup in seconds
        
        Raises:
            ValueError: If signing_key is not provided or is insecure
        """
        self.storage_backend = storage_backend
        
        # Validate signing key
        if not signing_key:
            raise ValueError("signing_key is required for audit log integrity")
        
        if len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 characters for security")
        
        self.signing_key = signing_key
        
        # In-memory buffer with bounded size and ring buffer for high-frequency events
        self.buffer: List[AuditEvent] = []
        self.buffer_size = max_buffer_size
        self.flush_interval = 5  # seconds
        
        # Ring buffer for high-frequency events (fixed size)
        self._high_freq_buffer = deque(maxlen=500)
        
        # Async queue with circuit breaker for overflow protection
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._queue_overflow_count = 0
        self._circuit_breaker_threshold = 100
        self._circuit_breaker_open = False
        self._circuit_breaker_reset_time = None
        
        # Statistics with bounded LRU cache if available
        if HAS_BOUNDED_COLLECTIONS:
            self.stats = create_lru_cache(
                max_size=max_stats_entries,
                ttl=stats_cleanup_interval,
                cleanup_interval=stats_cleanup_interval // 6  # Cleanup 6 times per TTL
            )
            self._stats_timestamps = deque(maxlen=max_stats_entries)
        else:
            # Fallback to bounded defaultdict with manual cleanup
            self.stats = defaultdict(int)
            self._stats_timestamps = deque(maxlen=max_stats_entries)
        
        self.max_stats_entries = max_stats_entries
        self.stats_cleanup_interval = stats_cleanup_interval
        self.last_flush = datetime.now(timezone.utc)
        self._last_stats_cleanup = datetime.now(timezone.utc)
        
        # Alert callbacks with weak references to prevent memory leaks
        self.alert_callbacks: List[weakref.ref] = []
        
        # Lifecycle management
        self._worker_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        # Start background worker
        self._start_worker()
    
    @handle_errors()
    def _start_worker(self) -> None:
        """Start background worker for processing events."""
        async def worker():
            self._is_running = True
            while self._is_running:
                try:
                    # Check circuit breaker
                    if self._circuit_breaker_open:
                        await self._check_circuit_breaker()
                        if self._circuit_breaker_open:
                            await asyncio.sleep(1)
                            continue
                    
                    # Process events from queue
                    try:
                        event = await asyncio.wait_for(
                            self.event_queue.get(),
                            timeout=self.flush_interval
                        )
                        
                        # Check if high-frequency event
                        if self._is_high_frequency_event(event):
                            self._high_freq_buffer.append(event)
                        else:
                            self.buffer.append(event)
                        
                        # Enforce buffer size limits
                        if len(self.buffer) >= self.buffer_size:
                            await self._flush_buffer()
                            
                    except asyncio.TimeoutError:
                        # Flush on timeout
                        await self._flush_buffers()
                        
                    # Periodic cleanup
                    await self._periodic_cleanup()
                        
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print(f"Audit worker error: {e}")
                    await asyncio.sleep(1)
        
        async def cleanup_worker():
            """Periodic cleanup task."""
            while self._is_running:
                try:
                    await asyncio.sleep(self.stats_cleanup_interval)
                    await self._cleanup_statistics()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print(f"Audit cleanup error: {e}")
        
        # Create tasks in background
        self._worker_task = asyncio.create_task(worker())
        self._cleanup_task = asyncio.create_task(cleanup_worker())
    
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
        """Log an audit event with input sanitization."""
        import uuid
        
        # Sanitize all inputs before creating audit event - use STRICT level for security
        level = SanitizationLevel.STRICT if HAS_SANITIZATION else None
        
        safe_user_id = sanitize_for_logging(user_id, level, "audit.input.user_id")
        safe_actor_id = sanitize_for_logging(actor_id or user_id, level, "audit.input.actor_id")
        safe_resource = sanitize_for_logging(resource, level, "audit.input.resource")
        safe_action = sanitize_for_logging(action, level, "audit.input.action")
        safe_result = sanitize_for_logging(result, level, "audit.input.result")
        safe_ip_address = sanitize_for_logging(ip_address, level, "audit.input.ip_address")
        safe_user_agent = sanitize_for_logging(user_agent, level, "audit.input.user_agent")
        safe_session_id = sanitize_for_logging(session_id, level, "audit.input.session_id")
        safe_correlation_id = sanitize_for_logging(correlation_id, level, "audit.input.correlation_id")
        safe_details = sanitize_dict_for_logging(details or {}, level, "audit.input.details")
        safe_tags = [sanitize_for_logging(tag, level, f"audit.input.tags[{i}]") for i, tag in enumerate(tags or [])]
        
        # Create event with sanitized data
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            user_id=safe_user_id,
            actor_id=safe_actor_id,
            resource=safe_resource,
            action=safe_action,
            result=safe_result,
            ip_address=safe_ip_address,
            user_agent=safe_user_agent,
            session_id=safe_session_id,
            correlation_id=safe_correlation_id,
            details=safe_details,
            tags=safe_tags
        )
        
        # Add signature for tamper detection
        event.details["signature"] = self._sign_event(event)
        
        # Update statistics with sliding window management
        current_time = datetime.now(timezone.utc)
        self._stats_timestamps.append(current_time)
        
        # Update statistics (handle both LRU cache and defaultdict)
        if HAS_BOUNDED_COLLECTIONS and hasattr(self.stats, 'get'):
            # LRU cache usage
            event_count = self.stats.get(event_type.value, 0)
            self.stats.put(event_type.value, event_count + 1)
            severity_count = self.stats.get(f"severity.{severity.value}", 0)
            self.stats.put(f"severity.{severity.value}", severity_count + 1)
        else:
            # Regular defaultdict usage
            self.stats[event_type.value] += 1
            self.stats[f"severity.{severity.value}"] += 1
        
        # Trigger immediate cleanup if stats are getting too large
        if len(self.stats) > self.max_stats_entries * 1.2:
            asyncio.create_task(self._cleanup_statistics())
        
        # Check for alerts
        await self._check_alerts(event)
        
        # Queue for processing with circuit breaker
        try:
            await self.event_queue.put(event)
            # Reset circuit breaker on successful queue operation
            if self._circuit_breaker_open:
                self._queue_overflow_count = 0
                self._circuit_breaker_open = False
        except asyncio.QueueFull:
            self._queue_overflow_count += 1
            
            # Open circuit breaker if too many overflows
            if self._queue_overflow_count >= self._circuit_breaker_threshold:
                self._circuit_breaker_open = True
                self._circuit_breaker_reset_time = datetime.now(timezone.utc) + timedelta(minutes=5)
                print(f"Audit queue circuit breaker opened due to overflow")
            
            # If queue is full, flush immediately and try again
            await self._flush_buffers()
            try:
                await self.event_queue.put(event)
            except asyncio.QueueFull:
                # Last resort: add to high-frequency buffer
                self._high_freq_buffer.append(event)
        
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
            # Re-queue events with size limit to prevent memory growth
            requeue_count = 0
            for event in events_to_flush:
                if requeue_count < 50:  # Limit requeue to prevent infinite growth
                    try:
                        await self.event_queue.put(event)
                        requeue_count += 1
                    except asyncio.QueueFull:
                        # Add to high-frequency buffer as last resort
                        self._high_freq_buffer.append(event)
                        break
                else:
                    break
    
    async def _flush_buffers(self) -> None:
        """Flush all buffers (main and high-frequency)."""
        await self._flush_buffer()
        
        # Flush high-frequency buffer if it has events
        if self._high_freq_buffer:
            high_freq_events = list(self._high_freq_buffer)
            self._high_freq_buffer.clear()
            
            try:
                if self.storage_backend:
                    await self.storage_backend.store_events(high_freq_events)
                else:
                    # Sample high-frequency events (keep only every 10th to reduce spam)
                    sampled_events = high_freq_events[::10]
                    for event in sampled_events:
                        print(f"AUDIT-HF: {event.to_json()}")
            except Exception as e:
                print(f"Failed to flush high-frequency buffer: {e}")
    
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
        """Trigger alert callbacks with weak reference handling."""
        active_callbacks = []
        
        for callback_ref in self.alert_callbacks:
            try:
                if isinstance(callback_ref, weakref.ref):
                    callback = callback_ref()
                    if callback is None:
                        continue  # Dead reference, skip
                else:
                    callback = callback_ref
                
                active_callbacks.append(callback)
                
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, message)
                else:
                    callback(event, message)
            except Exception as e:
                print(f"Alert callback error: {e}")
        
        # Update callbacks list to remove dead references
        self.alert_callbacks = [
            cb for cb in self.alert_callbacks 
            if not isinstance(cb, weakref.ref) or cb() is not None
        ]
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add callback for security alerts using weak references."""
        # Store weak reference to prevent memory leaks
        weak_callback = weakref.ref(callback) if hasattr(callback, '__self__') else callback
        self.alert_callbacks.append(weak_callback)
        
        # Clean up dead weak references
        self.alert_callbacks = [cb for cb in self.alert_callbacks 
                               if not isinstance(cb, weakref.ref) or cb() is not None]
    
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
    
    @handle_errors()
    def _cleanup_expired_stats(self) -> int:
        """
        Clean up expired statistics entries.
        
        Returns:
            Number of expired entries removed
        """
        if not HAS_BOUNDED_COLLECTIONS:
            return 0
        
        try:
            if hasattr(self.stats, 'cleanup'):
                removed_count = self.stats.cleanup()
                if removed_count > 0:
                    logger.debug(f"Cleaned up {removed_count} expired audit statistics")
                return removed_count
        except Exception as e:
            logger.error(f"Error during audit statistics cleanup: {e}")
        
        return 0
    
    @handle_errors()
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        stats_info = {}
        
        if HAS_BOUNDED_COLLECTIONS and hasattr(self.stats, 'get_stats'):
            try:
                cache_stats = self.stats.get_stats()
                stats_info["stats_cache"] = cache_stats.to_dict()
                stats_info["cache_type"] = "LRU Cache"
            except Exception as e:
                logger.error(f"Error getting cache stats: {e}")
        
        stats_info.update({
            "buffer_size": len(self.buffer),
            "queue_size": self.event_queue.qsize() if hasattr(self.event_queue, 'qsize') else 0,
            "alert_callbacks": len(self.alert_callbacks),
            "last_flush": self.last_flush.isoformat() if self.last_flush else None,
            "has_bounded_collections": HAS_BOUNDED_COLLECTIONS
        })
        
        return stats_info
    
    def _is_high_frequency_event(self, event: AuditEvent) -> bool:
        """Check if event is high-frequency and should use ring buffer."""
        high_freq_types = {
            AuditEventType.API_KEY_USED,
            AuditEventType.PERMISSION_CHECK_SUCCESS,
            AuditEventType.PERMISSION_CHECK_FAILED,
            AuditEventType.MCP_TOOL_CALLED,
            AuditEventType.MCP_TOOL_SUCCESS
        }
        return event.event_type in high_freq_types
    
    async def _check_circuit_breaker(self) -> None:
        """Check if circuit breaker should be reset."""
        if (self._circuit_breaker_reset_time and 
            datetime.now(timezone.utc) >= self._circuit_breaker_reset_time):
            self._circuit_breaker_open = False
            self._queue_overflow_count = 0
            self._circuit_breaker_reset_time = None
            print("Audit queue circuit breaker reset")
    
    async def _periodic_cleanup(self) -> None:
        """Perform periodic cleanup operations."""
        current_time = datetime.now(timezone.utc)
        
        # Clean up statistics every hour
        if (current_time - self._last_stats_cleanup).total_seconds() >= self.stats_cleanup_interval:
            await self._cleanup_statistics()
    
    async def _cleanup_statistics(self) -> None:
        """Clean up old statistics using sliding window."""
        current_time = datetime.now(timezone.utc)
        cutoff_time = current_time - timedelta(hours=24)  # Keep 24 hours of stats
        
        # Clean up timestamps older than cutoff
        while self._stats_timestamps and self._stats_timestamps[0] < cutoff_time:
            self._stats_timestamps.popleft()
        
        # If we have too many stats entries, keep only the most recent ones
        if len(self.stats) > self.max_stats_entries:
            # Sort by keys and keep the most recent entries
            sorted_keys = sorted(self.stats.keys())
            excess_count = len(self.stats) - self.max_stats_entries
            
            # Remove oldest statistical entries (simple heuristic)
            for i in range(excess_count):
                if i < len(sorted_keys):
                    key_to_remove = sorted_keys[i]
                    if not key_to_remove.startswith("severity."):  # Keep severity stats
                        del self.stats[key_to_remove]
        
        self._last_stats_cleanup = current_time
        print(f"Statistics cleanup completed. Entries: {len(self.stats)}")
    
    async def shutdown(self) -> None:
        """Gracefully shutdown the audit logger."""
        print("Shutting down audit logger...")
        self._is_running = False
        
        # Cancel background tasks
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self._flush_buffers()
        
        # Clear all buffers and reset state
        self.buffer.clear()
        self._high_freq_buffer.clear()
        self.stats.clear()
        self._stats_timestamps.clear()
        self.alert_callbacks.clear()
        
        print("Audit logger shutdown complete")


# Convenience decorators for audit logging
def audit_action(event_type: AuditEventType, severity: AuditSeverity = AuditSeverity.INFO):
    """Decorator for auditing function calls."""
    @handle_errors()
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            # Extract user context if available
            user_id = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'username'):
                    user_id = arg.id
                    break
            
            # Get audit logger (would be injected in real app)
            from .audit_config import get_audit_logger
            try:
                logger = get_audit_logger()
            except ValueError:
                # Skip audit logging if not configured
                return await func(*args, **kwargs)
            
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
        
        @handle_errors()
        def sync_wrapper(*args, **kwargs):
            # Similar for sync functions
            user_id = None
            for arg in args:
                if hasattr(arg, 'id') and hasattr(arg, 'username'):
                    user_id = arg.id
                    break
            
            from .audit_config import get_audit_logger
            try:
                logger = get_audit_logger()
            except ValueError:
                # Skip audit logging if not configured
                return func(*args, **kwargs)
            
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