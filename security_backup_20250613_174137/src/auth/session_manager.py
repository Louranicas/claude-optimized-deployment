"""
Session Management Service with Redis Backend.

Provides distributed session management with support for:
- Concurrent session limits
- Session activity tracking
- Device/IP tracking
- Session invalidation
- Activity-based timeouts
"""

import asyncio
import json
import secrets
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from ipaddress import ip_address, ip_network
import logging
import hashlib
from user_agents import parse

from ..core.connections import RedisConnectionPool, ConnectionPoolConfig

logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """Represents a user session."""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    device_info: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Parse user agent and extract device info."""
        if self.user_agent and not self.device_info:
            ua = parse(self.user_agent)
            self.device_info = {
                "browser": f"{ua.browser.family} {ua.browser.version_string}",
                "os": f"{ua.os.family} {ua.os.version_string}",
                "device": ua.device.family,
                "is_mobile": ua.is_mobile,
                "is_tablet": ua.is_tablet,
                "is_pc": ua.is_pc,
                "is_bot": ua.is_bot
            }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_info": self.device_info,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionInfo":
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            ip_address=data["ip_address"],
            user_agent=data["user_agent"],
            device_info=data.get("device_info", {}),
            metadata=data.get("metadata", {})
        )
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def needs_refresh(self, activity_timeout_minutes: int = 30) -> bool:
        """Check if session needs activity-based refresh."""
        inactive_time = datetime.now(timezone.utc) - self.last_activity
        return inactive_time > timedelta(minutes=activity_timeout_minutes)


@dataclass
class SessionSecurityEvent:
    """Represents a security event related to sessions."""
    event_type: str  # suspicious_location, concurrent_limit, ip_change, etc.
    session_id: str
    user_id: str
    timestamp: datetime
    details: Dict[str, Any]
    severity: str = "medium"  # low, medium, high, critical
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "event_type": self.event_type,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "severity": self.severity
        }


class SessionManager:
    """
    Redis-backed session management service.
    
    Features:
    - Distributed session storage
    - Concurrent session limits
    - Activity-based timeouts
    - IP and device tracking
    - Security event monitoring
    - Geographic anomaly detection
    """
    
    def __init__(
        self,
        redis_url: str,
        config: Optional[ConnectionPoolConfig] = None,
        max_concurrent_sessions: int = 5,
        session_timeout_minutes: int = 30,
        absolute_timeout_hours: int = 24,
        activity_timeout_minutes: int = 30
    ):
        """
        Initialize session manager.
        
        Args:
            redis_url: Redis connection URL
            config: Connection pool configuration
            max_concurrent_sessions: Maximum concurrent sessions per user
            session_timeout_minutes: Initial session timeout
            absolute_timeout_hours: Maximum session lifetime
            activity_timeout_minutes: Inactivity timeout
        """
        self.redis_url = redis_url
        self.config = config or ConnectionPoolConfig()
        self.redis_pool = RedisConnectionPool(self.config)
        
        # Session limits
        self.max_concurrent_sessions = max_concurrent_sessions
        self.session_timeout_minutes = session_timeout_minutes
        self.absolute_timeout_hours = absolute_timeout_hours
        self.activity_timeout_minutes = activity_timeout_minutes
        
        # Key prefixes
        self.SESSION_PREFIX = "session:"
        self.USER_SESSIONS_PREFIX = "user:sessions:"
        self.SESSION_EVENTS_PREFIX = "session:events:"
        self.USER_LOCATIONS_PREFIX = "user:locations:"
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._monitor_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the service and start background tasks."""
        # Test Redis connection
        redis = await self.redis_pool.get_redis(self.redis_url)
        await redis.ping()
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_sessions())
        self._monitor_task = asyncio.create_task(self._monitor_sessions())
        
        logger.info("Session manager initialized")
    
    async def create_session(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SessionInfo:
        """
        Create a new session.
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: User agent string
            metadata: Additional session metadata
            
        Returns:
            Created session info
            
        Raises:
            ValueError: If concurrent session limit exceeded
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Check concurrent session limit
        active_sessions = await self.get_user_sessions(user_id)
        if len(active_sessions) >= self.max_concurrent_sessions:
            # Remove oldest session
            oldest_session = min(active_sessions, key=lambda s: s.created_at)
            await self.invalidate_session(oldest_session.session_id, "concurrent_limit")
            
            # Log security event
            await self._log_security_event(
                SessionSecurityEvent(
                    event_type="concurrent_limit_exceeded",
                    session_id=oldest_session.session_id,
                    user_id=user_id,
                    timestamp=datetime.now(timezone.utc),
                    details={
                        "limit": self.max_concurrent_sessions,
                        "removed_session": oldest_session.session_id
                    },
                    severity="medium"
                )
            )
        
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create session
        now = datetime.now(timezone.utc)
        session = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(minutes=self.session_timeout_minutes),
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        
        # Store in Redis
        ttl = self.absolute_timeout_hours * 3600
        await redis.setex(
            f"{self.SESSION_PREFIX}{session_id}",
            ttl,
            json.dumps(session.to_dict())
        )
        
        # Add to user's session set
        await redis.sadd(f"{self.USER_SESSIONS_PREFIX}{user_id}", session_id)
        await redis.expire(f"{self.USER_SESSIONS_PREFIX}{user_id}", ttl)
        
        # Track user location
        await self._track_user_location(user_id, ip_address)
        
        # Check for suspicious activity
        await self._check_suspicious_activity(session)
        
        logger.info(f"Created session {session_id} for user {user_id}")
        return session
    
    async def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Get session by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session info if found and valid, None otherwise
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        session_data = await redis.get(f"{self.SESSION_PREFIX}{session_id}")
        if not session_data:
            return None
        
        session = SessionInfo.from_dict(json.loads(session_data))
        
        # Check if session is expired
        if session.is_expired():
            await self.invalidate_session(session_id, "expired")
            return None
        
        # Check activity timeout
        if session.needs_refresh(self.activity_timeout_minutes):
            await self.invalidate_session(session_id, "inactive")
            return None
        
        return session
    
    async def update_activity(
        self,
        session_id: str,
        ip_address: Optional[str] = None
    ) -> Optional[SessionInfo]:
        """
        Update session activity timestamp.
        
        Args:
            session_id: Session ID
            ip_address: Current IP address (for change detection)
            
        Returns:
            Updated session info if successful
        """
        session = await self.get_session(session_id)
        if not session:
            return None
        
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        
        # Extend expiration if needed
        time_since_creation = session.last_activity - session.created_at
        if time_since_creation < timedelta(hours=self.absolute_timeout_hours):
            session.expires_at = session.last_activity + timedelta(minutes=self.session_timeout_minutes)
        
        # Check for IP change
        if ip_address and ip_address != session.ip_address:
            await self._log_security_event(
                SessionSecurityEvent(
                    event_type="ip_change",
                    session_id=session_id,
                    user_id=session.user_id,
                    timestamp=datetime.now(timezone.utc),
                    details={
                        "old_ip": session.ip_address,
                        "new_ip": ip_address
                    },
                    severity="high"
                )
            )
            session.ip_address = ip_address
        
        # Update in Redis
        ttl = int((session.expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl > 0:
            await redis.setex(
                f"{self.SESSION_PREFIX}{session_id}",
                ttl,
                json.dumps(session.to_dict())
            )
        
        return session
    
    async def invalidate_session(
        self,
        session_id: str,
        reason: str = "manual"
    ) -> bool:
        """
        Invalidate a session.
        
        Args:
            session_id: Session ID to invalidate
            reason: Reason for invalidation
            
        Returns:
            True if session was invalidated, False if not found
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get session data first
        session_data = await redis.get(f"{self.SESSION_PREFIX}{session_id}")
        if not session_data:
            return False
        
        session = SessionInfo.from_dict(json.loads(session_data))
        
        # Remove from Redis
        await redis.delete(f"{self.SESSION_PREFIX}{session_id}")
        await redis.srem(f"{self.USER_SESSIONS_PREFIX}{session.user_id}", session_id)
        
        # Log invalidation
        await self._log_security_event(
            SessionSecurityEvent(
                event_type="session_invalidated",
                session_id=session_id,
                user_id=session.user_id,
                timestamp=datetime.now(timezone.utc),
                details={"reason": reason},
                severity="low"
            )
        )
        
        logger.info(f"Invalidated session {session_id} for user {session.user_id}, reason: {reason}")
        return True
    
    async def invalidate_all_user_sessions(
        self,
        user_id: str,
        reason: str = "security"
    ) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID
            reason: Reason for invalidation
            
        Returns:
            Number of sessions invalidated
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get all user sessions
        session_ids = await redis.smembers(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        
        count = 0
        for session_id_bytes in session_ids:
            session_id = session_id_bytes.decode('utf-8')
            if await self.invalidate_session(session_id, reason):
                count += 1
        
        # Clear user's session set
        await redis.delete(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        
        logger.info(f"Invalidated {count} sessions for user {user_id}, reason: {reason}")
        return count
    
    async def get_user_sessions(self, user_id: str) -> List[SessionInfo]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get session IDs
        session_ids = await redis.smembers(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        
        sessions = []
        for session_id_bytes in session_ids:
            session_id = session_id_bytes.decode('utf-8')
            session = await self.get_session(session_id)
            if session:
                sessions.append(session)
        
        # Sort by last activity
        sessions.sort(key=lambda s: s.last_activity, reverse=True)
        return sessions
    
    async def get_session_count(self, user_id: Optional[str] = None) -> int:
        """
        Get count of active sessions.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            Number of active sessions
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        if user_id:
            return await redis.scard(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        else:
            # Count all sessions
            keys = await redis.keys(f"{self.SESSION_PREFIX}*")
            return len(keys)
    
    async def get_security_events(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[SessionSecurityEvent]:
        """
        Get security events with filters.
        
        Args:
            user_id: Filter by user ID
            session_id: Filter by session ID
            event_type: Filter by event type
            severity: Filter by severity
            limit: Maximum number of events
            
        Returns:
            List of security events
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get all event keys (in production, use more efficient queries)
        pattern = f"{self.SESSION_EVENTS_PREFIX}*"
        keys = await redis.keys(pattern)
        
        events = []
        for key in keys[:limit * 2]:  # Get more to account for filtering
            event_data = await redis.get(key)
            if event_data:
                event_dict = json.loads(event_data)
                event = SessionSecurityEvent(
                    event_type=event_dict["event_type"],
                    session_id=event_dict["session_id"],
                    user_id=event_dict["user_id"],
                    timestamp=datetime.fromisoformat(event_dict["timestamp"]),
                    details=event_dict["details"],
                    severity=event_dict["severity"]
                )
                
                # Apply filters
                if user_id and event.user_id != user_id:
                    continue
                if session_id and event.session_id != session_id:
                    continue
                if event_type and event.event_type != event_type:
                    continue
                if severity and event.severity != severity:
                    continue
                
                events.append(event)
                
                if len(events) >= limit:
                    break
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events
    
    async def _track_user_location(self, user_id: str, ip_address: str):
        """Track user location for anomaly detection."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Store recent locations (keep last 10)
        key = f"{self.USER_LOCATIONS_PREFIX}{user_id}"
        await redis.lpush(key, ip_address)
        await redis.ltrim(key, 0, 9)
        await redis.expire(key, 30 * 24 * 3600)  # 30 days
    
    async def _check_suspicious_activity(self, session: SessionInfo):
        """Check for suspicious session activity."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Check for bot user agents
        if session.device_info.get("is_bot"):
            await self._log_security_event(
                SessionSecurityEvent(
                    event_type="bot_detected",
                    session_id=session.session_id,
                    user_id=session.user_id,
                    timestamp=datetime.now(timezone.utc),
                    details={"user_agent": session.user_agent},
                    severity="high"
                )
            )
        
        # Check for rapid location changes
        recent_ips = await redis.lrange(
            f"{self.USER_LOCATIONS_PREFIX}{session.user_id}",
            0, 4
        )
        
        if len(recent_ips) > 1:
            # Simple check - in production, use GeoIP database
            unique_ips = set(ip.decode('utf-8') for ip in recent_ips)
            if len(unique_ips) > 3:  # More than 3 different IPs recently
                await self._log_security_event(
                    SessionSecurityEvent(
                        event_type="rapid_location_change",
                        session_id=session.session_id,
                        user_id=session.user_id,
                        timestamp=datetime.now(timezone.utc),
                        details={"recent_ips": list(unique_ips)},
                        severity="medium"
                    )
                )
    
    async def _log_security_event(self, event: SessionSecurityEvent):
        """Log a security event."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Generate event key
        event_id = secrets.token_urlsafe(16)
        key = f"{self.SESSION_EVENTS_PREFIX}{event.user_id}:{event_id}"
        
        # Store event (keep for 30 days)
        await redis.setex(
            key,
            30 * 24 * 3600,
            json.dumps(event.to_dict())
        )
        
        # Log high severity events
        if event.severity in ["high", "critical"]:
            logger.warning(
                f"Security event: {event.event_type} for user {event.user_id}, "
                f"session {event.session_id}, severity: {event.severity}"
            )
    
    async def _cleanup_expired_sessions(self):
        """Background task to cleanup expired sessions."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                redis = await self.redis_pool.get_redis(self.redis_url)
                
                # Get all session keys
                keys = await redis.keys(f"{self.SESSION_PREFIX}*")
                
                cleaned = 0
                for key in keys:
                    session_data = await redis.get(key)
                    if session_data:
                        session = SessionInfo.from_dict(json.loads(session_data))
                        if session.is_expired() or session.needs_refresh(self.activity_timeout_minutes):
                            session_id = key.decode('utf-8').replace(self.SESSION_PREFIX, '')
                            await self.invalidate_session(session_id, "expired")
                            cleaned += 1
                
                if cleaned > 0:
                    logger.info(f"Cleaned up {cleaned} expired sessions")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    async def _monitor_sessions(self):
        """Background task to monitor session anomalies."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute
                
                # Monitor for anomalies
                # This is a placeholder for more sophisticated monitoring
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitor task: {e}")
    
    async def close(self):
        """Close the service and cleanup resources."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Close Redis pool
        await self.redis_pool.close()
        
        logger.info("Session manager closed")