"""
Token Revocation Service with Redis Backend.

Provides a distributed token revocation list (blacklist) using Redis
for scalable and performant token invalidation across multiple instances.
"""

import asyncio
import json
from typing import Optional, Set, Dict, Any, List
from datetime import datetime, timezone, timedelta
import logging
from dataclasses import dataclass, field, asdict

from ..core.connections import RedisConnectionPool, ConnectionPoolConfig

logger = logging.getLogger(__name__)


@dataclass
class RevokedToken:
    """Represents a revoked token."""
    jti: str  # JWT ID
    user_id: str
    revoked_at: datetime
    expires_at: datetime
    reason: str = "manual_revocation"
    revoked_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "jti": self.jti,
            "user_id": self.user_id,
            "revoked_at": self.revoked_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "reason": self.reason,
            "revoked_by": self.revoked_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RevokedToken":
        """Create from dictionary."""
        return cls(
            jti=data["jti"],
            user_id=data["user_id"],
            revoked_at=datetime.fromisoformat(data["revoked_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            reason=data.get("reason", "manual_revocation"),
            revoked_by=data.get("revoked_by")
        )


@dataclass
class RevokedSession:
    """Represents a revoked session."""
    session_id: str
    user_id: str
    revoked_at: datetime
    reason: str = "logout"
    revoked_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "revoked_at": self.revoked_at.isoformat(),
            "reason": self.reason,
            "revoked_by": self.revoked_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RevokedSession":
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            revoked_at=datetime.fromisoformat(data["revoked_at"]),
            reason=data.get("reason", "logout"),
            revoked_by=data.get("revoked_by")
        )


class TokenRevocationService:
    """
    Redis-backed token revocation service.
    
    Features:
    - Distributed revocation list across multiple instances
    - Automatic expiration of revoked tokens
    - Session-based revocation
    - Bulk revocation support
    - Performance optimization with local caching
    """
    
    def __init__(self, redis_url: str, config: Optional[ConnectionPoolConfig] = None):
        """
        Initialize token revocation service.
        
        Args:
            redis_url: Redis connection URL
            config: Connection pool configuration
        """
        self.redis_url = redis_url
        self.config = config or ConnectionPoolConfig()
        self.redis_pool = RedisConnectionPool(self.config)
        
        # Key prefixes for Redis
        self.TOKEN_PREFIX = "revoked:token:"
        self.SESSION_PREFIX = "revoked:session:"
        self.USER_TOKENS_PREFIX = "user:tokens:"
        self.USER_SESSIONS_PREFIX = "user:sessions:"
        
        # Local cache for performance (with TTL)
        self._local_token_cache: Dict[str, datetime] = {}
        self._local_session_cache: Dict[str, datetime] = {}
        self._cache_ttl = timedelta(minutes=5)
        self._last_cache_cleanup = datetime.now(timezone.utc)
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the service and start background tasks."""
        # Test Redis connection
        redis = await self.redis_pool.get_redis(self.redis_url)
        await redis.ping()
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_tokens())
        self._sync_task = asyncio.create_task(self._sync_local_cache())
        
        logger.info("Token revocation service initialized")
    
    async def revoke_token(
        self,
        jti: str,
        user_id: str,
        expires_at: datetime,
        reason: str = "manual_revocation",
        revoked_by: Optional[str] = None
    ) -> None:
        """
        Revoke a specific token.
        
        Args:
            jti: JWT ID
            user_id: User ID who owns the token
            expires_at: Token expiration time
            reason: Revocation reason
            revoked_by: ID of user who revoked the token
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Create revoked token record
        revoked_token = RevokedToken(
            jti=jti,
            user_id=user_id,
            revoked_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            reason=reason,
            revoked_by=revoked_by
        )
        
        # Store in Redis with expiration
        ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl > 0:
            # Store token revocation
            await redis.setex(
                f"{self.TOKEN_PREFIX}{jti}",
                ttl,
                json.dumps(revoked_token.to_dict())
            )
            
            # Add to user's revoked tokens set
            await redis.sadd(f"{self.USER_TOKENS_PREFIX}{user_id}", jti)
            await redis.expire(f"{self.USER_TOKENS_PREFIX}{user_id}", ttl)
            
            # Update local cache
            self._local_token_cache[jti] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
            
            logger.info(f"Token {jti} revoked for user {user_id}, reason: {reason}")
    
    async def revoke_session(
        self,
        session_id: str,
        user_id: str,
        reason: str = "logout",
        revoked_by: Optional[str] = None
    ) -> None:
        """
        Revoke all tokens for a session.
        
        Args:
            session_id: Session ID to revoke
            user_id: User ID who owns the session
            reason: Revocation reason
            revoked_by: ID of user who revoked the session
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Create revoked session record
        revoked_session = RevokedSession(
            session_id=session_id,
            user_id=user_id,
            revoked_at=datetime.now(timezone.utc),
            reason=reason,
            revoked_by=revoked_by
        )
        
        # Store in Redis (sessions are kept for 30 days for audit)
        ttl = 30 * 24 * 60 * 60  # 30 days
        await redis.setex(
            f"{self.SESSION_PREFIX}{session_id}",
            ttl,
            json.dumps(revoked_session.to_dict())
        )
        
        # Add to user's revoked sessions set
        await redis.sadd(f"{self.USER_SESSIONS_PREFIX}{user_id}", session_id)
        await redis.expire(f"{self.USER_SESSIONS_PREFIX}{user_id}", ttl)
        
        # Update local cache
        self._local_session_cache[session_id] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        
        logger.info(f"Session {session_id} revoked for user {user_id}, reason: {reason}")
    
    async def is_token_revoked(self, jti: str) -> bool:
        """
        Check if a token is revoked.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if token is revoked, False otherwise
        """
        # Check local cache first
        if jti in self._local_token_cache:
            if self._local_token_cache[jti] > datetime.now(timezone.utc):
                return True
            else:
                # Expired, remove from cache
                del self._local_token_cache[jti]
        
        # Check Redis
        redis = await self.redis_pool.get_redis(self.redis_url)
        exists = await redis.exists(f"{self.TOKEN_PREFIX}{jti}")
        
        # Update local cache if found
        if exists:
            ttl = await redis.ttl(f"{self.TOKEN_PREFIX}{jti}")
            if ttl > 0:
                self._local_token_cache[jti] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        
        return bool(exists)
    
    async def is_session_revoked(self, session_id: str) -> bool:
        """
        Check if a session is revoked.
        
        Args:
            session_id: Session ID to check
            
        Returns:
            True if session is revoked, False otherwise
        """
        # Check local cache first
        if session_id in self._local_session_cache:
            if self._local_session_cache[session_id] > datetime.now(timezone.utc):
                return True
            else:
                # Expired, remove from cache
                del self._local_session_cache[session_id]
        
        # Check Redis
        redis = await self.redis_pool.get_redis(self.redis_url)
        exists = await redis.exists(f"{self.SESSION_PREFIX}{session_id}")
        
        # Update local cache if found
        if exists:
            ttl = await redis.ttl(f"{self.SESSION_PREFIX}{session_id}")
            if ttl > 0:
                self._local_session_cache[session_id] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        
        return bool(exists)
    
    async def revoke_all_user_tokens(
        self,
        user_id: str,
        reason: str = "security",
        revoked_by: Optional[str] = None
    ) -> int:
        """
        Revoke all tokens for a user.
        
        Args:
            user_id: User ID whose tokens to revoke
            reason: Revocation reason
            revoked_by: ID of user who initiated revocation
            
        Returns:
            Number of tokens revoked
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get all user's tokens
        token_jtis = await redis.smembers(f"{self.USER_TOKENS_PREFIX}{user_id}")
        
        count = 0
        for jti_bytes in token_jtis:
            jti = jti_bytes.decode('utf-8')
            # Check if token still exists
            token_data = await redis.get(f"{self.TOKEN_PREFIX}{jti}")
            if token_data:
                token = RevokedToken.from_dict(json.loads(token_data))
                # Re-revoke with new reason if needed
                if token.reason != reason:
                    await self.revoke_token(
                        jti=jti,
                        user_id=user_id,
                        expires_at=token.expires_at,
                        reason=reason,
                        revoked_by=revoked_by
                    )
                count += 1
        
        # Also revoke all sessions
        session_ids = await redis.smembers(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        for session_id_bytes in session_ids:
            session_id = session_id_bytes.decode('utf-8')
            await self.revoke_session(
                session_id=session_id,
                user_id=user_id,
                reason=reason,
                revoked_by=revoked_by
            )
        
        logger.info(f"Revoked {count} tokens and {len(session_ids)} sessions for user {user_id}")
        return count
    
    async def get_revoked_tokens_count(self) -> Dict[str, int]:
        """Get statistics about revoked tokens."""
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Count tokens and sessions
        token_keys = await redis.keys(f"{self.TOKEN_PREFIX}*")
        session_keys = await redis.keys(f"{self.SESSION_PREFIX}*")
        
        return {
            "revoked_tokens": len(token_keys),
            "revoked_sessions": len(session_keys),
            "cached_tokens": len(self._local_token_cache),
            "cached_sessions": len(self._local_session_cache)
        }
    
    async def get_user_revocation_history(
        self,
        user_id: str,
        limit: int = 100
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get revocation history for a user.
        
        Args:
            user_id: User ID
            limit: Maximum number of records to return
            
        Returns:
            Dictionary with tokens and sessions lists
        """
        redis = await self.redis_pool.get_redis(self.redis_url)
        
        # Get user's revoked tokens
        token_jtis = await redis.smembers(f"{self.USER_TOKENS_PREFIX}{user_id}")
        tokens = []
        
        for jti_bytes in list(token_jtis)[:limit]:
            jti = jti_bytes.decode('utf-8')
            token_data = await redis.get(f"{self.TOKEN_PREFIX}{jti}")
            if token_data:
                tokens.append(json.loads(token_data))
        
        # Get user's revoked sessions
        session_ids = await redis.smembers(f"{self.USER_SESSIONS_PREFIX}{user_id}")
        sessions = []
        
        for session_id_bytes in list(session_ids)[:limit]:
            session_id = session_id_bytes.decode('utf-8')
            session_data = await redis.get(f"{self.SESSION_PREFIX}{session_id}")
            if session_data:
                sessions.append(json.loads(session_data))
        
        # Sort by revocation time
        tokens.sort(key=lambda x: x["revoked_at"], reverse=True)
        sessions.sort(key=lambda x: x["revoked_at"], reverse=True)
        
        return {
            "tokens": tokens[:limit],
            "sessions": sessions[:limit]
        }
    
    async def _cleanup_expired_tokens(self):
        """Background task to cleanup expired entries from local cache."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                now = datetime.now(timezone.utc)
                
                # Cleanup expired tokens from local cache
                expired_tokens = [
                    jti for jti, exp_time in self._local_token_cache.items()
                    if exp_time <= now
                ]
                for jti in expired_tokens:
                    del self._local_token_cache[jti]
                
                # Cleanup expired sessions from local cache
                expired_sessions = [
                    sid for sid, exp_time in self._local_session_cache.items()
                    if exp_time <= now
                ]
                for sid in expired_sessions:
                    del self._local_session_cache[sid]
                
                if expired_tokens or expired_sessions:
                    logger.debug(
                        f"Cleaned up {len(expired_tokens)} expired tokens "
                        f"and {len(expired_sessions)} expired sessions from local cache"
                    )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    async def _sync_local_cache(self):
        """Background task to periodically sync with Redis."""
        while True:
            try:
                await asyncio.sleep(60)  # Sync every minute
                
                # For high-traffic scenarios, we might want to sync
                # the most frequently checked tokens/sessions
                # This is a placeholder for more sophisticated sync logic
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync task: {e}")
    
    async def close(self):
        """Close the service and cleanup resources."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        
        # Close Redis pool
        await self.redis_pool.close()
        
        logger.info("Token revocation service closed")