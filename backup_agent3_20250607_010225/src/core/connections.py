"""
Comprehensive connection pooling module for all network operations.

This module provides thread-safe connection pooling for:
- HTTP/HTTPS connections (aiohttp)
- Database connections (PostgreSQL, MongoDB)
- Redis connections
- WebSocket connections

Features:
- Automatic retry and reconnection
- Connection health checks
- Resource limits and timeouts
- Performance monitoring
- Graceful shutdown
"""

from __future__ import annotations
import asyncio
import time
from typing import Dict, Optional, Any, List, Tuple, Union
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
import logging
from datetime import datetime, timedelta
import weakref
from collections import defaultdict
import ssl

# Import LRU cache and cleanup scheduler
from .lru_cache import create_ttl_dict
from .cleanup_scheduler import get_cleanup_scheduler

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientError
import aiodns

# Optional imports for database connections
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False

try:
    import motor.motor_asyncio
    HAS_MOTOR = True
except ImportError:
    HAS_MOTOR = False

try:
    import redis.asyncio as aioredis
    HAS_AIOREDIS = True
except ImportError:
    HAS_AIOREDIS = False

logger = logging.getLogger(__name__)


@dataclass
class ConnectionPoolConfig:
    """Configuration for connection pools."""
    # HTTP/HTTPS settings
    http_total_connections: int = 100
    http_per_host_connections: int = 10
    http_keepalive_timeout: int = 30
    http_connect_timeout: int = 10
    http_request_timeout: int = 60
    
    # Database settings
    db_min_connections: int = 5
    db_max_connections: int = 20
    db_connection_timeout: int = 10
    db_command_timeout: int = 30
    db_idle_timeout: int = 300
    
    # Redis settings
    redis_max_connections: int = 50
    redis_connection_timeout: int = 5
    redis_socket_timeout: int = 5
    redis_keepalive: bool = True
    
    # WebSocket settings
    ws_max_connections: int = 50
    ws_heartbeat_interval: int = 30
    ws_reconnect_interval: int = 5
    
    # General settings
    health_check_interval: int = 60
    connection_lifetime: int = 3600  # 1 hour
    enable_monitoring: bool = True


@dataclass
class ConnectionMetrics:
    """Metrics for connection pool monitoring."""
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_connections: int = 0
    active_connections: int = 0
    failed_connections: int = 0
    total_requests: int = 0
    total_errors: int = 0
    wait_time_sum: float = 0.0
    connection_reuse_count: int = 0
    health_check_failures: int = 0
    cleanup_count: int = 0
    expired_connections: int = 0
    
    def add_request(self, wait_time: float = 0.0):
        """Record a request."""
        self.total_requests += 1
        self.wait_time_sum += wait_time
    
    def add_error(self):
        """Record an error."""
        self.total_errors += 1
    
    def get_average_wait_time(self) -> float:
        """Get average wait time for connections."""
        if self.total_requests == 0:
            return 0.0
        return self.wait_time_sum / self.total_requests
    
    def get_error_rate(self) -> float:
        """Get error rate."""
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests


class HTTPConnectionPool:
    """HTTP/HTTPS connection pool using aiohttp."""
    
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        
        # Use TTL dict for sessions (TTL: 30 minutes, max: 50 sessions)
        self._sessions = create_ttl_dict(
            max_size=50,
            ttl=1800.0,  # 30 minutes
            cleanup_interval=300.0  # 5 minutes
        )
        
        # Metrics with TTL (TTL: 1 hour, max: 100 entries)
        self._session_metrics = create_ttl_dict(
            max_size=100,
            ttl=3600.0,  # 1 hour
            cleanup_interval=600.0  # 10 minutes
        )
        
        self._lock = asyncio.Lock()
        self._closed = False
        self._health_check_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Session timestamp tracking for lifecycle management
        self._session_timestamps: Dict[str, datetime] = {}
        
        # SSL context for HTTPS
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = True
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Register cleanup with scheduler
        try:
            cleanup_scheduler = get_cleanup_scheduler()
            cleanup_scheduler.register_cleanable_object(self._sessions)
            cleanup_scheduler.register_cleanable_object(self._session_metrics)
            cleanup_scheduler.register_task(
                name=f"http_pool_{id(self)}_cleanup",
                callback=self._cleanup_expired_sessions,
                interval_seconds=300.0,  # 5 minutes
                priority=cleanup_scheduler.TaskPriority.MEDIUM
            )
        except Exception as e:
            logger.warning(f"Could not register with cleanup scheduler: {e}")
    
    async def initialize(self):
        """Initialize the connection pool."""
        if self.config.enable_monitoring:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self._cleanup_task = asyncio.create_task(self._session_cleanup_loop())
    
    async def _create_session(self, base_url: str) -> ClientSession:
        """Create a new session for a base URL."""
        connector = TCPConnector(
            limit=self.config.http_total_connections,
            limit_per_host=self.config.http_per_host_connections,
            ttl_dns_cache=300,
            keepalive_timeout=self.config.http_keepalive_timeout,
            force_close=False,
            enable_cleanup_closed=True,
            ssl=self._ssl_context
        )
        
        timeout = ClientTimeout(
            connect=self.config.http_connect_timeout,
            total=self.config.http_request_timeout,
            sock_connect=self.config.http_connect_timeout,
            sock_read=self.config.http_request_timeout
        )
        
        session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Claude-Optimized-Deployment/1.0',
                'Accept': 'application/json',
            }
        )
        
        return session
    
    @asynccontextmanager
    async def get_session(self, base_url: str):
        """Get or create a session for the given base URL."""
        start_time = time.time()
        
        async with self._lock:
            if base_url not in self._sessions:
                self._sessions[base_url] = await self._create_session(base_url)
                # Initialize metrics if not present
                if base_url not in self._session_metrics:
                    self._session_metrics[base_url] = ConnectionMetrics()
                self._session_metrics[base_url].total_connections += 1
                
                # Track session creation timestamp
                self._session_timestamps[base_url] = datetime.now()
            
            session = self._sessions[base_url]
            metrics = self._session_metrics.get(base_url)
            if metrics is None:
                metrics = ConnectionMetrics()
                self._session_metrics[base_url] = metrics
            
        wait_time = time.time() - start_time
        metrics.add_request(wait_time)
        metrics.active_connections += 1
        
        try:
            yield session
            metrics.connection_reuse_count += 1
        except Exception as e:
            metrics.add_error()
            logger.error(f"HTTP session error for {base_url}: {e}")
            raise
        finally:
            metrics.active_connections -= 1
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Make an HTTP request with connection pooling."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        async with self.get_session(base_url) as session:
            try:
                async with session.request(method, url, **kwargs) as response:
                    return response
            except ClientError as e:
                metrics = self._session_metrics.get(base_url)
                if metrics:
                    metrics.failed_connections += 1
                raise
    
    async def _health_check_loop(self):
        """Periodic health check for connections."""
        while not self._closed:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._check_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _check_sessions(self):
        """Check health of existing sessions."""
        async with self._lock:
            for base_url, session in list(self._sessions.items()):
                if session.closed:
                    del self._sessions[base_url]
                    logger.info(f"Removed closed session for {base_url}")
    
    async def _session_cleanup_loop(self):
        """Periodic cleanup of session timestamps and metrics."""
        while not self._closed:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
    
    async def _cleanup_expired_sessions(self):
        """Clean up expired session timestamps."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.config.connection_lifetime)
        
        async with self._lock:
            # Clean up expired session timestamps
            expired_sessions = [
                url for url, timestamp in self._session_timestamps.items()
                if timestamp < cutoff_time
            ]
            
            for url in expired_sessions:
                del self._session_timestamps[url]
                # Update metrics
                if url in self._session_metrics:
                    self._session_metrics[url].expired_connections += 1
                    self._session_metrics[url].cleanup_count += 1
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired session timestamps")
    
    async def close(self):
        """Close all connections."""
        self._closed = True
        
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        async with self._lock:
            for session in self._sessions.values():
                await session.close()
            self._sessions.clear()
    
    def get_metrics(self) -> Dict[str, ConnectionMetrics]:
        """Get connection metrics."""
        return dict(self._session_metrics.items())
    
    def _cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and metrics.
        
        Returns:
            Number of expired entries removed
        """
        try:
            session_cleanup = self._sessions.cleanup()
            metrics_cleanup = self._session_metrics.cleanup()
            total_cleanup = session_cleanup + metrics_cleanup
            
            if total_cleanup > 0:
                logger.info(f"Cleaned up {session_cleanup} sessions and {metrics_cleanup} metrics")
            
            return total_cleanup
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
            return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        try:
            session_stats = self._sessions.get_stats()
            metrics_stats = self._session_metrics.get_stats()
            
            return {
                "sessions_cache": session_stats.to_dict(),
                "metrics_cache": metrics_stats.to_dict(),
                "active_sessions": len(self._sessions),
                "cached_metrics": len(self._session_metrics),
                "cache_type": "TTLDict with LRU eviction"
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}


class DatabaseConnectionPool:
    """Database connection pool supporting PostgreSQL and MongoDB."""
    
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        self._pg_pools: Dict[str, asyncpg.Pool] = {}
        self._mongo_clients: Dict[str, motor.motor_asyncio.AsyncIOMotorClient] = {}
        self._metrics: Dict[str, ConnectionMetrics] = defaultdict(ConnectionMetrics)
        self._lock = asyncio.Lock()
        self._closed = False
    
    @asynccontextmanager
    async def get_postgres_connection(self, dsn: str):
        """Get a PostgreSQL connection from the pool."""
        if not HAS_ASYNCPG:
            raise RuntimeError("asyncpg is not installed")
        
        start_time = time.time()
        
        async with self._lock:
            if dsn not in self._pg_pools:
                pool = await asyncpg.create_pool(
                    dsn,
                    min_size=self.config.db_min_connections,
                    max_size=self.config.db_max_connections,
                    command_timeout=self.config.db_command_timeout,
                    max_inactive_connection_lifetime=self.config.db_idle_timeout,
                    server_settings={
                        'application_name': 'claude-optimized-deployment'
                    }
                )
                self._pg_pools[dsn] = pool
                self._metrics[f"pg:{dsn}"].total_connections += 1
        
        pool = self._pg_pools[dsn]
        metrics = self._metrics[f"pg:{dsn}"]
        
        wait_time = time.time() - start_time
        metrics.add_request(wait_time)
        
        try:
            async with pool.acquire() as conn:
                metrics.active_connections += 1
                try:
                    yield conn
                finally:
                    metrics.active_connections -= 1
        except Exception as e:
            metrics.add_error()
            logger.error(f"PostgreSQL connection error: {e}")
            raise
    
    def get_mongo_client(self, uri: str) -> motor.motor_asyncio.AsyncIOMotorClient:
        """Get a MongoDB client."""
        if not HAS_MOTOR:
            raise RuntimeError("motor is not installed")
        
        if uri not in self._mongo_clients:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                uri,
                maxPoolSize=self.config.db_max_connections,
                minPoolSize=self.config.db_min_connections,
                maxIdleTimeMS=self.config.db_idle_timeout * 1000,
                serverSelectionTimeoutMS=self.config.db_connection_timeout * 1000,
                appname='claude-optimized-deployment'
            )
            self._mongo_clients[uri] = client
            self._metrics[f"mongo:{uri}"].total_connections += 1
        
        return self._mongo_clients[uri]
    
    async def close(self):
        """Close all database connections."""
        self._closed = True
        
        # Close PostgreSQL pools
        for pool in self._pg_pools.values():
            await pool.close()
        self._pg_pools.clear()
        
        # Close MongoDB clients
        for client in self._mongo_clients.values():
            client.close()
        self._mongo_clients.clear()
    
    def get_metrics(self) -> Dict[str, ConnectionMetrics]:
        """Get connection metrics."""
        return dict(self._metrics)


class RedisConnectionPool:
    """Redis connection pool using aioredis."""
    
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        self._pools: Dict[str, aioredis.Redis] = {}
        self._metrics: Dict[str, ConnectionMetrics] = defaultdict(ConnectionMetrics)
        self._lock = asyncio.Lock()
        self._closed = False
    
    async def get_redis(self, url: str) -> aioredis.Redis:
        """Get a Redis connection."""
        if not HAS_AIOREDIS:
            raise RuntimeError("aioredis is not installed")
        
        async with self._lock:
            if url not in self._pools:
                redis = await aioredis.from_url(
                    url,
                    max_connections=self.config.redis_max_connections,
                    socket_connect_timeout=self.config.redis_connection_timeout,
                    socket_timeout=self.config.redis_socket_timeout,
                    socket_keepalive=self.config.redis_keepalive,
                    health_check_interval=self.config.health_check_interval,
                    retry_on_timeout=True,
                    retry_on_error=[ConnectionError, TimeoutError]
                )
                self._pools[url] = redis
                self._metrics[url].total_connections += 1
        
        return self._pools[url]
    
    async def execute(self, url: str, command: str, *args, **kwargs):
        """Execute a Redis command."""
        start_time = time.time()
        redis = await self.get_redis(url)
        metrics = self._metrics[url]
        
        wait_time = time.time() - start_time
        metrics.add_request(wait_time)
        
        try:
            result = await getattr(redis, command)(*args, **kwargs)
            return result
        except Exception as e:
            metrics.add_error()
            logger.error(f"Redis command error: {e}")
            raise
    
    async def close(self):
        """Close all Redis connections."""
        self._closed = True
        
        for redis in self._pools.values():
            await redis.close()
        self._pools.clear()
    
    def get_metrics(self) -> Dict[str, ConnectionMetrics]:
        """Get connection metrics."""
        return dict(self._metrics)


class WebSocketConnectionPool:
    """WebSocket connection pool with automatic reconnection."""
    
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        self._connections: Dict[str, aiohttp.ClientWebSocketResponse] = {}
        self._sessions: Dict[str, ClientSession] = {}
        self._metrics: Dict[str, ConnectionMetrics] = defaultdict(ConnectionMetrics)
        self._reconnect_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._closed = False
    
    async def connect(
        self,
        url: str,
        **kwargs
    ) -> aiohttp.ClientWebSocketResponse:
        """Connect to a WebSocket endpoint."""
        async with self._lock:
            if url in self._connections and not self._connections[url].closed:
                return self._connections[url]
            
            # Create session if needed
            if url not in self._sessions:
                self._sessions[url] = ClientSession()
            
            session = self._sessions[url]
            metrics = self._metrics[url]
            
        try:
            ws = await session.ws_connect(
                url,
                heartbeat=self.config.ws_heartbeat_interval,
                **kwargs
            )
            
            async with self._lock:
                self._connections[url] = ws
                metrics.total_connections += 1
                metrics.active_connections += 1
            
            # Start reconnection monitor
            self._reconnect_tasks[url] = asyncio.create_task(
                self._monitor_connection(url, ws)
            )
            
            return ws
            
        except Exception as e:
            metrics.failed_connections += 1
            logger.error(f"WebSocket connection error: {e}")
            raise
    
    async def _monitor_connection(self, url: str, ws: aiohttp.ClientWebSocketResponse):
        """Monitor WebSocket connection and reconnect if needed."""
        while not self._closed:
            try:
                if ws.closed:
                    logger.info(f"WebSocket {url} closed, reconnecting...")
                    await self._reconnect(url)
                await asyncio.sleep(self.config.ws_reconnect_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"WebSocket monitor error: {e}")
    
    async def _reconnect(self, url: str):
        """Reconnect to a WebSocket endpoint."""
        metrics = self._metrics[url]
        
        for attempt in range(3):
            try:
                await asyncio.sleep(self.config.ws_reconnect_interval * (attempt + 1))
                
                async with self._lock:
                    session = self._sessions[url]
                
                ws = await session.ws_connect(
                    url,
                    heartbeat=self.config.ws_heartbeat_interval
                )
                
                async with self._lock:
                    self._connections[url] = ws
                    metrics.active_connections += 1
                
                logger.info(f"WebSocket {url} reconnected")
                return
                
            except Exception as e:
                logger.error(f"WebSocket reconnection attempt {attempt + 1} failed: {e}")
                metrics.failed_connections += 1
    
    async def send(self, url: str, data: Union[str, bytes]):
        """Send data through a WebSocket connection."""
        ws = await self.connect(url)
        metrics = self._metrics[url]
        
        try:
            if isinstance(data, str):
                await ws.send_str(data)
            else:
                await ws.send_bytes(data)
            metrics.add_request()
        except Exception as e:
            metrics.add_error()
            raise
    
    async def receive(self, url: str) -> aiohttp.WSMessage:
        """Receive data from a WebSocket connection."""
        ws = await self.connect(url)
        metrics = self._metrics[url]
        
        try:
            msg = await ws.receive()
            metrics.add_request()
            return msg
        except Exception as e:
            metrics.add_error()
            raise
    
    async def close(self):
        """Close all WebSocket connections."""
        self._closed = True
        
        # Cancel reconnection tasks
        for task in self._reconnect_tasks.values():
            task.cancel()
        
        # Close connections
        async with self._lock:
            for ws in self._connections.values():
                await ws.close()
            
            for session in self._sessions.values():
                await session.close()
            
            self._connections.clear()
            self._sessions.clear()
    
    def get_metrics(self) -> Dict[str, ConnectionMetrics]:
        """Get connection metrics."""
        return dict(self._metrics)


class ConnectionPoolManager:
    """
    Central manager for all connection pools.
    
    This class provides a unified interface for managing all types of
    connection pools with monitoring and graceful shutdown.
    """
    
    _instance: Optional[ConnectionPoolManager] = None
    _lock = asyncio.Lock()
    
    def __init__(self, config: Optional[ConnectionPoolConfig] = None):
        if ConnectionPoolManager._instance is not None:
            raise RuntimeError("Use get_instance() to get ConnectionPoolManager")
        
        self.config = config or ConnectionPoolConfig()
        self.http_pool = HTTPConnectionPool(self.config)
        self.db_pool = DatabaseConnectionPool(self.config)
        self.redis_pool = RedisConnectionPool(self.config)
        self.ws_pool = WebSocketConnectionPool(self.config)
        self._initialized = False
        self._monitor_task: Optional[asyncio.Task] = None
    
    @classmethod
    async def get_instance(cls, config: Optional[ConnectionPoolConfig] = None) -> ConnectionPoolManager:
        """Get singleton instance of ConnectionPoolManager."""
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(config)
                await cls._instance.initialize()
            return cls._instance
    
    async def initialize(self):
        """Initialize all connection pools."""
        if self._initialized:
            return
        
        await self.http_pool.initialize()
        
        if self.config.enable_monitoring:
            self._monitor_task = asyncio.create_task(self._monitor_pools())
        
        self._initialized = True
        logger.info("Connection pool manager initialized")
    
    async def _monitor_pools(self):
        """Monitor all connection pools and log metrics."""
        while self._initialized:
            try:
                await asyncio.sleep(300)  # Log every 5 minutes
                self._log_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
    
    def _log_metrics(self):
        """Log connection pool metrics."""
        # HTTP metrics
        for url, metrics in self.http_pool.get_metrics().items():
            logger.info(
                f"HTTP Pool {url}: "
                f"active={metrics.active_connections}, "
                f"total={metrics.total_connections}, "
                f"errors={metrics.get_error_rate():.2%}, "
                f"avg_wait={metrics.get_average_wait_time():.3f}s"
            )
        
        # Database metrics
        for dsn, metrics in self.db_pool.get_metrics().items():
            logger.info(
                f"DB Pool {dsn}: "
                f"active={metrics.active_connections}, "
                f"total={metrics.total_connections}, "
                f"errors={metrics.get_error_rate():.2%}"
            )
        
        # Redis metrics
        for url, metrics in self.redis_pool.get_metrics().items():
            logger.info(
                f"Redis Pool {url}: "
                f"total={metrics.total_connections}, "
                f"requests={metrics.total_requests}, "
                f"errors={metrics.get_error_rate():.2%}"
            )
        
        # WebSocket metrics
        for url, metrics in self.ws_pool.get_metrics().items():
            logger.info(
                f"WS Pool {url}: "
                f"active={metrics.active_connections}, "
                f"failed={metrics.failed_connections}, "
                f"errors={metrics.get_error_rate():.2%}"
            )
    
    async def close(self):
        """Close all connection pools gracefully."""
        logger.info("Shutting down connection pools...")
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Close all pools
        await asyncio.gather(
            self.http_pool.close(),
            self.db_pool.close(),
            self.redis_pool.close(),
            self.ws_pool.close(),
            return_exceptions=True
        )
        
        self._initialized = False
        ConnectionPoolManager._instance = None
        logger.info("Connection pools shut down")
    
    def get_all_metrics(self) -> Dict[str, Dict[str, ConnectionMetrics]]:
        """Get metrics from all connection pools."""
        return {
            "http": self.http_pool.get_metrics(),
            "database": self.db_pool.get_metrics(),
            "redis": self.redis_pool.get_metrics(),
            "websocket": self.ws_pool.get_metrics()
        }


# Convenience functions for easy access
async def get_connection_manager(config: Optional[ConnectionPoolConfig] = None) -> ConnectionPoolManager:
    """Get the global connection pool manager."""
    return await ConnectionPoolManager.get_instance(config)


async def close_all_connections():
    """Close all connection pools."""
    if ConnectionPoolManager._instance:
        await ConnectionPoolManager._instance.close()