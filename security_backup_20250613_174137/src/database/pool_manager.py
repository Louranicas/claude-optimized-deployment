"""Enhanced database connection pool manager with monitoring and circuit breakers.

This module provides:
- Connection pool management with proper sizing
- Automatic connection health checks
- Connection pool metrics and monitoring
- Circuit breakers for fault tolerance
- Graceful connection cleanup
- Pod-aware pool sizing
"""

import os
import asyncio
import time
from typing import Dict, Optional, Any, List, AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
    AsyncConnection
)
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool
from sqlalchemy import event, pool, text
from sqlalchemy.exc import DatabaseError as SQLAlchemyDatabaseError, TimeoutError
from tortoise import Tortoise
from tortoise.backends.base.client import BaseDBAsyncClient

from src.core.logging_config import get_logger
from src.core.exceptions import DatabaseConnectionError, ConfigurationError
from src.core.circuit_breaker import (
    CircuitBreakerConfig,
    get_circuit_breaker_manager,
    CircuitOpenError
)
from src.monitoring.metrics import MetricsCollector
from src.core.lru_cache import create_ttl_dict

logger = get_logger(__name__)

__all__ = [
    "DatabasePoolConfig",
    "DatabasePoolMetrics",
    "DatabasePoolManager",
    "get_pool_manager"
]


@dataclass
class DatabasePoolConfig:
    """Configuration for database connection pools."""
    # Connection string
    connection_string: str
    
    # Pool sizing
    min_pool_size: int = 5
    max_pool_size: int = 20
    max_overflow: int = 10
    pool_recycle: int = 3600  # 1 hour
    pool_pre_ping: bool = True
    pool_use_lifo: bool = True  # Last-in-first-out for better connection reuse
    
    # Timeouts (in seconds)
    connect_timeout: int = 10
    command_timeout: int = 30
    checkout_timeout: int = 30
    idle_timeout: int = 300  # 5 minutes
    
    # Circuit breaker settings
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: int = 60
    circuit_expected_exception_types: List[type] = field(default_factory=lambda: [
        SQLAlchemyDatabaseError, TimeoutError, ConnectionError
    ])
    
    # Health check settings
    health_check_interval: int = 60
    health_check_query: str = "SELECT 1"
    
    # Monitoring
    enable_monitoring: bool = True
    metrics_interval: int = 60
    
    # Pod awareness
    pod_count: Optional[int] = None
    connections_per_pod: int = 10
    
    def __post_init__(self):
        """Adjust pool size based on pod count if provided."""
        if self.pod_count and self.pod_count > 0:
            # Calculate pool size based on pod count
            total_connections = self.connections_per_pod * self.pod_count
            self.max_pool_size = min(total_connections, 50)  # Cap at 50
            self.min_pool_size = max(self.max_pool_size // 4, 2)  # At least 2
            self.max_overflow = self.max_pool_size // 2
            logger.info(
                f"Adjusted pool size for {self.pod_count} pods: "
                f"min={self.min_pool_size}, max={self.max_pool_size}, overflow={self.max_overflow}"
            )


@dataclass
class DatabasePoolMetrics:
    """Metrics for database connection pool monitoring."""
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Connection metrics
    total_connections_created: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    overflow_connections: int = 0
    
    # Request metrics
    total_checkouts: int = 0
    successful_checkouts: int = 0
    failed_checkouts: int = 0
    checkout_wait_time_sum: float = 0.0
    
    # Query metrics
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    query_time_sum: float = 0.0
    
    # Health metrics
    health_check_passes: int = 0
    health_check_failures: int = 0
    last_health_check: Optional[datetime] = None
    
    # Connection lifecycle
    connections_recycled: int = 0
    connections_invalidated: int = 0
    connection_timeouts: int = 0
    
    def record_checkout(self, wait_time: float, success: bool = True):
        """Record a connection checkout."""
        self.total_checkouts += 1
        self.checkout_wait_time_sum += wait_time
        if success:
            self.successful_checkouts += 1
        else:
            self.failed_checkouts += 1
    
    def record_query(self, execution_time: float, success: bool = True):
        """Record a query execution."""
        self.total_queries += 1
        self.query_time_sum += execution_time
        if success:
            self.successful_queries += 1
        else:
            self.failed_queries += 1
    
    def get_average_checkout_time(self) -> float:
        """Get average checkout wait time."""
        if self.total_checkouts == 0:
            return 0.0
        return self.checkout_wait_time_sum / self.total_checkouts
    
    def get_average_query_time(self) -> float:
        """Get average query execution time."""
        if self.total_queries == 0:
            return 0.0
        return self.query_time_sum / self.total_queries
    
    def get_checkout_failure_rate(self) -> float:
        """Get checkout failure rate."""
        if self.total_checkouts == 0:
            return 0.0
        return self.failed_checkouts / self.total_checkouts
    
    def get_query_failure_rate(self) -> float:
        """Get query failure rate."""
        if self.total_queries == 0:
            return 0.0
        return self.failed_queries / self.total_queries
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for reporting."""
        return {
            "created_at": self.created_at.isoformat(),
            "connections": {
                "total_created": self.total_connections_created,
                "active": self.active_connections,
                "idle": self.idle_connections,
                "overflow": self.overflow_connections,
                "recycled": self.connections_recycled,
                "invalidated": self.connections_invalidated,
                "timeouts": self.connection_timeouts
            },
            "checkouts": {
                "total": self.total_checkouts,
                "successful": self.successful_checkouts,
                "failed": self.failed_checkouts,
                "average_wait_time": self.get_average_checkout_time(),
                "failure_rate": self.get_checkout_failure_rate()
            },
            "queries": {
                "total": self.total_queries,
                "successful": self.successful_queries,
                "failed": self.failed_queries,
                "average_time": self.get_average_query_time(),
                "failure_rate": self.get_query_failure_rate()
            },
            "health": {
                "passes": self.health_check_passes,
                "failures": self.health_check_failures,
                "last_check": self.last_health_check.isoformat() if self.last_health_check else None
            }
        }


class DatabasePoolManager:
    """Enhanced database connection pool manager."""
    
    def __init__(self, config: DatabasePoolConfig):
        self.config = config
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None
        self._tortoise_initialized = False
        
        # Metrics
        self.metrics = DatabasePoolMetrics()
        self._metrics_collector = MetricsCollector() if config.enable_monitoring else None
        
        # Circuit breaker
        self._circuit_breaker = None
        
        # Health check task
        self._health_check_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        
        # Connection tracking for leak detection
        self._active_sessions: Dict[int, datetime] = {}
        self._session_lock = asyncio.Lock()
        
        # Query timeout cache (TTL: 1 hour)
        self._query_timeout_cache = create_ttl_dict(
            max_size=1000,
            ttl=3600.0,
            cleanup_interval=300.0
        )
        
        self._initialized = False
        self._closing = False
    
    async def initialize(self):
        """Initialize the database pool manager."""
        if self._initialized:
            return
        
        try:
            # Initialize circuit breaker
            manager = get_circuit_breaker_manager()
            self._circuit_breaker = await manager.get_or_create(
                "database_pool",
                CircuitBreakerConfig(
                    failure_threshold=self.config.circuit_failure_threshold,
                    timeout=self.config.circuit_recovery_timeout,
                    failure_rate_threshold=0.5,
                    expected_exception_types=self.config.circuit_expected_exception_types
                )
            )
            
            # Create engine with circuit breaker
            self._engine = await self._circuit_breaker.call(self._create_engine)
            
            # Create session factory
            self._session_factory = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Initialize Tortoise ORM if needed
            if self.config.connection_string.startswith("postgresql"):
                await self._init_tortoise()
            
            # Start background tasks
            if self.config.enable_monitoring:
                self._health_check_task = asyncio.create_task(self._health_check_loop())
                self._metrics_task = asyncio.create_task(self._metrics_loop())
            
            self._initialized = True
            logger.info("Database pool manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database pool manager: {e}")
            raise DatabaseConnectionError(f"Database pool initialization failed: {e}")
    
    async def _create_engine(self) -> AsyncEngine:
        """Create SQLAlchemy engine with proper configuration."""
        # Determine pool class based on database type
        if self.config.connection_string.startswith("sqlite"):
            pool_class = NullPool
            pool_config = {}
        else:
            pool_class = AsyncAdaptedQueuePool
            pool_config = {
                "pool_size": self.config.max_pool_size,
                "max_overflow": self.config.max_overflow,
                "pool_timeout": self.config.checkout_timeout,
                "pool_recycle": self.config.pool_recycle,
                "pool_pre_ping": self.config.pool_pre_ping,
                "pool_use_lifo": self.config.pool_use_lifo,
            }
        
        # Create engine
        engine = create_async_engine(
            self.config.connection_string,
            poolclass=pool_class,
            connect_args={
                "server_settings": {
                    "application_name": "claude-optimized-deployment",
                    "jit": "off"
                },
                "command_timeout": self.config.command_timeout,
                "timeout": self.config.connect_timeout
            } if self.config.connection_string.startswith("postgresql") else {},
            **pool_config
        )
        
        # Set up event listeners for monitoring
        if self.config.enable_monitoring:
            self._setup_pool_events(engine.pool)
        
        return engine
    
    def _setup_pool_events(self, pool: pool.Pool):
        """Set up connection pool event listeners for monitoring."""
        @event.listens_for(pool, "connect")
        def on_connect(dbapi_conn, connection_record):
            connection_record.info['connect_time'] = time.time()
            self.metrics.total_connections_created += 1
            logger.debug(f"New connection established: {id(dbapi_conn)}")
        
        @event.listens_for(pool, "checkout")
        def on_checkout(dbapi_conn, connection_record, connection_proxy):
            checkout_time = time.time() - connection_record.info.get('checkout_start', time.time())
            self.metrics.record_checkout(checkout_time, success=True)
            self.metrics.active_connections += 1
            self.metrics.idle_connections = max(0, self.metrics.idle_connections - 1)
            logger.debug(f"Connection checked out: {id(dbapi_conn)}")
        
        @event.listens_for(pool, "checkin")
        def on_checkin(dbapi_conn, connection_record):
            self.metrics.active_connections = max(0, self.metrics.active_connections - 1)
            self.metrics.idle_connections += 1
            logger.debug(f"Connection returned: {id(dbapi_conn)}")
        
        @event.listens_for(pool, "invalidate")
        def on_invalidate(dbapi_conn, connection_record, exception):
            self.metrics.connections_invalidated += 1
            logger.warning(f"Connection invalidated: {id(dbapi_conn)}, reason: {exception}")
        
        @event.listens_for(pool, "reset")
        def on_reset(dbapi_conn, connection_record):
            self.metrics.connections_recycled += 1
            logger.debug(f"Connection reset: {id(dbapi_conn)}")
    
    async def _init_tortoise(self):
        """Initialize Tortoise ORM for compatibility."""
        try:
            db_url = self.config.connection_string.replace("postgresql+asyncpg://", "postgres://")
            
            await Tortoise.init(
                db_url=db_url,
                modules={"models": ["src.database.models"]},
                timezone="UTC",
                use_tz=True,
                minsize=self.config.min_pool_size,
                maxsize=self.config.max_pool_size,
                max_queries=50000,
                max_inactive_connection_lifetime=self.config.idle_timeout
            )
            
            self._tortoise_initialized = True
            logger.info("Tortoise ORM initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Tortoise ORM: {e}")
            # Don't fail if Tortoise init fails - SQLAlchemy is primary
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with proper timeout and cleanup."""
        if not self._initialized:
            await self.initialize()
        
        if self._closing:
            raise DatabaseConnectionError("Database pool is closing")
        
        session_id = id(asyncio.current_task())
        start_time = time.time()
        session = None
        
        try:
            # Track session creation
            async with self._session_lock:
                self._active_sessions[session_id] = datetime.utcnow()
            
            # Get session through circuit breaker
            session = await self._circuit_breaker.call(self._session_factory)
            
            # Set query timeout for this session
            if self.config.connection_string.startswith("postgresql"):
                await session.execute(
                    text(f"SET statement_timeout = {self.config.command_timeout * 1000}")
                )
            
            yield session
            
            # Commit on success
            await session.commit()
            
        except CircuitOpenError:
            self.metrics.record_checkout(time.time() - start_time, success=False)
            raise DatabaseConnectionError("Database circuit breaker is open")
            
        except Exception as e:
            # Rollback on error
            if session:
                await session.rollback()
            
            # Record failure
            self.metrics.record_checkout(time.time() - start_time, success=False)
            
            # Log detailed error
            logger.error(f"Database session error: {e}", exc_info=True)
            raise
            
        finally:
            # Clean up session
            if session:
                await session.close()
            
            # Remove from active sessions
            async with self._session_lock:
                self._active_sessions.pop(session_id, None)
    
    @asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[AsyncConnection, None]:
        """Get a raw database connection for special operations."""
        if not self._initialized:
            await self.initialize()
        
        if self._closing:
            raise DatabaseConnectionError("Database pool is closing")
        
        async with self._engine.connect() as conn:
            yield conn
    
    async def execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> Any:
        """Execute a query with timeout and monitoring."""
        if timeout is None:
            timeout = self.config.command_timeout
        
        start_time = time.time()
        
        try:
            async with self.get_session() as session:
                # Set query-specific timeout if provided
                if timeout != self.config.command_timeout:
                    await session.execute(
                        text(f"SET LOCAL statement_timeout = {timeout * 1000}")
                    )
                
                result = await session.execute(text(query), params or {})
                
                # Record success
                execution_time = time.time() - start_time
                self.metrics.record_query(execution_time, success=True)
                
                # Cache successful query timeout
                self._query_timeout_cache[query] = timeout
                
                return result
                
        except asyncio.TimeoutError:
            self.metrics.connection_timeouts += 1
            self.metrics.record_query(time.time() - start_time, success=False)
            raise DatabaseConnectionError(f"Query timeout after {timeout}s")
            
        except Exception as e:
            self.metrics.record_query(time.time() - start_time, success=False)
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_status = {
            "status": "healthy",
            "checks": {},
            "metrics": self.metrics.to_dict()
        }
        
        # Check engine
        if self._engine:
            try:
                async with self._engine.connect() as conn:
                    await conn.execute(text(self.config.health_check_query))
                health_status["checks"]["engine"] = "ok"
                self.metrics.health_check_passes += 1
            except Exception as e:
                health_status["status"] = "unhealthy"
                health_status["checks"]["engine"] = f"failed: {str(e)}"
                self.metrics.health_check_failures += 1
        
        # Check pool status
        if hasattr(self._engine.pool, "size"):
            pool_info = {
                "size": self._engine.pool.size(),
                "checked_in": self._engine.pool.checkedin(),
                "overflow": self._engine.pool.overflow(),
                "total": self._engine.pool.size() + self._engine.pool.overflow()
            }
            health_status["pool"] = pool_info
            
            # Update metrics
            self.metrics.idle_connections = self._engine.pool.checkedin()
            self.metrics.overflow_connections = self._engine.pool.overflow()
        
        # Check for connection leaks
        async with self._session_lock:
            current_time = datetime.utcnow()
            leaked_sessions = []
            
            for session_id, created_at in self._active_sessions.items():
                age = (current_time - created_at).total_seconds()
                if age > self.config.idle_timeout:
                    leaked_sessions.append({
                        "session_id": session_id,
                        "age_seconds": age
                    })
            
            if leaked_sessions:
                health_status["status"] = "degraded"
                health_status["connection_leaks"] = leaked_sessions
                logger.warning(f"Detected {len(leaked_sessions)} potential connection leaks")
        
        # Check circuit breaker
        if self._circuit_breaker:
            health_status["circuit_breaker"] = {
                "state": self._circuit_breaker.state.name,
                "failure_count": self._circuit_breaker.failure_count,
                "last_failure": self._circuit_breaker.last_failure_time
            }
        
        self.metrics.last_health_check = datetime.utcnow()
        return health_status
    
    async def _health_check_loop(self):
        """Periodic health check background task."""
        while not self._closing:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self.health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _metrics_loop(self):
        """Periodic metrics reporting background task."""
        while not self._closing:
            try:
                await asyncio.sleep(self.config.metrics_interval)
                
                # Report metrics
                if self._metrics_collector:
                    metrics_data = self.metrics.to_dict()
                    
                    # Report connection metrics
                    self._metrics_collector.gauge(
                        "db_pool_active_connections",
                        self.metrics.active_connections
                    )
                    self._metrics_collector.gauge(
                        "db_pool_idle_connections",
                        self.metrics.idle_connections
                    )
                    self._metrics_collector.gauge(
                        "db_pool_overflow_connections",
                        self.metrics.overflow_connections
                    )
                    
                    # Report performance metrics
                    self._metrics_collector.histogram(
                        "db_pool_checkout_duration",
                        self.metrics.get_average_checkout_time()
                    )
                    self._metrics_collector.histogram(
                        "db_query_duration",
                        self.metrics.get_average_query_time()
                    )
                    
                    # Report error rates
                    self._metrics_collector.gauge(
                        "db_pool_checkout_failure_rate",
                        self.metrics.get_checkout_failure_rate()
                    )
                    self._metrics_collector.gauge(
                        "db_query_failure_rate",
                        self.metrics.get_query_failure_rate()
                    )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics reporting error: {e}")
    
    async def close(self):
        """Close the database pool and clean up resources."""
        if self._closing:
            return
        
        self._closing = True
        logger.info("Closing database pool manager...")
        
        # Cancel background tasks
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._metrics_task:
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass
        
        # Check for leaked sessions
        async with self._session_lock:
            if self._active_sessions:
                logger.warning(
                    f"Closing with {len(self._active_sessions)} active sessions - "
                    f"potential connection leak"
                )
        
        # Close SQLAlchemy engine
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
        
        # Close Tortoise connections
        if self._tortoise_initialized:
            await Tortoise.close_connections()
            self._tortoise_initialized = False
        
        logger.info("Database pool manager closed")


# Global instance
_pool_manager: Optional[DatabasePoolManager] = None
_pool_manager_lock = asyncio.Lock()


async def get_pool_manager(config: Optional[DatabasePoolConfig] = None) -> DatabasePoolManager:
    """Get or create the global database pool manager."""
    global _pool_manager
    
    async with _pool_manager_lock:
        if _pool_manager is None:
            if config is None:
                # Create default config from environment
                connection_string = os.getenv(
                    "DATABASE_URL",
                    "postgresql+asyncpg://postgres:postgres@localhost/code_deployment"
                )
                
                config = DatabasePoolConfig(
                    connection_string=connection_string,
                    pod_count=int(os.getenv("POD_COUNT", "1")),
                    min_pool_size=int(os.getenv("DB_MIN_POOL_SIZE", "5")),
                    max_pool_size=int(os.getenv("DB_MAX_POOL_SIZE", "20")),
                    connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", "10")),
                    command_timeout=int(os.getenv("DB_COMMAND_TIMEOUT", "30")),
                    enable_monitoring=os.getenv("DB_ENABLE_MONITORING", "true").lower() == "true"
                )
            
            _pool_manager = DatabasePoolManager(config)
            await _pool_manager.initialize()
        
        return _pool_manager


async def close_pool_manager():
    """Close the global database pool manager."""
    global _pool_manager
    
    if _pool_manager:
        await _pool_manager.close()
        _pool_manager = None