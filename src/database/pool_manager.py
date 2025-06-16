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
                    "jit": "off"\n                },\n                "command_timeout": self.config.command_timeout,\n                "timeout": self.config.connect_timeout\n            } if self.config.connection_string.startswith("postgresql") else {},\n            **pool_config\n        )\n\n        # Set up event listeners for monitoring\n        if self.config.enable_monitoring:\n            self._setup_pool_events(engine.pool)\n\n        return engine\n\n    def _setup_pool_events(self, pool: pool.Pool):\n        """Set up connection pool event listeners for monitoring."""\n        @event.listens_for(pool, "connect")\n        def on_connect(dbapi_conn, connection_record):\n            connection_record.info['connect_time'] = time.time()\n            self.metrics.total_connections_created += 1\n            logger.debug(f"New connection established: {id(dbapi_conn)}")\n\n        @event.listens_for(pool, "checkout")\n        def on_checkout(dbapi_conn, connection_record, connection_proxy):\n            checkout_time = time.time() - connection_record.info.get('checkout_start', time.time())\n            self.metrics.record_checkout(checkout_time, success=True)\n            self.metrics.active_connections += 1\n            self.metrics.idle_connections = max(0, self.metrics.idle_connections - 1)\n            logger.debug(f"Connection checked out: {id(dbapi_conn)}")\n\n        @event.listens_for(pool, "checkin")\n        def on_checkin(dbapi_conn, connection_record):\n            self.metrics.active_connections = max(0, self.metrics.active_connections - 1)\n            self.metrics.idle_connections += 1\n            logger.debug(f"Connection returned: {id(dbapi_conn)}")\n\n        @event.listens_for(pool, "invalidate")\n        def on_invalidate(dbapi_conn, connection_record, exception):\n            self.metrics.connections_invalidated += 1\n            logger.warning(f"Connection invalidated: {id(dbapi_conn)}, reason: {exception}")\n\n        @event.listens_for(pool, "reset")\n        def on_reset(dbapi_conn, connection_record):\n            self.metrics.connections_recycled += 1\n            logger.debug(f"Connection reset: {id(dbapi_conn)}")\n\n    async def _init_tortoise(self):\n        """Initialize Tortoise ORM for compatibility."""\n        try:\n            db_url = self.config.connection_string.replace("postgresql+asyncpg://", "postgres://")\n\n            await Tortoise.init(\n                db_url=db_url,\n                modules={"models": ["src.database.models"]},\n                timezone="UTC",\n                use_tz=True,\n                minsize=self.config.min_pool_size,\n                maxsize=self.config.max_pool_size,\n                max_queries=50000,\n                max_inactive_connection_lifetime=self.config.idle_timeout\n            )\n\n            self._tortoise_initialized = True\n            logger.info("Tortoise ORM initialized")\n\n        except Exception as e:\n            logger.error(f"Failed to initialize Tortoise ORM: {e}")\n            # Don't fail if Tortoise init fails - SQLAlchemy is primary\n\n    @asynccontextmanager\n    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:\n        """Get a database session with proper timeout and cleanup."""\n        if not self._initialized:\n            await self.initialize()\n\n        if self._closing:\n            raise DatabaseConnectionError("Database pool is closing")\n\n        session_id = id(asyncio.current_task())\n        start_time = time.time()\n        session = None\n\n        try:\n            # Track session creation\n            async with self._session_lock:\n                self._active_sessions[session_id] = datetime.utcnow()\n\n            # Get session through circuit breaker\n            session = await self._circuit_breaker.call(self._session_factory)\n\n            # Set query timeout for this session\n            if self.config.connection_string.startswith("postgresql"):\n                await session.execute(\n                    text(f"SET statement_timeout = {self.config.command_timeout * 1000}")\n                )\n\n            yield session\n\n            # Commit on success\n            await session.commit()\n\n        except CircuitOpenError:\n            self.metrics.record_checkout(time.time() - start_time, success=False)\n            raise DatabaseConnectionError("Database circuit breaker is open")\n\n        except Exception as e:\n            # Rollback on error\n            if session:\n                await session.rollback()\n\n            # Record failure\n            self.metrics.record_checkout(time.time() - start_time, success=False)\n\n            # Log detailed error\n            logger.error(f"Database session error: {e}", exc_info=True)\n            raise\n\n        finally:\n            # Clean up session\n            if session:\n                await session.close()\n\n            # Remove from active sessions\n            async with self._session_lock:\n                self._active_sessions.pop(session_id, None)\n\n    @asynccontextmanager\n    async def get_connection(self) -> AsyncGenerator[AsyncConnection, None]:\n        """Get a raw database connection for special operations."""\n        if not self._initialized:\n            await self.initialize()\n\n        if self._closing:\n            raise DatabaseConnectionError("Database pool is closing")\n\n        async with self._engine.connect() as conn:\n            yield conn\n\n    async def execute_query(\n        self,\n        query: str,\n        params: Optional[Dict[str, Any]] = None,\n        timeout: Optional[int] = None\n    ) -> Any:\n        """Execute a query with timeout and monitoring."""\n        if timeout is None:\n            timeout = self.config.command_timeout\n\n        start_time = time.time()\n\n        try:\n            async with self.get_session() as session:\n                # Set query-specific timeout if provided\n                if timeout != self.config.command_timeout:\n                    await session.execute(\n                        text(f"SET LOCAL statement_timeout = {timeout * 1000}")\n                    )\n\n                result = await session.execute(text(query), params or {})\n\n                # Record success\n                execution_time = time.time() - start_time\n                self.metrics.record_query(execution_time, success=True)\n\n                # Cache successful query timeout\n                self._query_timeout_cache[query] = timeout\n\n                return result\n\n        except asyncio.TimeoutError:\n            self.metrics.connection_timeouts += 1\n            self.metrics.record_query(time.time() - start_time, success=False)\n            raise DatabaseConnectionError(f"Query timeout after {timeout}s")\n\n        except Exception as e:\n            self.metrics.record_query(time.time() - start_time, success=False)\n            raise\n\n    async def health_check(self) -> Dict[str, Any]:\n        """Perform comprehensive health check."""\n        health_status = {\n            "status": "healthy",\n            "checks": {},\n            "metrics": self.metrics.to_dict()\n        }\n\n        # Check engine\n        if self._engine:\n            try:\n                async with self._engine.connect() as conn:\n                    await conn.execute(text(self.config.health_check_query))\n                health_status["checks"]["engine"] = "ok"\n                self.metrics.health_check_passes += 1\n            except Exception as e:\n                health_status["status"] = "unhealthy"\n                health_status["checks"]["engine"] = f"failed: {str(e)}"\n                self.metrics.health_check_failures += 1\n\n        # Check pool status\n        if hasattr(self._engine.pool, "size"):\n            pool_info = {\n                "size": self._engine.pool.size(),\n                "checked_in": self._engine.pool.checkedin(),\n                "overflow": self._engine.pool.overflow(),\n                "total": self._engine.pool.size() + self._engine.pool.overflow()\n            }\n            health_status["pool"] = pool_info\n\n            # Update metrics\n            self.metrics.idle_connections = self._engine.pool.checkedin()\n            self.metrics.overflow_connections = self._engine.pool.overflow()\n\n        # Check for connection leaks\n        async with self._session_lock:\n            current_time = datetime.utcnow()\n            leaked_sessions = []\n\n            for session_id, created_at in self._active_sessions.items():\n                age = (current_time - created_at).total_seconds()\n                if age > self.config.idle_timeout:\n                    leaked_sessions.append({\n                        "session_id": session_id,\n                        "age_seconds": age\n                    })\n\n            if leaked_sessions:\n                health_status["status"] = "degraded"\n                health_status["connection_leaks"] = leaked_sessions\n                logger.warning(f"Detected {len(leaked_sessions)} potential connection leaks")\n\n        # Check circuit breaker\n        if self._circuit_breaker:\n            health_status["circuit_breaker"] = {\n                "state": self._circuit_breaker.state.name,\n                "failure_count": self._circuit_breaker.failure_count,\n                "last_failure": self._circuit_breaker.last_failure_time\n            }\n\n        self.metrics.last_health_check = datetime.utcnow()\n        return health_status\n\n    async def _health_check_loop(self):\n        """Periodic health check background task."""\n        while not self._closing:\n            try:\n                await asyncio.sleep(self.config.health_check_interval)\n                await self.health_check()\n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f"Health check error: {e}")\n\n    async def _metrics_loop(self):\n        """Periodic metrics reporting background task."""\n        while not self._closing:\n            try:\n                await asyncio.sleep(self.config.metrics_interval)\n\n                # Report metrics\n                if self._metrics_collector:\n                    metrics_data = self.metrics.to_dict()\n\n                    # Report connection metrics\n                    self._metrics_collector.gauge(\n                        "db_pool_active_connections",\n                        self.metrics.active_connections\n                    )\n                    self._metrics_collector.gauge(\n                        "db_pool_idle_connections",\n                        self.metrics.idle_connections\n                    )\n                    self._metrics_collector.gauge(\n                        "db_pool_overflow_connections",\n                        self.metrics.overflow_connections\n                    )\n\n                    # Report performance metrics\n                    self._metrics_collector.histogram(\n                        "db_pool_checkout_duration",\n                        self.metrics.get_average_checkout_time()\n                    )\n                    self._metrics_collector.histogram(\n                        "db_query_duration",\n                        self.metrics.get_average_query_time()\n                    )\n\n                    # Report error rates\n                    self._metrics_collector.gauge(\n                        "db_pool_checkout_failure_rate",\n                        self.metrics.get_checkout_failure_rate()\n                    )\n                    self._metrics_collector.gauge(\n                        "db_query_failure_rate",\n                        self.metrics.get_query_failure_rate()\n                    )\n\n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f"Metrics reporting error: {e}")\n\n    async def close(self):\n        """Close the database pool and clean up resources."""\n        if self._closing:\n            return\n\n        self._closing = True\n        logger.info("Closing database pool manager...")\n\n        # Cancel background tasks\n        if self._health_check_task:\n            self._health_check_task.cancel()\n            try:\n                await self._health_check_task\n            except asyncio.CancelledError:\n                pass\n\n        if self._metrics_task:\n            self._metrics_task.cancel()\n            try:\n                await self._metrics_task\n            except asyncio.CancelledError:\n                pass\n\n        # Check for leaked sessions\n        async with self._session_lock:\n            if self._active_sessions:\n                logger.warning(\n                    f"Closing with {len(self._active_sessions)} active sessions - "\n                    f"potential connection leak"\n                )\n\n        # Close SQLAlchemy engine\n        if self._engine:\n            await self._engine.dispose()\n            self._engine = None\n            self._session_factory = None\n\n        # Close Tortoise connections\n        if self._tortoise_initialized:\n            await Tortoise.close_connections()\n            self._tortoise_initialized = False\n\n        logger.info("Database pool manager closed")\n\n\n# Global instance\n_pool_manager: Optional[DatabasePoolManager] = None\n_pool_manager_lock = asyncio.Lock()\n\n\nasync def get_pool_manager(config: Optional[DatabasePoolConfig] = None) -> DatabasePoolManager:\n    """Get or create the global database pool manager."""\n    global _pool_manager\n\n    async with _pool_manager_lock:\n        if _pool_manager is None:\n            if config is None:\n                # Create default config from environment\n                connection_string = os.getenv(\n                    "DATABASE_URL",\n                    "postgresql+asyncpg://postgres:postgres@localhost/code_deployment"\n                )\n\n                config = DatabasePoolConfig(\n                    connection_string=connection_string,\n                    pod_count=int(os.getenv("POD_COUNT", "1")),\n                    min_pool_size=int(os.getenv("DB_MIN_POOL_SIZE", "5")),\n                    max_pool_size=int(os.getenv("DB_MAX_POOL_SIZE", "20")),\n                    connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", "10")),\n                    command_timeout=int(os.getenv("DB_COMMAND_TIMEOUT", "30")),\n                    enable_monitoring=os.getenv("DB_ENABLE_MONITORING", "true").lower() == "true"\n                )\n\n            _pool_manager = DatabasePoolManager(config)\n            await _pool_manager.initialize()\n\n        return _pool_manager\n\n\nasync def close_pool_manager():\n    """Close the global database pool manager."""\n    global _pool_manager\n\n    if _pool_manager:\n        await _pool_manager.close()\n        _pool_manager = None