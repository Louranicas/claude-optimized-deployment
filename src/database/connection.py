"""Database connection management with async support and connection pooling.

This module handles:
- Async database connections for PostgreSQL and SQLite
- Connection pooling for optimal performance
- Environment-based configuration
- Health checks and connection monitoring
"""

import os
from typing import Optional, Dict, Any, Type, Union
from contextlib import asynccontextmanager
import asyncio
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool
from sqlalchemy import event, pool
from tortoise import Tortoise
from tortoise.backends.base.client import BaseDBAsyncClient

from src.core.logging_config import get_logger
from src.core.exceptions import DatabaseConnectionError, ConfigurationError
from src.core.circuit_breaker import (
    CircuitBreakerConfig,
    get_circuit_breaker_manager,
    CircuitOpenError
)

logger = get_logger(__name__)


class DatabaseConnection:
    """Manages database connections with async support and connection pooling."""
    
    def __init__(self, connection_string: Optional[str] = None):
        """Initialize database connection manager.
        
        Args:
            connection_string: Database URL. If None, reads from environment.
        """
        self.connection_string = connection_string or os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./code_deployment.db")
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None
        self._tortoise_initialized = False
        self._connection_pool_config = self._get_pool_config()
        
    def _get_pool_config(self) -> Dict[str, Any]:
        """Get connection pool configuration based on database type."""
        parsed = urlparse(self.connection_string)
        
        if parsed.scheme.startswith("postgresql"):
            return {
                "pool_size": int(os.getenv("DB_POOL_SIZE", "20")),
                "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
                "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT", "30")),
                "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "3600")),
                "pool_pre_ping": True,
                "echo_pool": os.getenv("DB_ECHO_POOL", "false").lower() == "true",
            }
        else:
            # SQLite doesn't support connection pooling
            return {"poolclass": NullPool}
    
    async def init_sqlalchemy(self) -> AsyncEngine:
        """Initialize SQLAlchemy async engine with connection pooling."""
        if self._engine is not None:
            return self._engine
        
        # Get circuit breaker for database initialization
        manager = get_circuit_breaker_manager()
        breaker = await manager.get_or_create(
            "database_init_sqlalchemy",
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout=30,
                failure_rate_threshold=0.5,
                fallback=lambda: self._get_fallback_engine()
            )
        )
        
        try:
            # Initialize engine through circuit breaker
            self._engine = await breaker.call(self._create_engine_with_config)
            
            logger.info(f"SQLAlchemy engine initialized for {self._get_db_type()}")
            return self._engine
            
        except CircuitOpenError:
            logger.warning("Database circuit breaker is open, using fallback")
            return self._get_fallback_engine()
        except Exception as e:
            logger.error(f"Failed to initialize SQLAlchemy: {e}")
            raise DatabaseConnectionError(f"SQLAlchemy initialization failed: {e}")
    
    async def _create_engine_with_config(self) -> AsyncEngine:
        """Create SQLAlchemy engine with configuration."""
        # Create async engine with appropriate pooling
        engine = create_async_engine(
            self.connection_string,
            echo=os.getenv("DB_ECHO", "false").lower() == "true",
            **self._connection_pool_config
        )
        
        # Set up connection pool monitoring
        if self.connection_string.startswith("postgresql"):
            self._setup_pool_monitoring(engine.pool)
        
        # Create session factory
        self._session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        return engine
    
    def _get_fallback_engine(self) -> Optional[AsyncEngine]:
        """Get fallback engine for when circuit breaker is open."""
        # Return existing engine if available
        if self._engine:
            return self._engine
        
        # Or raise an error to indicate database is unavailable
        raise DatabaseConnectionError("Database is temporarily unavailable (circuit breaker open)")
    
    async def init_tortoise(self) -> None:
        """Initialize Tortoise ORM with connection pooling."""
        if self._tortoise_initialized:
            return
            
        try:
            db_url = self._convert_to_tortoise_url(self.connection_string)
            
            await Tortoise.init(
                db_url=db_url,
                modules={"models": ["src.database.models"]},
                timezone="UTC",
                use_tz=True,
                # Connection pool settings for PostgreSQL
                **self._get_tortoise_pool_config()
            )
            
            self._tortoise_initialized = True
            logger.info(f"Tortoise ORM initialized for {self._get_db_type()}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Tortoise ORM: {e}")
            raise DatabaseConnectionError(f"Tortoise ORM initialization failed: {e}")
    
    def _convert_to_tortoise_url(self, url: str) -> str:
        """Convert SQLAlchemy URL format to Tortoise ORM format."""
        # Handle the conversion between different URL formats
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgres://")
        elif url.startswith("sqlite+aiosqlite://"):
            return url.replace("sqlite+aiosqlite://", "sqlite://")
        return url
    
    def _get_tortoise_pool_config(self) -> Dict[str, Any]:
        """Get Tortoise ORM specific pool configuration."""
        if self.connection_string.startswith("postgresql"):
            return {
                "minsize": int(os.getenv("DB_POOL_MIN_SIZE", "5")),
                "maxsize": int(os.getenv("DB_POOL_SIZE", "20")),
                "max_queries": int(os.getenv("DB_MAX_QUERIES", "50000")),
                "max_inactive_connection_lifetime": float(os.getenv("DB_CONNECTION_LIFETIME", "300")),
            }
        return {}
    
    def _setup_pool_monitoring(self, pool: pool.Pool) -> None:
        """Set up connection pool monitoring events."""
        @event.listens_for(pool, "connect")
        def on_connect(dbapi_conn, connection_record):
            connection_record.info['connect_time'] = asyncio.get_event_loop().time()
            logger.debug(f"New connection established: {id(dbapi_conn)}")
        
        @event.listens_for(pool, "checkout")
        def on_checkout(dbapi_conn, connection_record, connection_proxy):
            logger.debug(f"Connection checked out from pool: {id(dbapi_conn)}")
        
        @event.listens_for(pool, "checkin")
        def on_checkin(dbapi_conn, connection_record):
            logger.debug(f"Connection returned to pool: {id(dbapi_conn)}")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        """Get an async database session from the pool."""
        if self._session_factory is None:
            await self.init_sqlalchemy()
        
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def get_tortoise_connection(self) -> BaseDBAsyncClient:
        """Get a Tortoise ORM database connection."""
        if not self._tortoise_initialized:
            await self.init_tortoise()
        
        from tortoise import connections
        return connections.get("default")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check."""
        health_status = {
            "database_type": self._get_db_type(),
            "sqlalchemy_connected": False,
            "tortoise_connected": False,
            "pool_status": None,
        }
        
        # Check SQLAlchemy connection
        if self._engine:
            try:
                async with self._engine.connect() as conn:
                    await conn.execute("SELECT 1")
                health_status["sqlalchemy_connected"] = True
                
                # Get pool status for PostgreSQL
                if hasattr(self._engine.pool, "size"):
                    health_status["pool_status"] = {
                        "size": self._engine.pool.size(),
                        "checked_in": self._engine.pool.checkedin(),
                        "overflow": self._engine.pool.overflow(),
                        "total": self._engine.pool.size() + self._engine.pool.overflow()
                    }
            except Exception as e:
                logger.error(f"SQLAlchemy health check failed: {e}")
        
        # Check Tortoise connection
        if self._tortoise_initialized:
            try:
                conn = await self.get_tortoise_connection()
                await conn.execute_query("SELECT 1")
                health_status["tortoise_connected"] = True
            except Exception as e:
                logger.error(f"Tortoise health check failed: {e}")
        
        return health_status
    
    async def close(self) -> None:
        """Close all database connections and cleanup resources."""
        # Close SQLAlchemy
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("SQLAlchemy connections closed")
        
        # Close Tortoise
        if self._tortoise_initialized:
            await Tortoise.close_connections()
            self._tortoise_initialized = False
            logger.info("Tortoise ORM connections closed")
    
    def _get_db_type(self) -> str:
        """Get the database type from connection string."""
        if "postgresql" in self.connection_string:
            return "PostgreSQL"
        elif "sqlite" in self.connection_string:
            return "SQLite"
        else:
            return "Unknown"


# Global connection instance
_db_connection: Optional[DatabaseConnection] = None


async def init_database(connection_string: Optional[str] = None) -> DatabaseConnection:
    """Initialize the global database connection.
    
    Args:
        connection_string: Optional database URL. Uses environment if not provided.
        
    Returns:
        DatabaseConnection instance
    """
    global _db_connection
    
    if _db_connection is None:
        _db_connection = DatabaseConnection(connection_string)
        await _db_connection.init_sqlalchemy()
        await _db_connection.init_tortoise()
    
    return _db_connection


async def get_database_connection() -> DatabaseConnection:
    """Get the global database connection instance.
    
    Returns:
        DatabaseConnection instance
        
    Raises:
        DatabaseConnectionError: If database not initialized
    """
    if _db_connection is None:
        raise DatabaseConnectionError("Database not initialized. Call init_database() first.")
    
    return _db_connection


async def close_database() -> None:
    """Close the global database connection."""
    global _db_connection
    
    if _db_connection:
        await _db_connection.close()
        _db_connection = None