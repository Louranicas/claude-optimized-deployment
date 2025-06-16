"""Database test configuration and fixtures.

Provides shared fixtures for database testing including:
- Test database setup/teardown
- Connection management
- Data fixtures
- Mock objects
"""

import pytest
import asyncio
import os
import tempfile
from typing import AsyncGenerator, Dict, Any, Optional
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import text, event
import aiosqlite

from src.database.connection import DatabaseConnection
from src.database.pool_manager import DatabasePoolManager, DatabasePoolConfig
from src.database.repositories.base import SQLAlchemyRepository
from src.database.repositories.user_repository import UserRepository
from src.database.repositories.audit_repository import AuditLogRepository
from src.database.repositories.metrics_repository import MetricsRepository
from src.database.models import SQLAlchemyUser, UserRole
from src.core.logging_config import get_logger

logger = get_logger(__name__)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db_url():
    """Create a temporary SQLite database URL for testing."""
    # Use in-memory SQLite database for speed
    return "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def test_postgresql_url():
    """PostgreSQL test database URL (if available)."""
    # Use environment variable or skip if not available
    pg_url = os.getenv("TEST_DATABASE_URL")
    if not pg_url:
        pytest.skip("PostgreSQL test database not configured")
    return pg_url


@pytest.fixture
async def test_engine(test_db_url):
    """Create a test database engine."""
    engine = create_async_engine(
        test_db_url,
        poolclass=StaticPool,
        connect_args={
            "check_same_thread": False,
        },
        echo=False  # Set to True for SQL debugging
    )
    
    # Create tables
    from src.database.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def test_session_factory(test_engine):
    """Create a test session factory."""
    return async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )


@pytest.fixture
async def test_session(test_session_factory):
    """Create a test database session with automatic rollback."""
    async with test_session_factory() as session:
        # Start a transaction
        transaction = await session.begin()
        
        try:
            yield session
        finally:
            # Always rollback to keep tests isolated
            await transaction.rollback()


@pytest.fixture
async def test_connection(test_db_url):
    """Create a test database connection."""
    connection = DatabaseConnection(test_db_url)
    await connection.init_sqlalchemy()
    yield connection
    await connection.close()


@pytest.fixture
async def test_pool_config(test_db_url):
    """Create test pool configuration."""
    return DatabasePoolConfig(
        connection_string=test_db_url,
        min_pool_size=2,
        max_pool_size=5,
        max_overflow=2,
        pool_recycle=3600,
        connect_timeout=5,
        command_timeout=10,
        enable_monitoring=True,
        pod_count=1
    )


@pytest.fixture
async def test_pool_manager(test_pool_config):
    """Create a test database pool manager."""
    pool_manager = DatabasePoolManager(test_pool_config)
    await pool_manager.initialize()
    yield pool_manager
    await pool_manager.close()


@pytest.fixture
def mock_metrics_collector():
    """Create a mock metrics collector."""
    mock = MagicMock()
    mock.gauge = MagicMock()
    mock.counter = MagicMock()
    mock.histogram = MagicMock()
    return mock


@pytest.fixture
async def sample_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "full_name": "Test User",
        "role": UserRole.VIEWER,
        "preferences": {"theme": "dark", "language": "en"}
    }


@pytest.fixture
async def sample_users_data():
    """Multiple sample users for testing."""
    return [
        {
            "username": "admin",
            "email": "admin@example.com", 
            "full_name": "Admin User",
            "role": UserRole.ADMIN
        },
        {
            "username": "developer",
            "email": "dev@example.com",
            "full_name": "Developer User", 
            "role": UserRole.DEVELOPER
        },
        {
            "username": "viewer",
            "email": "viewer@example.com",
            "full_name": "Viewer User",
            "role": UserRole.VIEWER
        }
    ]


@pytest.fixture
async def user_repository(test_session):
    """Create a user repository for testing."""
    repo = UserRepository()
    repo._session = test_session
    return repo


@pytest.fixture
async def audit_repository(test_session):
    """Create an audit log repository for testing."""
    repo = AuditLogRepository()
    repo._session = test_session
    return repo


@pytest.fixture
async def metrics_repository(test_session):
    """Create a metrics repository for testing."""
    repo = MetricsRepository()
    repo._session = test_session
    return repo


@pytest.fixture
async def created_test_user(user_repository, sample_user_data):
    """Create a test user in the database."""
    user = await user_repository.create(**sample_user_data)
    return user


@pytest.fixture
async def created_test_users(user_repository, sample_users_data):
    """Create multiple test users in the database."""
    users = []
    for user_data in sample_users_data:
        user = await user_repository.create(**user_data)
        users.append(user)
    return users


@pytest.fixture
def mock_circuit_breaker():
    """Create a mock circuit breaker."""
    mock = AsyncMock()
    mock.call = AsyncMock()
    mock.state = MagicMock()
    mock.state.name = "CLOSED"
    mock.failure_count = 0
    mock.last_failure_time = None
    return mock


@pytest.fixture
def mock_database_health():
    """Mock database health status."""
    return {
        "status": "healthy",
        "checks": {"engine": "ok"},
        "pool": {
            "size": 5,
            "checked_in": 3,
            "overflow": 0,
            "total": 5
        },
        "circuit_breaker": {
            "state": "CLOSED",
            "failure_count": 0,
            "last_failure": None
        }
    }


@pytest.fixture
async def connection_leak_detector():
    """Utility to detect connection leaks during tests."""
    connections_before = {}
    
    def record_connections():
        # In a real implementation, this would track actual connections
        return {"active": 0, "idle": 0}
    
    connections_before = record_connections()
    
    yield
    
    connections_after = record_connections()
    
    # Check for leaks
    if connections_after["active"] > connections_before["active"]:
        logger.warning(f"Potential connection leak detected: {connections_after}")


@pytest.fixture
def performance_timer():
    """Timer utility for performance testing."""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            
        def start(self):
            self.start_time = datetime.utcnow()
            
        def stop(self):
            self.end_time = datetime.utcnow()
            
        @property
        def elapsed_seconds(self):
            if self.start_time and self.end_time:
                return (self.end_time - self.start_time).total_seconds()
            return None
    
    return Timer()


@pytest.fixture
async def database_test_data():
    """Comprehensive test data for database operations."""
    return {
        "audit_logs": [
            {
                "action": "create_user",
                "resource_type": "user",
                "resource_id": "1",
                "user_id": 1,
                "details": {"username": "testuser"},
                "success": True
            },
            {
                "action": "login", 
                "resource_type": "auth",
                "user_id": 1,
                "ip_address": "127.0.0.1",
                "success": True
            }
        ],
        "metrics": [
            {
                "metric_name": "cpu_usage",
                "value": 75.5,
                "labels": {"instance": "test", "region": "us-east-1"}
            },
            {
                "metric_name": "memory_usage",
                "value": 85.2,
                "labels": {"instance": "test", "region": "us-east-1"}
            }
        ]
    }


@pytest.fixture
def stress_test_config():
    """Configuration for stress testing."""
    return {
        "concurrent_connections": 10,
        "operations_per_connection": 50,
        "timeout_seconds": 30,
        "connection_pool_size": 5
    }


@pytest.fixture
async def isolated_test_transaction(test_engine):
    """Create an isolated transaction for testing transaction behavior."""
    async with test_engine.connect() as conn:
        trans = await conn.begin()
        try:
            yield conn
        finally:
            await trans.rollback()


@pytest.fixture
def mock_database_error():
    """Mock database error for error handling tests."""
    from sqlalchemy.exc import DatabaseError
    return DatabaseError("Mock database error", None, None)


@pytest.fixture
def database_backup_config():
    """Configuration for database backup testing."""
    return {
        "backup_dir": tempfile.mkdtemp(),
        "retention_days": 7,
        "compression": True
    }


@pytest.fixture
async def setup_database_monitoring():
    """Set up database monitoring for tests."""
    from src.database.monitoring import DatabaseMonitor, DatabaseMonitorConfig
    
    config = DatabaseMonitorConfig(
        health_check_interval=1,  # Very short for testing
        metrics_collection_interval=1,
        leak_detection_interval=2,
        consecutive_failures_for_alert=2
    )
    
    monitor = DatabaseMonitor(config)
    yield monitor
    
    if monitor.is_monitoring:
        await monitor.stop_monitoring()


# Test utilities
class DatabaseTestUtils:
    """Utility class for database testing."""
    
    @staticmethod
    async def count_table_rows(session: AsyncSession, table_name: str) -> int:
        """Count rows in a table."""
        result = await session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        return result.scalar()
    
    @staticmethod
    async def clear_table(session: AsyncSession, table_name: str):
        """Clear all rows from a table."""
        await session.execute(text(f"DELETE FROM {table_name}"))
        await session.commit()
    
    @staticmethod
    def create_large_dataset(size: int, data_type: str = "user"):
        """Create a large dataset for performance testing."""
        if data_type == "user":
            return [
                {
                    "username": f"user_{i}",
                    "email": f"user_{i}@example.com",
                    "full_name": f"User {i}",
                    "role": UserRole.VIEWER
                }
                for i in range(size)
            ]
        elif data_type == "metrics":
            return [
                {
                    "metric_name": "test_metric",
                    "value": float(i % 100),
                    "labels": {"instance": f"test_{i % 10}"}
                }
                for i in range(size)
            ]
        else:
            raise ValueError(f"Unknown data type: {data_type}")


@pytest.fixture
def db_utils():
    """Database test utilities."""
    return DatabaseTestUtils


# Async cleanup utilities
@pytest.fixture(autouse=True)
async def cleanup_test_data():
    """Automatically cleanup test data after each test."""
    yield
    # Cleanup happens automatically via transaction rollback in test_session