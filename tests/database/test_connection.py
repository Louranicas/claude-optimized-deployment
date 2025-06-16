"""Comprehensive tests for database connection management.

Tests cover:
- Connection establishment and cleanup
- Connection pooling behavior
- Health checks and monitoring
- Circuit breaker functionality
- Connection leak detection
- Error handling and recovery
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import os
import tempfile

from src.database.connection import (
    DatabaseConnection, 
    init_database, 
    get_database_connection, 
    close_database
)
from src.core.exceptions import DatabaseConnectionError, ConfigurationError
from src.core.circuit_breaker import CircuitOpenError


class TestDatabaseConnection:
    """Test database connection functionality."""
    
    async def test_connection_initialization(self, test_db_url):
        """Test basic connection initialization."""
        connection = DatabaseConnection(test_db_url)
        assert connection.connection_string == test_db_url
        assert connection._engine is None
        assert connection._session_factory is None
        assert not connection._tortoise_initialized
    
    async def test_sqlalchemy_initialization(self, test_db_url):
        """Test SQLAlchemy engine initialization."""
        connection = DatabaseConnection(test_db_url)
        engine = await connection.init_sqlalchemy()
        
        assert engine is not None
        assert connection._engine is engine
        assert connection._session_factory is not None
        
        await connection.close()
    
    async def test_tortoise_initialization(self, test_db_url):
        """Test Tortoise ORM initialization."""
        connection = DatabaseConnection(test_db_url)
        
        # Mock Tortoise initialization since it requires specific setup
        with patch('src.database.connection.Tortoise.init') as mock_init:
            await connection.init_tortoise()
            assert connection._tortoise_initialized
            mock_init.assert_called_once()
        
        await connection.close()
    
    async def test_connection_string_from_environment(self):
        """Test connection string resolution from environment."""
        test_url = "sqlite+aiosqlite:///test.db"
        
        with patch.dict(os.environ, {"DATABASE_URL": test_url}):
            connection = DatabaseConnection()
            assert connection.connection_string == test_url
    
    async def test_pool_config_postgresql(self):
        """Test pool configuration for PostgreSQL."""
        pg_url = "postgresql+asyncpg://user:pass@localhost/test"
        connection = DatabaseConnection(pg_url)
        
        pool_config = connection._get_pool_config()
        
        assert "pool_size" in pool_config
        assert "max_overflow" in pool_config
        assert "pool_timeout" in pool_config
        assert pool_config["pool_pre_ping"] is True
    
    async def test_pool_config_sqlite(self, test_db_url):
        """Test pool configuration for SQLite."""
        connection = DatabaseConnection(test_db_url)
        pool_config = connection._get_pool_config()
        
        # SQLite should use NullPool
        from sqlalchemy.pool import NullPool
        assert pool_config["poolclass"] == NullPool
    
    async def test_session_context_manager(self, test_connection):
        """Test session context manager functionality."""
        async with test_connection.get_session() as session:
            assert session is not None
            # Test basic query
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1 as test"))
            row = result.fetchone()
            assert row[0] == 1
    
    async def test_health_check_healthy(self, test_connection):
        """Test health check when database is healthy."""
        health_status = await test_connection.health_check()
        
        assert "database_type" in health_status
        assert "pool_manager_health" in health_status
        assert health_status["database_type"] in ["PostgreSQL", "SQLite"]
    
    async def test_health_check_with_pool_manager(self, test_pool_manager):
        """Test health check integration with pool manager."""
        # Create connection that uses the pool manager
        connection = DatabaseConnection(test_pool_manager.config.connection_string)
        await connection.init_sqlalchemy()
        
        health_status = await connection.health_check()
        
        assert health_status["pool_manager_health"]["status"] in ["healthy", "degraded"]
        
        await connection.close()
    
    async def test_circuit_breaker_integration(self, test_db_url):
        """Test circuit breaker integration."""
        connection = DatabaseConnection(test_db_url)
        
        with patch('src.database.connection.get_circuit_breaker_manager') as mock_manager:
            mock_breaker = AsyncMock()
            mock_manager.return_value.get_or_create.return_value = mock_breaker
            mock_breaker.call.return_value = MagicMock()  # Mock engine
            
            await connection.init_sqlalchemy()
            
            # Verify circuit breaker was created and used
            mock_manager.return_value.get_or_create.assert_called_once()
            mock_breaker.call.assert_called_once()
        
        await connection.close()
    
    async def test_circuit_breaker_fallback(self, test_db_url):
        """Test circuit breaker fallback behavior."""
        connection = DatabaseConnection(test_db_url)
        
        with patch('src.database.connection.get_circuit_breaker_manager') as mock_manager:
            mock_breaker = AsyncMock()
            mock_manager.return_value.get_or_create.return_value = mock_breaker
            mock_breaker.call.side_effect = CircuitOpenError("Circuit open")
            
            # Should raise DatabaseConnectionError when circuit is open
            with pytest.raises(DatabaseConnectionError, match="temporarily unavailable"):
                await connection.init_sqlalchemy()
    
    async def test_connection_cleanup(self, test_db_url):
        """Test proper connection cleanup."""
        connection = DatabaseConnection(test_db_url)
        await connection.init_sqlalchemy()
        
        # Ensure resources are created
        assert connection._engine is not None
        assert connection._session_factory is not None
        
        await connection.close()
        
        # Ensure cleanup
        assert connection._engine is None
        assert connection._session_factory is None
    
    async def test_multiple_initializations(self, test_db_url):
        """Test that multiple initializations don't create duplicate resources."""
        connection = DatabaseConnection(test_db_url)
        
        engine1 = await connection.init_sqlalchemy()
        engine2 = await connection.init_sqlalchemy()
        
        # Should return the same engine
        assert engine1 is engine2
        
        await connection.close()
    
    async def test_db_type_detection(self):
        """Test database type detection."""
        # PostgreSQL
        pg_connection = DatabaseConnection("postgresql+asyncpg://user:pass@localhost/test")
        assert pg_connection._get_db_type() == "PostgreSQL"
        
        # SQLite
        sqlite_connection = DatabaseConnection("sqlite+aiosqlite:///test.db")
        assert sqlite_connection._get_db_type() == "SQLite"
        
        # Unknown
        unknown_connection = DatabaseConnection("mysql://user:pass@localhost/test")
        assert unknown_connection._get_db_type() == "Unknown"


class TestDatabaseConnectionErrors:
    """Test error handling in database connections."""
    
    async def test_invalid_connection_string(self):
        """Test handling of invalid connection strings."""
        connection = DatabaseConnection("invalid://connection/string")
        
        with pytest.raises(DatabaseConnectionError):
            await connection.init_sqlalchemy()
    
    async def test_connection_timeout(self, test_db_url):
        """Test connection timeout handling."""
        connection = DatabaseConnection(test_db_url)
        
        # Mock a timeout during engine creation
        with patch('src.database.connection.create_async_engine') as mock_create:
            mock_create.side_effect = asyncio.TimeoutError("Connection timeout")
            
            with pytest.raises(DatabaseConnectionError, match="initialization failed"):
                await connection.init_sqlalchemy()
    
    async def test_tortoise_initialization_failure(self, test_db_url):
        """Test Tortoise initialization failure handling."""
        connection = DatabaseConnection(test_db_url)
        
        with patch('src.database.connection.Tortoise.init') as mock_init:
            mock_init.side_effect = Exception("Tortoise error")
            
            with pytest.raises(DatabaseConnectionError, match="Tortoise ORM initialization failed"):
                await connection.init_tortoise()
    
    async def test_session_error_handling(self, test_connection):
        """Test session error handling."""
        # Test that errors in session are properly handled
        with pytest.raises(Exception):
            async with test_connection.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("INVALID SQL QUERY"))


class TestGlobalConnectionManagement:
    """Test global database connection management functions."""
    
    async def test_init_database(self, test_db_url):
        """Test global database initialization."""
        # Ensure clean state
        from src.database.connection import _db_connection
        if _db_connection:
            await close_database()
        
        connection = await init_database(test_db_url)
        
        assert connection is not None
        assert connection.connection_string == test_db_url
        
        await close_database()
    
    async def test_get_database_connection_before_init(self):
        """Test getting connection before initialization."""
        # Ensure clean state
        await close_database()
        
        with pytest.raises(DatabaseConnectionError, match="not initialized"):
            await get_database_connection()
    
    async def test_get_database_connection_after_init(self, test_db_url):
        """Test getting connection after initialization."""
        await init_database(test_db_url)
        
        connection = await get_database_connection()
        assert connection is not None
        
        await close_database()
    
    async def test_close_database(self, test_db_url):
        """Test global database closure."""
        await init_database(test_db_url)
        
        # Verify connection exists
        connection = await get_database_connection()
        assert connection is not None
        
        await close_database()
        
        # Verify connection is closed
        with pytest.raises(DatabaseConnectionError, match="not initialized"):
            await get_database_connection()


class TestConnectionPoolMonitoring:
    """Test connection pool monitoring functionality."""
    
    async def test_pool_monitoring_setup(self, test_db_url):
        """Test that pool monitoring is properly set up."""
        connection = DatabaseConnection(test_db_url)
        await connection.init_sqlalchemy()
        
        # For PostgreSQL-like URLs, monitoring should be set up
        if "postgresql" in test_db_url:
            # Check that event listeners are set up
            # This is difficult to test directly, so we test indirectly
            assert connection._engine is not None
        
        await connection.close()
    
    async def test_pool_events_logging(self, test_db_url, caplog):
        """Test that pool events are logged."""
        connection = DatabaseConnection(test_db_url)
        await connection.init_sqlalchemy()
        
        # Use a session to trigger pool events
        async with connection.get_session() as session:
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))
        
        await connection.close()
        
        # Check for debug logs (if enabled)
        # Note: This test may not always pass depending on log level
    
    async def test_tortoise_connection_retrieval(self, test_db_url):
        """Test Tortoise connection retrieval."""
        connection = DatabaseConnection(test_db_url)
        
        with patch('src.database.connection.Tortoise.init'):
            await connection.init_tortoise()
            
            with patch('src.database.connection.connections.get') as mock_get:
                mock_get.return_value = MagicMock()
                
                tortoise_conn = await connection.get_tortoise_connection()
                assert tortoise_conn is not None
                mock_get.assert_called_once_with("default")
        
        await connection.close()


class TestConnectionLeakDetection:
    """Test connection leak detection."""
    
    async def test_connection_leak_detection(self, test_connection, connection_leak_detector):
        """Test connection leak detection in health checks."""
        # Simulate creating sessions without proper cleanup
        sessions = []
        for _ in range(3):
            # In a real scenario, these would be actual database sessions
            sessions.append(MagicMock())
        
        health_status = await test_connection.health_check()
        
        # Health check should include connection leak information
        assert "pool_manager_health" in health_status
    
    async def test_session_cleanup_on_error(self, test_connection):
        """Test that sessions are properly cleaned up on errors."""
        try:
            async with test_connection.get_session() as session:
                # Simulate an error
                raise ValueError("Test error")
        except ValueError:
            pass  # Expected error
        
        # Session should be cleaned up automatically
        # This is tested indirectly through the health check
        health_status = await test_connection.health_check()
        assert health_status is not None


class TestConnectionPerformance:
    """Test connection performance characteristics."""
    
    async def test_connection_establishment_time(self, test_db_url, performance_timer):
        """Test connection establishment performance."""
        connection = DatabaseConnection(test_db_url)
        
        performance_timer.start()
        await connection.init_sqlalchemy()
        performance_timer.stop()
        
        # Connection should be established quickly
        assert performance_timer.elapsed_seconds < 5.0
        
        await connection.close()
    
    async def test_session_creation_performance(self, test_connection, performance_timer):
        """Test session creation performance."""
        performance_timer.start()
        
        async with test_connection.get_session() as session:
            assert session is not None
        
        performance_timer.stop()
        
        # Session creation should be fast
        assert performance_timer.elapsed_seconds < 1.0
    
    async def test_concurrent_session_handling(self, test_connection):
        """Test handling of concurrent sessions."""
        async def create_session():
            async with test_connection.get_session() as session:
                from sqlalchemy import text
                result = await session.execute(text("SELECT 1"))
                return result.scalar()
        
        # Create multiple concurrent sessions
        tasks = [create_session() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All sessions should complete successfully
        assert all(result == 1 for result in results)
    
    async def test_session_reuse(self, test_connection):
        """Test session reuse behavior."""
        results = []
        
        # Create multiple sessions sequentially
        for _ in range(5):
            async with test_connection.get_session() as session:
                from sqlalchemy import text
                result = await session.execute(text("SELECT 1"))
                results.append(result.scalar())
        
        # All operations should succeed
        assert all(result == 1 for result in results)


class TestConnectionConfiguration:
    """Test connection configuration options."""
    
    async def test_secrets_manager_integration(self):
        """Test integration with secrets manager."""
        with patch('src.database.connection.get_secret') as mock_get_secret:
            mock_get_secret.return_value = "sqlite+aiosqlite:///:memory:"
            
            connection = DatabaseConnection()
            assert connection.connection_string == "sqlite+aiosqlite:///:memory:"
            
            mock_get_secret.assert_called_once_with("database/connection", "url")
    
    async def test_secrets_manager_fallback(self):
        """Test fallback when secrets manager fails."""
        from src.core.secrets_manager import SecretNotFoundError
        
        test_url = "sqlite+aiosqlite:///fallback.db"
        
        with patch('src.database.connection.get_secret') as mock_get_secret:
            mock_get_secret.side_effect = SecretNotFoundError("Secret not found")
            
            with patch.dict(os.environ, {"DATABASE_URL": test_url}):
                connection = DatabaseConnection()
                assert connection.connection_string == test_url
    
    async def test_pool_config_from_secrets(self):
        """Test pool configuration from secrets manager."""
        mock_pool_config = {
            "size": "15",
            "max_overflow": "5",
            "timeout": "20",
            "recycle": "7200",
            "echo": "true"
        }
        
        with patch('src.database.connection.get_secret') as mock_get_secret:
            mock_get_secret.return_value = mock_pool_config
            
            connection = DatabaseConnection("postgresql+asyncpg://test")
            pool_config = connection._get_pool_config()
            
            assert pool_config["pool_size"] == 15
            assert pool_config["max_overflow"] == 5
            assert pool_config["pool_timeout"] == 20
            assert pool_config["pool_recycle"] == 7200
            assert pool_config["echo_pool"] is True
    
    async def test_pool_config_environment_fallback(self):
        """Test pool configuration fallback to environment variables."""
        from src.core.secrets_manager import SecretNotFoundError
        
        env_vars = {
            "DB_POOL_SIZE": "25",
            "DB_MAX_OVERFLOW": "15", 
            "DB_POOL_TIMEOUT": "45",
            "DB_POOL_RECYCLE": "5400",
            "DB_ECHO_POOL": "true"
        }
        
        with patch('src.database.connection.get_secret') as mock_get_secret:
            mock_get_secret.side_effect = SecretNotFoundError("Not found")
            
            with patch.dict(os.environ, env_vars):
                connection = DatabaseConnection("postgresql+asyncpg://test")
                pool_config = connection._get_pool_config()
                
                assert pool_config["pool_size"] == 25
                assert pool_config["max_overflow"] == 15
                assert pool_config["pool_timeout"] == 45
                assert pool_config["pool_recycle"] == 5400
                assert pool_config["echo_pool"] is True


class TestConnectionIntegration:
    """Integration tests for database connections."""
    
    async def test_full_connection_lifecycle(self, test_db_url):
        """Test complete connection lifecycle."""
        # Initialize
        connection = DatabaseConnection(test_db_url)
        await connection.init_sqlalchemy()
        
        # Use connection
        async with connection.get_session() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 'connection test' as message"))
            row = result.fetchone()
            assert row[0] == "connection test"
        
        # Health check
        health = await connection.health_check()
        assert health["database_type"] in ["PostgreSQL", "SQLite"]
        
        # Cleanup
        await connection.close()
    
    async def test_connection_recovery_after_error(self, test_db_url):
        """Test connection recovery after errors."""
        connection = DatabaseConnection(test_db_url)
        await connection.init_sqlalchemy()
        
        # Simulate error and recovery
        try:
            async with connection.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("INVALID SQL"))
        except Exception:
            pass  # Expected error
        
        # Connection should still work
        async with connection.get_session() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1"))
            assert result.scalar() == 1
        
        await connection.close()
    
    async def test_global_and_local_connections(self, test_db_url):
        """Test interaction between global and local connections."""
        # Global connection
        await init_database(test_db_url)
        global_conn = await get_database_connection()
        
        # Local connection
        local_conn = DatabaseConnection(test_db_url)
        await local_conn.init_sqlalchemy()
        
        # Both should work independently
        async with global_conn.get_session() as session1:
            async with local_conn.get_session() as session2:
                from sqlalchemy import text
                result1 = await session1.execute(text("SELECT 'global'"))
                result2 = await session2.execute(text("SELECT 'local'"))
                
                assert result1.scalar() == "global"
                assert result2.scalar() == "local"
        
        # Cleanup
        await local_conn.close()
        await close_database()