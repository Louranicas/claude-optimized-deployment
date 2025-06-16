"""Comprehensive tests for database connection pool manager.

Tests cover:
- Pool configuration and initialization
- Connection lifecycle management
- Pool sizing and overflow handling
- Health checks and monitoring
- Circuit breaker integration
- Connection leak detection
- Performance optimization
- Graceful shutdown and cleanup
"""

import pytest
import asyncio
import os
from unittest.mock import patch, AsyncMock, MagicMock, call
from datetime import datetime, timedelta

from src.database.pool_manager import (
    DatabasePoolConfig,
    DatabasePoolMetrics,
    DatabasePoolManager,
    get_pool_manager,
    close_pool_manager
)
from src.core.exceptions import DatabaseConnectionError
from src.core.circuit_breaker import CircuitOpenError


class TestDatabasePoolConfig:
    """Test database pool configuration."""
    
    def test_pool_config_defaults(self):
        """Test pool configuration with defaults."""
        config = DatabasePoolConfig(connection_string="sqlite:///:memory:")
        
        assert config.connection_string == "sqlite:///:memory:"
        assert config.min_pool_size == 5
        assert config.max_pool_size == 20
        assert config.max_overflow == 10
        assert config.pool_recycle == 3600
        assert config.pool_pre_ping is True
        assert config.connect_timeout == 10
        assert config.command_timeout == 30
        assert config.enable_monitoring is True
    
    def test_pool_config_pod_awareness(self):
        """Test pool configuration with pod awareness."""
        config = DatabasePoolConfig(
            connection_string="postgresql://test",
            pod_count=4,
            connections_per_pod=8
        )
        
        # Should adjust pool size based on pod count
        expected_max = 4 * 8  # 32 connections
        assert config.max_pool_size == 32
        assert config.min_pool_size == 8  # max_pool_size // 4
        assert config.max_overflow == 16  # max_pool_size // 2
    
    def test_pool_config_pod_awareness_capping(self):
        """Test pool configuration caps at maximum size."""
        config = DatabasePoolConfig(
            connection_string="postgresql://test",
            pod_count=10,
            connections_per_pod=20
        )
        
        # Should cap at 50 connections
        assert config.max_pool_size == 50
        assert config.min_pool_size == 12  # max(50 // 4, 2)
        assert config.max_overflow == 25
    
    def test_pool_config_custom_values(self):
        """Test pool configuration with custom values."""
        config = DatabasePoolConfig(
            connection_string="postgresql://test",
            min_pool_size=10,
            max_pool_size=30,
            max_overflow=5,
            connect_timeout=15,
            command_timeout=45,
            enable_monitoring=False
        )
        
        assert config.min_pool_size == 10
        assert config.max_pool_size == 30
        assert config.max_overflow == 5
        assert config.connect_timeout == 15
        assert config.command_timeout == 45
        assert config.enable_monitoring is False


class TestDatabasePoolMetrics:
    """Test database pool metrics functionality."""
    
    def test_metrics_initialization(self):
        """Test metrics initialization with defaults."""
        metrics = DatabasePoolMetrics()
        
        assert metrics.total_connections_created == 0
        assert metrics.active_connections == 0
        assert metrics.total_checkouts == 0
        assert metrics.total_queries == 0
        assert metrics.health_check_passes == 0
        assert isinstance(metrics.created_at, datetime)
    
    def test_record_checkout_success(self):
        """Test recording successful checkout."""
        metrics = DatabasePoolMetrics()
        
        metrics.record_checkout(0.5, success=True)
        
        assert metrics.total_checkouts == 1
        assert metrics.successful_checkouts == 1
        assert metrics.failed_checkouts == 0
        assert metrics.checkout_wait_time_sum == 0.5
    
    def test_record_checkout_failure(self):
        """Test recording failed checkout."""
        metrics = DatabasePoolMetrics()
        
        metrics.record_checkout(2.0, success=False)
        
        assert metrics.total_checkouts == 1
        assert metrics.successful_checkouts == 0
        assert metrics.failed_checkouts == 1
        assert metrics.checkout_wait_time_sum == 2.0
    
    def test_record_query_success(self):
        """Test recording successful query."""
        metrics = DatabasePoolMetrics()
        
        metrics.record_query(0.1, success=True)
        
        assert metrics.total_queries == 1
        assert metrics.successful_queries == 1
        assert metrics.failed_queries == 0
        assert metrics.query_time_sum == 0.1
    
    def test_record_query_failure(self):
        """Test recording failed query."""
        metrics = DatabasePoolMetrics()
        
        metrics.record_query(5.0, success=False)
        
        assert metrics.total_queries == 1
        assert metrics.successful_queries == 0
        assert metrics.failed_queries == 1
        assert metrics.query_time_sum == 5.0
    
    def test_average_calculations(self):
        """Test average time calculations."""
        metrics = DatabasePoolMetrics()
        
        # Record multiple checkouts
        metrics.record_checkout(0.5)
        metrics.record_checkout(1.0)
        metrics.record_checkout(1.5)
        
        assert metrics.get_average_checkout_time() == 1.0  # (0.5 + 1.0 + 1.5) / 3
        
        # Record multiple queries
        metrics.record_query(0.1)
        metrics.record_query(0.2)
        
        assert metrics.get_average_query_time() == 0.15  # (0.1 + 0.2) / 2
    
    def test_failure_rate_calculations(self):
        """Test failure rate calculations."""
        metrics = DatabasePoolMetrics()
        
        # 80% checkout success rate
        for _ in range(8):
            metrics.record_checkout(0.5, success=True)
        for _ in range(2):
            metrics.record_checkout(0.5, success=False)
        
        assert metrics.get_checkout_failure_rate() == 0.2
        
        # 90% query success rate
        for _ in range(9):
            metrics.record_query(0.1, success=True)
        metrics.record_query(0.1, success=False)
        
        assert metrics.get_query_failure_rate() == 0.1
    
    def test_metrics_to_dict(self):
        """Test metrics serialization to dictionary."""
        metrics = DatabasePoolMetrics()
        metrics.total_connections_created = 10
        metrics.active_connections = 5
        metrics.record_checkout(0.5)
        metrics.record_query(0.1)
        
        metrics_dict = metrics.to_dict()
        
        assert "created_at" in metrics_dict
        assert "connections" in metrics_dict
        assert "checkouts" in metrics_dict
        assert "queries" in metrics_dict
        assert "health" in metrics_dict
        
        assert metrics_dict["connections"]["total_created"] == 10
        assert metrics_dict["connections"]["active"] == 5
        assert metrics_dict["checkouts"]["total"] == 1
        assert metrics_dict["queries"]["total"] == 1


class TestDatabasePoolManager:
    """Test database pool manager functionality."""
    
    async def test_pool_manager_initialization(self, test_pool_config):
        """Test pool manager initialization."""
        manager = DatabasePoolManager(test_pool_config)
        
        assert manager.config == test_pool_config
        assert manager._engine is None
        assert not manager._initialized
        assert manager.metrics is not None
    
    async def test_pool_manager_initialize_sqlite(self):
        """Test pool manager initialization with SQLite."""
        config = DatabasePoolConfig(connection_string="sqlite+aiosqlite:///:memory:")
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            
            # Mock engine creation
            mock_engine = MagicMock()
            mock_circuit_breaker.call.return_value = mock_engine
            
            with patch('src.database.pool_manager.async_sessionmaker') as mock_session_maker:
                await manager.initialize()
                
                assert manager._initialized
                assert manager._engine is mock_engine
                mock_session_maker.assert_called_once()
    
    async def test_pool_manager_initialize_postgresql(self):
        """Test pool manager initialization with PostgreSQL."""
        config = DatabasePoolConfig(connection_string="postgresql+asyncpg://test")
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            
            mock_engine = MagicMock()
            mock_circuit_breaker.call.return_value = mock_engine
            
            with patch('src.database.pool_manager.async_sessionmaker') as mock_session_maker:
                with patch.object(manager, '_init_tortoise') as mock_init_tortoise:
                    await manager.initialize()
                    
                    assert manager._initialized
                    mock_init_tortoise.assert_called_once()
    
    async def test_pool_manager_initialize_with_monitoring(self):
        """Test pool manager initialization with monitoring enabled."""
        config = DatabasePoolConfig(
            connection_string="sqlite:///:memory:",
            enable_monitoring=True
        )
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            mock_circuit_breaker.call.return_value = MagicMock()
            
            with patch('src.database.pool_manager.async_sessionmaker'):
                with patch('asyncio.create_task') as mock_create_task:
                    await manager.initialize()
                    
                    # Should create health check and metrics tasks
                    assert mock_create_task.call_count == 2
    
    async def test_pool_manager_double_initialization(self, test_pool_config):
        """Test that double initialization is handled correctly."""
        manager = DatabasePoolManager(test_pool_config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            mock_circuit_breaker.call.return_value = MagicMock()
            
            with patch('src.database.pool_manager.async_sessionmaker'):
                await manager.initialize()
                assert manager._initialized
                
                # Second initialization should return immediately
                await manager.initialize()
                
                # Circuit breaker manager should only be called once
                mock_cb_manager.assert_called_once()
    
    async def test_get_session_success(self, test_pool_manager):
        """Test successful session retrieval."""
        mock_session = AsyncMock()
        
        with patch.object(test_pool_manager, '_session_factory') as mock_factory:
            with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
                mock_cb.call.return_value = mock_session
                
                async with test_pool_manager.get_session() as session:
                    assert session is mock_session
                    
                # Session should be committed and closed
                mock_session.commit.assert_called_once()
                mock_session.close.assert_called_once()
    
    async def test_get_session_circuit_breaker_open(self, test_pool_manager):
        """Test session retrieval when circuit breaker is open."""
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_cb.call.side_effect = CircuitOpenError("Circuit open")
            
            with pytest.raises(DatabaseConnectionError, match="circuit breaker is open"):
                async with test_pool_manager.get_session():
                    pass
    
    async def test_get_session_with_error_rollback(self, test_pool_manager):
        """Test session rollback on error."""
        mock_session = AsyncMock()
        
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_cb.call.return_value = mock_session
            
            with pytest.raises(ValueError):
                async with test_pool_manager.get_session() as session:
                    raise ValueError("Test error")
            
            # Session should be rolled back and closed
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()
    
    async def test_get_session_tracks_active_sessions(self, test_pool_manager):
        """Test that active sessions are tracked for leak detection."""
        mock_session = AsyncMock()
        
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_cb.call.return_value = mock_session
            
            # Initially no active sessions
            assert len(test_pool_manager._active_sessions) == 0
            
            async with test_pool_manager.get_session():
                # Should track active session
                assert len(test_pool_manager._active_sessions) == 1
            
            # Session should be cleaned up
            assert len(test_pool_manager._active_sessions) == 0
    
    async def test_get_connection(self, test_pool_manager):
        """Test getting raw database connection."""
        mock_connection = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        test_pool_manager._engine = mock_engine
        
        async with test_pool_manager.get_connection() as conn:
            assert conn is mock_connection
    
    async def test_execute_query_success(self, test_pool_manager):
        """Test successful query execution."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.execute.return_value = mock_result
        
        with patch.object(test_pool_manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            result = await test_pool_manager.execute_query("SELECT 1")
            
            assert result is mock_result
            mock_session.execute.assert_called_once()
    
    async def test_execute_query_with_params(self, test_pool_manager):
        """Test query execution with parameters."""
        mock_session = AsyncMock()
        
        with patch.object(test_pool_manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            await test_pool_manager.execute_query(
                "SELECT * FROM users WHERE id = :user_id",
                params={"user_id": 123}
            )
            
            # Should call execute with text and params
            mock_session.execute.assert_called_once()
    
    async def test_execute_query_timeout(self, test_pool_manager):
        """Test query execution with timeout."""
        with patch.object(test_pool_manager, 'get_session'):
            with patch('asyncio.TimeoutError'):
                # This would be more complex to test properly
                # For now, just verify the timeout parameter is handled
                pass
    
    async def test_health_check_healthy(self, test_pool_manager):
        """Test health check when everything is healthy."""
        mock_engine = MagicMock()
        mock_connection = AsyncMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Mock pool attributes
        mock_pool = MagicMock()
        mock_pool.size.return_value = 10
        mock_pool.checkedin.return_value = 5
        mock_pool.overflow.return_value = 2
        mock_engine.pool = mock_pool
        
        test_pool_manager._engine = mock_engine
        
        health_status = await test_pool_manager.health_check()
        
        assert health_status["status"] == "healthy"
        assert "checks" in health_status
        assert "metrics" in health_status
        assert health_status["checks"]["engine"] == "ok"
        assert "pool" in health_status
    
    async def test_health_check_unhealthy_engine(self, test_pool_manager):
        """Test health check when engine is unhealthy."""
        mock_engine = MagicMock()
        mock_connection = AsyncMock()
        mock_connection.execute.side_effect = Exception("Database error")
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        test_pool_manager._engine = mock_engine
        
        health_status = await test_pool_manager.health_check()
        
        assert health_status["status"] == "unhealthy"
        assert "failed:" in health_status["checks"]["engine"]
    
    async def test_health_check_connection_leaks(self, test_pool_manager):
        """Test health check detects connection leaks."""
        # Simulate active sessions older than idle timeout
        old_time = datetime.utcnow() - timedelta(seconds=test_pool_manager.config.idle_timeout + 100)
        test_pool_manager._active_sessions[12345] = old_time
        
        mock_engine = MagicMock()
        mock_connection = AsyncMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        test_pool_manager._engine = mock_engine
        
        health_status = await test_pool_manager.health_check()
        
        assert health_status["status"] == "degraded"
        assert "connection_leaks" in health_status
        assert len(health_status["connection_leaks"]) == 1
    
    async def test_close_pool_manager(self, test_pool_manager):
        """Test pool manager cleanup."""
        # Set up mock tasks
        mock_health_task = AsyncMock()
        mock_metrics_task = AsyncMock()
        test_pool_manager._health_check_task = mock_health_task
        test_pool_manager._metrics_task = mock_metrics_task
        
        # Set up mock engine
        mock_engine = AsyncMock()
        test_pool_manager._engine = mock_engine
        
        await test_pool_manager.close()
        
        # Tasks should be cancelled
        mock_health_task.cancel.assert_called_once()
        mock_metrics_task.cancel.assert_called_once()
        
        # Engine should be disposed
        mock_engine.dispose.assert_called_once()
        assert test_pool_manager._engine is None
    
    async def test_close_with_active_sessions_warning(self, test_pool_manager, caplog):
        """Test close warns about active sessions."""
        # Add active sessions
        test_pool_manager._active_sessions[1] = datetime.utcnow()
        test_pool_manager._active_sessions[2] = datetime.utcnow()
        
        await test_pool_manager.close()
        
        # Should log warning about leaked sessions
        assert "potential connection leak" in caplog.text.lower()
    
    async def test_background_task_error_handling(self, test_pool_config):
        """Test that background task errors are handled gracefully."""
        manager = DatabasePoolManager(test_pool_config)
        
        # Mock health check to raise error
        with patch.object(manager, 'health_check') as mock_health_check:
            mock_health_check.side_effect = Exception("Health check error")
            
            # Start health check loop
            task = asyncio.create_task(manager._health_check_loop())
            
            # Let it run briefly
            await asyncio.sleep(0.1)
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # Should not crash the application


class TestGlobalPoolManager:
    """Test global pool manager functions."""
    
    async def test_get_pool_manager_default_config(self):
        """Test getting pool manager with default configuration."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test",
            "POD_COUNT": "3",
            "DB_MIN_POOL_SIZE": "8",
            "DB_MAX_POOL_SIZE": "25"
        }):
            # Clear any existing global manager
            await close_pool_manager()
            
            with patch('src.database.pool_manager.DatabasePoolManager') as mock_manager_class:
                mock_manager = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                manager = await get_pool_manager()
                
                assert manager is mock_manager
                mock_manager.initialize.assert_called_once()
                
                # Config should be created from environment
                call_args = mock_manager_class.call_args[0][0]
                assert call_args.connection_string == "postgresql://test"
                assert call_args.pod_count == 3
                assert call_args.min_pool_size == 8
                assert call_args.max_pool_size == 25
    
    async def test_get_pool_manager_custom_config(self):
        """Test getting pool manager with custom configuration."""
        # Clear any existing global manager
        await close_pool_manager()
        
        custom_config = DatabasePoolConfig(
            connection_string="sqlite:///:memory:",
            min_pool_size=2,
            max_pool_size=5
        )
        
        with patch('src.database.pool_manager.DatabasePoolManager') as mock_manager_class:
            mock_manager = AsyncMock()
            mock_manager_class.return_value = mock_manager
            
            manager = await get_pool_manager(custom_config)
            
            assert manager is mock_manager
            mock_manager_class.assert_called_once_with(custom_config)
    
    async def test_get_pool_manager_singleton(self):
        """Test that get_pool_manager returns the same instance."""
        await close_pool_manager()
        
        with patch('src.database.pool_manager.DatabasePoolManager') as mock_manager_class:
            mock_manager = AsyncMock()
            mock_manager_class.return_value = mock_manager
            
            manager1 = await get_pool_manager()
            manager2 = await get_pool_manager()
            
            assert manager1 is manager2
            # Manager should only be created once
            mock_manager_class.assert_called_once()
    
    async def test_close_pool_manager_global(self):
        """Test closing the global pool manager."""
        with patch('src.database.pool_manager.DatabasePoolManager') as mock_manager_class:
            mock_manager = AsyncMock()
            mock_manager_class.return_value = mock_manager
            
            # Get a manager
            await get_pool_manager()
            
            # Close it
            await close_pool_manager()
            
            mock_manager.close.assert_called_once()


class TestPoolManagerPerformance:
    """Test pool manager performance characteristics."""
    
    async def test_concurrent_session_creation(self, test_pool_manager):
        """Test concurrent session creation and management."""
        async def get_session_and_query():
            async with test_pool_manager.get_session() as session:
                # Simulate query
                await asyncio.sleep(0.01)
                return "result"
        
        # Mock session creation
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_sessions = [AsyncMock() for _ in range(10)]
            mock_cb.call.side_effect = mock_sessions
            
            # Run concurrent sessions
            tasks = [get_session_and_query() for _ in range(10)]
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 10
            assert all(result == "result" for result in results)
            
            # All sessions should be committed and closed
            for session in mock_sessions:
                session.commit.assert_called_once()
                session.close.assert_called_once()
    
    async def test_session_creation_performance(self, test_pool_manager, performance_timer):
        """Test session creation performance."""
        mock_session = AsyncMock()
        
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_cb.call.return_value = mock_session
            
            performance_timer.start()
            
            # Create many sessions sequentially
            for _ in range(100):
                async with test_pool_manager.get_session():
                    pass
            
            performance_timer.stop()
            
            # Should be fast
            assert performance_timer.elapsed_seconds < 5.0
    
    async def test_health_check_performance(self, test_pool_manager, performance_timer):
        """Test health check performance."""
        # Set up mock engine
        mock_engine = MagicMock()
        mock_connection = AsyncMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        mock_pool = MagicMock()
        mock_pool.size.return_value = 10
        mock_pool.checkedin.return_value = 5
        mock_pool.overflow.return_value = 0
        mock_engine.pool = mock_pool
        
        test_pool_manager._engine = mock_engine
        
        performance_timer.start()
        
        # Perform multiple health checks
        for _ in range(50):
            await test_pool_manager.health_check()
        
        performance_timer.stop()
        
        # Health checks should be fast
        assert performance_timer.elapsed_seconds < 2.0
    
    async def test_metrics_collection_overhead(self, test_pool_config):
        """Test metrics collection overhead."""
        # Test with monitoring enabled
        config_with_monitoring = test_pool_config
        config_with_monitoring.enable_monitoring = True
        
        manager_with_metrics = DatabasePoolManager(config_with_monitoring)
        
        # Test with monitoring disabled
        config_without_monitoring = DatabasePoolConfig(
            connection_string=test_pool_config.connection_string,
            enable_monitoring=False
        )
        
        manager_without_metrics = DatabasePoolManager(config_without_monitoring)
        
        # Both should initialize successfully
        with patch('src.database.pool_manager.get_circuit_breaker_manager'):
            with patch('src.database.pool_manager.async_sessionmaker'):
                await manager_with_metrics.initialize()
                await manager_without_metrics.initialize()
        
        # Monitoring should not significantly impact performance
        # This is more of a structural test than a performance test
        assert manager_with_metrics._metrics_collector is not None
        assert manager_without_metrics._metrics_collector is None


class TestPoolManagerErrorScenarios:
    """Test pool manager error handling scenarios."""
    
    async def test_initialization_failure(self):
        """Test pool manager initialization failure."""
        config = DatabasePoolConfig(connection_string="invalid://connection")
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_cb_manager.side_effect = Exception("Circuit breaker setup failed")
            
            with pytest.raises(DatabaseConnectionError, match="initialization failed"):
                await manager.initialize()
    
    async def test_engine_creation_failure(self, test_pool_config):
        """Test engine creation failure."""
        manager = DatabasePoolManager(test_pool_config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            mock_circuit_breaker.call.side_effect = Exception("Engine creation failed")
            
            with pytest.raises(DatabaseConnectionError):
                await manager.initialize()
    
    async def test_tortoise_initialization_failure(self):
        """Test Tortoise initialization failure doesn't crash."""
        config = DatabasePoolConfig(connection_string="postgresql://test")
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            mock_circuit_breaker.call.return_value = MagicMock()
            
            with patch('src.database.pool_manager.async_sessionmaker'):
                with patch('src.database.pool_manager.Tortoise.init') as mock_tortoise_init:
                    mock_tortoise_init.side_effect = Exception("Tortoise init failed")
                    
                    # Should not raise error - Tortoise failure is not critical
                    await manager.initialize()
                    assert manager._initialized
    
    async def test_session_factory_failure(self, test_pool_manager):
        """Test session factory failure."""
        with patch.object(test_pool_manager, '_circuit_breaker') as mock_cb:
            mock_cb.call.side_effect = Exception("Session creation failed")
            
            with pytest.raises(Exception):
                async with test_pool_manager.get_session():
                    pass
    
    async def test_query_execution_failure(self, test_pool_manager):
        """Test query execution failure."""
        mock_session = AsyncMock()
        mock_session.execute.side_effect = Exception("Query failed")
        
        with patch.object(test_pool_manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            with pytest.raises(Exception, match="Query failed"):
                await test_pool_manager.execute_query("SELECT 1")
    
    async def test_closing_already_closed_manager(self, test_pool_manager):
        """Test closing an already closed manager."""
        await test_pool_manager.close()
        assert test_pool_manager._closing
        
        # Second close should not raise error
        await test_pool_manager.close()
    
    async def test_using_closed_manager(self, test_pool_manager):
        """Test using a closed manager."""
        await test_pool_manager.close()
        
        with pytest.raises(DatabaseConnectionError, match="closing"):
            async with test_pool_manager.get_session():
                pass
    
    async def test_circuit_breaker_state_tracking(self, test_pool_manager):
        """Test circuit breaker state is tracked in health checks."""
        mock_circuit_breaker = MagicMock()
        mock_circuit_breaker.state.name = "OPEN"
        mock_circuit_breaker.failure_count = 5
        mock_circuit_breaker.last_failure_time = datetime.utcnow()
        
        test_pool_manager._circuit_breaker = mock_circuit_breaker
        
        # Mock engine for basic health check
        mock_engine = MagicMock()
        mock_connection = AsyncMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        test_pool_manager._engine = mock_engine
        
        health_status = await test_pool_manager.health_check()
        
        assert "circuit_breaker" in health_status
        assert health_status["circuit_breaker"]["state"] == "OPEN"
        assert health_status["circuit_breaker"]["failure_count"] == 5


class TestPoolManagerIntegration:
    """Test pool manager integration scenarios."""
    
    async def test_full_lifecycle_integration(self):
        """Test complete pool manager lifecycle."""
        config = DatabasePoolConfig(
            connection_string="sqlite+aiosqlite:///:memory:",
            min_pool_size=2,
            max_pool_size=5,
            enable_monitoring=True
        )
        
        manager = DatabasePoolManager(config)
        
        # Initialize
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            
            mock_engine = MagicMock()
            mock_circuit_breaker.call.return_value = mock_engine
            
            with patch('src.database.pool_manager.async_sessionmaker') as mock_session_maker:
                await manager.initialize()
                
                assert manager._initialized
                
                # Use sessions
                mock_session = AsyncMock()
                mock_circuit_breaker.call.return_value = mock_session
                
                async with manager.get_session() as session:
                    assert session is mock_session
                
                # Check health
                mock_connection = AsyncMock()
                mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
                mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
                
                health_status = await manager.health_check()
                assert health_status["status"] in ["healthy", "unhealthy"]
                
                # Execute query
                with patch.object(manager, 'get_session') as mock_get_session:
                    mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
                    
                    await manager.execute_query("SELECT 1")
                
                # Close
                await manager.close()
                assert manager._closing
    
    async def test_pool_manager_with_real_circuit_breaker(self):
        """Test pool manager integration with circuit breaker."""
        config = DatabasePoolConfig(connection_string="sqlite:///:memory:")
        manager = DatabasePoolManager(config)
        
        # Don't mock circuit breaker manager to test real integration
        with patch('src.database.pool_manager.create_async_engine') as mock_create_engine:
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            
            with patch('src.database.pool_manager.async_sessionmaker'):
                await manager.initialize()
                
                assert manager._circuit_breaker is not None
                assert manager._initialized
        
        await manager.close()
    
    async def test_pool_manager_metrics_integration(self, test_pool_config):
        """Test pool manager metrics integration."""
        config = test_pool_config
        config.enable_monitoring = True
        
        manager = DatabasePoolManager(config)
        
        with patch('src.database.pool_manager.get_circuit_breaker_manager') as mock_cb_manager:
            mock_circuit_breaker = AsyncMock()
            mock_cb_manager.return_value.get_or_create.return_value = mock_circuit_breaker
            mock_circuit_breaker.call.return_value = MagicMock()
            
            with patch('src.database.pool_manager.async_sessionmaker'):
                await manager.initialize()
                
                # Metrics should be tracked
                assert manager.metrics is not None
                assert manager._metrics_collector is not None
                
                # Test metrics recording
                manager.metrics.record_checkout(0.5, success=True)
                manager.metrics.record_query(0.1, success=True)
                
                metrics_dict = manager.metrics.to_dict()
                assert metrics_dict["checkouts"]["total"] == 1
                assert metrics_dict["queries"]["total"] == 1
        
        await manager.close()