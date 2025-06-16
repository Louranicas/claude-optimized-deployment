"""Comprehensive tests for database monitoring.

Tests cover:
- Monitor configuration and initialization
- Health check monitoring and alerting
- Metrics collection and thresholds
- Connection leak detection
- Performance monitoring
- Alert management and callbacks
- Global monitor management
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock, call
from datetime import datetime, timedelta

from src.database.monitoring import (
    DatabaseMonitorConfig,
    DatabaseAlert,
    DatabaseMonitor,
    get_database_monitor,
    start_database_monitoring,
    stop_database_monitoring
)
from src.database.pool_manager import DatabasePoolManager, DatabasePoolMetrics
from src.monitoring.metrics import MetricsCollector


class TestDatabaseMonitorConfig:
    """Test database monitor configuration."""
    
    def test_config_defaults(self):
        """Test configuration default values."""
        config = DatabaseMonitorConfig()
        
        # Monitoring intervals
        assert config.health_check_interval == 60
        assert config.metrics_collection_interval == 30
        assert config.leak_detection_interval == 300
        
        # Alert thresholds
        assert config.max_checkout_time_threshold == 5.0
        assert config.max_query_time_threshold == 10.0
        assert config.connection_failure_rate_threshold == 0.1
        assert config.query_failure_rate_threshold == 0.05
        
        # Connection pool thresholds
        assert config.high_pool_usage_threshold == 0.8
        assert config.connection_leak_threshold == 5
        
        # Health check settings
        assert config.consecutive_failures_for_alert == 3
        assert config.alert_cooldown_minutes == 15
        
        # Performance monitoring
        assert config.slow_query_threshold == 5.0
        assert config.collect_slow_queries is True
        assert config.max_slow_queries_tracked == 100
    
    def test_config_custom_values(self):
        """Test configuration with custom values."""
        config = DatabaseMonitorConfig(
            health_check_interval=30,
            metrics_collection_interval=15,
            max_checkout_time_threshold=3.0,
            connection_failure_rate_threshold=0.05,
            consecutive_failures_for_alert=5,
            alert_cooldown_minutes=30
        )
        
        assert config.health_check_interval == 30
        assert config.metrics_collection_interval == 15
        assert config.max_checkout_time_threshold == 3.0
        assert config.connection_failure_rate_threshold == 0.05
        assert config.consecutive_failures_for_alert == 5
        assert config.alert_cooldown_minutes == 30


class TestDatabaseAlert:
    """Test database alert functionality."""
    
    def test_alert_creation(self):
        """Test alert creation with required fields."""
        alert = DatabaseAlert(
            alert_type="test_alert",
            severity="warning",
            message="Test alert message",
            timestamp=datetime.utcnow()
        )
        
        assert alert.alert_type == "test_alert"
        assert alert.severity == "warning"
        assert alert.message == "Test alert message"
        assert isinstance(alert.timestamp, datetime)
        assert alert.metrics == {}
        assert alert.resolved is False
        assert alert.resolved_at is None
    
    def test_alert_with_metrics(self):
        """Test alert creation with metrics."""
        metrics = {"connection_count": 10, "failure_rate": 0.15}
        alert = DatabaseAlert(
            alert_type="high_failure_rate",
            severity="error",
            message="High failure rate detected",
            timestamp=datetime.utcnow(),
            metrics=metrics
        )
        
        assert alert.metrics == metrics
    
    def test_alert_resolution(self):
        """Test alert resolution."""
        alert = DatabaseAlert(
            alert_type="test_alert",
            severity="warning",
            message="Test message",
            timestamp=datetime.utcnow()
        )
        
        # Resolve alert
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        
        assert alert.resolved is True
        assert isinstance(alert.resolved_at, datetime)


class TestDatabaseMonitor:
    """Test database monitor functionality."""
    
    @pytest.fixture
    def monitor_config(self):
        """Create test monitor configuration."""
        return DatabaseMonitorConfig(
            health_check_interval=1,  # Fast for testing
            metrics_collection_interval=1,
            leak_detection_interval=2,
            consecutive_failures_for_alert=2,
            alert_cooldown_minutes=1
        )
    
    @pytest.fixture
    def mock_pool_manager(self):
        """Create mock pool manager."""
        manager = MagicMock(spec=DatabasePoolManager)
        
        # Mock metrics
        metrics = MagicMock(spec=DatabasePoolMetrics)
        metrics.active_connections = 5
        metrics.idle_connections = 3
        metrics.overflow_connections = 0
        metrics.total_connections_created = 10
        metrics.total_checkouts = 100
        metrics.successful_checkouts = 95
        metrics.failed_checkouts = 5
        metrics.total_queries = 200
        metrics.successful_queries = 190
        metrics.failed_queries = 10
        metrics.health_check_passes = 50
        metrics.health_check_failures = 2
        metrics.connections_recycled = 5
        metrics.connections_invalidated = 1
        metrics.connection_timeouts = 0
        metrics.get_average_checkout_time.return_value = 0.5
        metrics.get_checkout_failure_rate.return_value = 0.05
        metrics.get_average_query_time.return_value = 0.2
        metrics.get_query_failure_rate.return_value = 0.05
        metrics.to_dict.return_value = {
            "connections": {"active": 5, "idle": 3},
            "checkouts": {"total": 100, "successful": 95},
            "queries": {"total": 200, "successful": 190}
        }
        
        manager.metrics = metrics
        manager.config = MagicMock()
        manager.config.max_pool_size = 20
        
        # Mock health check
        manager.health_check = AsyncMock(return_value={
            "status": "healthy",
            "checks": {"engine": "ok", "pool": "ok"},
            "pool": {"active": 5, "idle": 3, "overflow": 0}
        })
        
        return manager
    
    @pytest.fixture
    def database_monitor(self, monitor_config):
        """Create database monitor instance."""
        return DatabaseMonitor(monitor_config)
    
    def test_monitor_initialization(self, monitor_config):
        """Test monitor initialization."""
        monitor = DatabaseMonitor(monitor_config)
        
        assert monitor.config == monitor_config
        assert monitor.pool_manager is None
        assert isinstance(monitor.metrics_collector, MetricsCollector)
        assert monitor.is_monitoring is False
        assert monitor.monitor_tasks == []
        assert monitor.active_alerts == {}
        assert monitor.alert_history == []
        assert monitor.last_alert_times == {}
        assert monitor.slow_queries == []
        assert monitor.connection_leak_count == 0
        assert monitor.last_health_check is None
        assert monitor.consecutive_health_failures == 0
        assert monitor.alert_callbacks == []
    
    def test_monitor_default_config(self):
        """Test monitor with default configuration."""
        monitor = DatabaseMonitor()
        
        assert isinstance(monitor.config, DatabaseMonitorConfig)
        assert monitor.config.health_check_interval == 60
    
    async def test_start_monitoring(self, database_monitor, mock_pool_manager):
        """Test starting monitoring."""
        with patch('asyncio.create_task') as mock_create_task:
            mock_tasks = [MagicMock() for _ in range(4)]
            mock_create_task.side_effect = mock_tasks
            
            await database_monitor.start_monitoring(mock_pool_manager)
            
            assert database_monitor.is_monitoring is True
            assert database_monitor.pool_manager == mock_pool_manager
            assert len(database_monitor.monitor_tasks) == 4
            assert mock_create_task.call_count == 4
    
    async def test_start_monitoring_already_running(self, database_monitor, mock_pool_manager):
        """Test starting monitoring when already running."""
        database_monitor.is_monitoring = True
        
        with patch('asyncio.create_task') as mock_create_task:
            await database_monitor.start_monitoring(mock_pool_manager)
            
            # Should not create new tasks
            mock_create_task.assert_not_called()
    
    async def test_start_monitoring_with_global_pool(self, database_monitor):
        """Test starting monitoring with global pool manager."""
        with patch('src.database.monitoring.get_pool_manager') as mock_get_pool:
            mock_pool = MagicMock()
            mock_get_pool.return_value = mock_pool
            
            with patch('asyncio.create_task'):
                await database_monitor.start_monitoring()
                
                assert database_monitor.pool_manager == mock_pool
                mock_get_pool.assert_called_once()
    
    async def test_stop_monitoring(self, database_monitor):
        """Test stopping monitoring."""
        # Set up monitoring state
        database_monitor.is_monitoring = True
        mock_tasks = [AsyncMock() for _ in range(4)]
        database_monitor.monitor_tasks = mock_tasks
        
        with patch('asyncio.gather') as mock_gather:
            mock_gather.return_value = None
            
            await database_monitor.stop_monitoring()
            
            assert database_monitor.is_monitoring is False
            assert database_monitor.monitor_tasks == []
            
            # Verify tasks were cancelled
            for task in mock_tasks:
                task.cancel.assert_called_once()
            
            mock_gather.assert_called_once()
    
    async def test_stop_monitoring_not_running(self, database_monitor):
        """Test stopping monitoring when not running."""
        assert database_monitor.is_monitoring is False
        
        # Should not raise error
        await database_monitor.stop_monitoring()
    
    def test_add_alert_callback(self, database_monitor):
        """Test adding alert callback."""
        callback = MagicMock()
        
        database_monitor.add_alert_callback(callback)
        
        assert callback in database_monitor.alert_callbacks
    
    async def test_health_check_loop_success(self, database_monitor, mock_pool_manager):
        """Test health check loop with successful checks."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        # Mock successful health check
        mock_pool_manager.health_check.return_value = {
            "status": "healthy",
            "checks": {"engine": "ok"}
        }
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            
            await database_monitor._health_check_loop()
            
            assert database_monitor.consecutive_health_failures == 0
            assert database_monitor.last_health_check is not None
            mock_pool_manager.health_check.assert_called_once()
    
    async def test_health_check_loop_failure(self, database_monitor, mock_pool_manager):
        """Test health check loop with failures."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        # Mock failed health check
        mock_pool_manager.health_check.return_value = {
            "status": "unhealthy",
            "checks": {"engine": "failed: connection error"}
        }
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, None, asyncio.CancelledError()]
            
            await database_monitor._health_check_loop()
            
            assert database_monitor.consecutive_health_failures == 2
            assert "database_unhealthy" in database_monitor.active_alerts
    
    async def test_health_check_connection_leaks(self, database_monitor, mock_pool_manager):
        """Test health check detecting connection leaks."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        # Mock health check with connection leaks
        mock_pool_manager.health_check.return_value = {
            "status": "degraded",
            "connection_leaks": [
                {"session_id": 123, "age_seconds": 3600},
                {"session_id": 456, "age_seconds": 1800}
            ]
        }
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            
            await database_monitor._health_check_loop()
            
            assert "connection_leaks" in database_monitor.active_alerts
            alert = database_monitor.active_alerts["connection_leaks"]
            assert "2 potential connection leaks" in alert.message
    
    async def test_metrics_collection_loop(self, database_monitor, mock_pool_manager):
        """Test metrics collection loop."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            
            with patch.object(database_monitor.metrics_collector, 'gauge') as mock_gauge:
                await database_monitor._metrics_collection_loop()
                
                # Verify metrics were collected
                mock_gauge.assert_called()
                gauge_calls = [call[0] for call in mock_gauge.call_args_list]
                
                expected_metrics = [
                    "db_active_connections",
                    "db_idle_connections",
                    "db_total_checkouts",
                    "db_total_queries",
                    "db_average_checkout_time",
                    "db_average_query_time"
                ]
                
                for metric in expected_metrics:
                    assert any(metric in call for call in gauge_calls)
    
    async def test_leak_detection_loop(self, database_monitor, mock_pool_manager):
        """Test connection leak detection loop."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        # Mock health check with many leaks
        leak_data = [{"session_id": i, "age_seconds": 3600} for i in range(10)]
        mock_pool_manager.health_check.return_value = {
            "connection_leaks": leak_data
        }
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            
            await database_monitor._leak_detection_loop()
            
            assert database_monitor.connection_leak_count == 10
            assert "connection_leaks" in database_monitor.active_alerts
            
            alert = database_monitor.active_alerts["connection_leaks"]
            assert alert.severity == "error"
            assert "10 connection leaks" in alert.message
    
    async def test_performance_monitoring_loop(self, database_monitor, mock_pool_manager):
        """Test performance monitoring loop."""
        database_monitor.pool_manager = mock_pool_manager
        database_monitor.is_monitoring = True
        
        # Mock slow query performance
        mock_pool_manager.metrics.get_average_query_time.return_value = 6.0  # Above threshold
        mock_pool_manager.metrics.get_average_checkout_time.return_value = 6.0  # Above threshold
        
        with patch('asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            
            await database_monitor._performance_monitoring_loop()
            
            assert "slow_queries" in database_monitor.active_alerts
            assert "slow_checkouts" in database_monitor.active_alerts
            
            slow_query_alert = database_monitor.active_alerts["slow_queries"]
            assert "6.00s" in slow_query_alert.message
            
            slow_checkout_alert = database_monitor.active_alerts["slow_checkouts"]
            assert "6.00s" in slow_checkout_alert.message
    
    async def test_metrics_threshold_checking(self, database_monitor, mock_pool_manager):
        """Test metrics threshold checking."""
        database_monitor.pool_manager = mock_pool_manager
        
        # Mock high failure rates
        mock_pool_manager.metrics.get_checkout_failure_rate.return_value = 0.15  # Above 0.1 threshold
        mock_pool_manager.metrics.get_query_failure_rate.return_value = 0.08    # Above 0.05 threshold
        
        await database_monitor._check_metrics_thresholds(mock_pool_manager.metrics)
        
        assert "high_checkout_failure_rate" in database_monitor.active_alerts
        assert "high_query_failure_rate" in database_monitor.active_alerts
        
        checkout_alert = database_monitor.active_alerts["high_checkout_failure_rate"]
        assert checkout_alert.severity == "error"
        assert "15.00%" in checkout_alert.message
        
        query_alert = database_monitor.active_alerts["high_query_failure_rate"]
        assert query_alert.severity == "error"
        assert "8.00%" in query_alert.message
    
    async def test_high_pool_usage_alert(self, database_monitor, mock_pool_manager):
        """Test high pool usage alert."""
        database_monitor.pool_manager = mock_pool_manager
        
        # Mock high pool usage (17 out of 20 connections = 85%)
        mock_pool_manager.metrics.active_connections = 15
        mock_pool_manager.metrics.idle_connections = 2
        
        await database_monitor._check_metrics_thresholds(mock_pool_manager.metrics)
        
        assert "high_pool_usage" in database_monitor.active_alerts
        
        alert = database_monitor.active_alerts["high_pool_usage"]
        assert alert.severity == "warning"
        assert "85.0%" in alert.message
        assert "17/20" in alert.message
    
    async def test_alert_cooldown(self, database_monitor):
        """Test alert cooldown mechanism."""
        # Trigger initial alert
        await database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="warning",
            message="First alert"
        )
        
        assert "test_alert" in database_monitor.active_alerts
        assert len(database_monitor.alert_history) == 1
        
        # Try to trigger same alert immediately (should be blocked by cooldown)
        await database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="warning",
            message="Second alert"
        )
        
        # Should still only have one alert in history
        assert len(database_monitor.alert_history) == 1
        assert database_monitor.alert_history[0].message == "First alert"
    
    async def test_alert_callbacks(self, database_monitor):
        """Test alert callback notifications."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        
        database_monitor.add_alert_callback(callback1)
        database_monitor.add_alert_callback(callback2)
        
        await database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="error",
            message="Test message"
        )
        
        # Both callbacks should be called
        callback1.assert_called_once()
        callback2.assert_called_once()
        
        # Verify alert data
        alert = callback1.call_args[0][0]
        assert isinstance(alert, DatabaseAlert)
        assert alert.alert_type == "test_alert"
        assert alert.severity == "error"
        assert alert.message == "Test message"
    
    async def test_alert_callback_error_handling(self, database_monitor):
        """Test alert callback error handling."""
        failing_callback = MagicMock(side_effect=Exception("Callback error"))
        working_callback = MagicMock()
        
        database_monitor.add_alert_callback(failing_callback)
        database_monitor.add_alert_callback(working_callback)
        
        # Should not raise exception even if callback fails
        await database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="warning",
            message="Test message"
        )
        
        # Working callback should still be called
        working_callback.assert_called_once()
    
    async def test_resolve_alert(self, database_monitor):
        """Test alert resolution."""
        # Create an alert
        await database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="warning",
            message="Test message"
        )
        
        assert "test_alert" in database_monitor.active_alerts
        
        # Resolve the alert
        await database_monitor._resolve_alert("test_alert")
        
        assert "test_alert" not in database_monitor.active_alerts
        
        # Check alert history has resolved alert
        resolved_alert = database_monitor.alert_history[0]
        assert resolved_alert.resolved is True
        assert resolved_alert.resolved_at is not None
    
    async def test_resolve_nonexistent_alert(self, database_monitor):
        """Test resolving non-existent alert."""
        # Should not raise error
        await database_monitor._resolve_alert("nonexistent_alert")
    
    def test_get_status(self, database_monitor):
        """Test getting monitor status."""
        database_monitor.is_monitoring = True
        database_monitor.last_health_check = datetime.utcnow()
        database_monitor.consecutive_health_failures = 2
        database_monitor.connection_leak_count = 3
        
        # Add some alerts
        database_monitor.active_alerts["test1"] = MagicMock()
        database_monitor.active_alerts["test2"] = MagicMock()
        database_monitor.alert_history = [MagicMock() for _ in range(5)]
        
        status = database_monitor.get_status()
        
        assert status["monitoring_active"] is True
        assert status["consecutive_health_failures"] == 2
        assert status["active_alerts"] == 2
        assert status["total_alerts"] == 5
        assert status["connection_leak_count"] == 3
        assert "config" in status
        assert status["config"]["health_check_interval"] == database_monitor.config.health_check_interval
    
    def test_get_alerts_active_only(self, database_monitor):
        """Test getting active alerts only."""
        # Create some alerts
        alert1 = MagicMock()
        alert2 = MagicMock()
        database_monitor.active_alerts["alert1"] = alert1
        database_monitor.active_alerts["alert2"] = alert2
        database_monitor.alert_history = [alert1, alert2, MagicMock()]  # Third is resolved
        
        alerts = database_monitor.get_alerts(include_resolved=False)
        
        assert len(alerts) == 2
        assert alert1 in alerts
        assert alert2 in alerts
    
    def test_get_alerts_include_resolved(self, database_monitor):
        """Test getting all alerts including resolved."""
        # Create alerts
        database_monitor.alert_history = [MagicMock() for _ in range(3)]
        
        alerts = database_monitor.get_alerts(include_resolved=True)
        
        assert len(alerts) == 3
        assert alerts == database_monitor.alert_history
    
    def test_get_metrics_summary(self, database_monitor, mock_pool_manager):
        """Test getting metrics summary."""
        database_monitor.pool_manager = mock_pool_manager
        
        summary = database_monitor.get_metrics_summary()
        
        assert summary == mock_pool_manager.metrics.to_dict()
        mock_pool_manager.metrics.to_dict.assert_called_once()
    
    def test_get_metrics_summary_no_pool(self, database_monitor):
        """Test getting metrics summary with no pool manager."""
        summary = database_monitor.get_metrics_summary()
        
        assert summary == {}
    
    def test_alert_history_limit(self, database_monitor):
        """Test alert history size limiting."""
        # Fill history beyond limit
        database_monitor.alert_history = [MagicMock() for _ in range(1050)]
        
        # Trigger new alert
        asyncio.run(database_monitor._trigger_alert(
            alert_type="test_alert",
            severity="warning",
            message="Test message"
        ))
        
        # History should be limited to 800 + 1 new alert
        assert len(database_monitor.alert_history) == 801


class TestGlobalMonitorManagement:
    """Test global monitor management functions."""
    
    async def test_get_database_monitor_singleton(self):
        """Test that get_database_monitor returns singleton."""
        # Clear global state
        import src.database.monitoring
        src.database.monitoring._database_monitor = None
        
        monitor1 = await get_database_monitor()
        monitor2 = await get_database_monitor()
        
        assert monitor1 is monitor2
        assert isinstance(monitor1, DatabaseMonitor)
    
    async def test_get_database_monitor_with_config(self):
        """Test get_database_monitor with custom config."""
        # Clear global state
        import src.database.monitoring
        src.database.monitoring._database_monitor = None
        
        config = DatabaseMonitorConfig(health_check_interval=30)
        monitor = await get_database_monitor(config)
        
        assert monitor.config == config
        assert monitor.config.health_check_interval == 30
    
    async def test_start_database_monitoring(self):
        """Test start_database_monitoring function."""
        # Clear global state
        import src.database.monitoring
        src.database.monitoring._database_monitor = None
        
        mock_pool = MagicMock()
        config = DatabaseMonitorConfig(health_check_interval=1)
        
        with patch('src.database.monitoring.DatabaseMonitor') as mock_monitor_class:
            mock_monitor = AsyncMock()
            mock_monitor_class.return_value = mock_monitor
            
            await start_database_monitoring(mock_pool, config)
            
            mock_monitor_class.assert_called_once_with(config)
            mock_monitor.start_monitoring.assert_called_once_with(mock_pool)
    
    async def test_stop_database_monitoring(self):
        """Test stop_database_monitoring function."""
        # Set up global monitor
        import src.database.monitoring
        mock_monitor = AsyncMock()
        src.database.monitoring._database_monitor = mock_monitor
        
        await stop_database_monitoring()
        
        mock_monitor.stop_monitoring.assert_called_once()
        assert src.database.monitoring._database_monitor is None
    
    async def test_stop_database_monitoring_no_monitor(self):
        """Test stop_database_monitoring when no monitor exists."""
        # Clear global state
        import src.database.monitoring
        src.database.monitoring._database_monitor = None
        
        # Should not raise error
        await stop_database_monitoring()


class TestDatabaseMonitoringIntegration:
    """Test database monitoring integration scenarios."""
    
    async def test_full_monitoring_cycle(self):
        """Test complete monitoring lifecycle."""
        config = DatabaseMonitorConfig(
            health_check_interval=0.1,  # Very fast for testing
            metrics_collection_interval=0.1,
            leak_detection_interval=0.2,
            consecutive_failures_for_alert=1
        )
        
        monitor = DatabaseMonitor(config)
        
        # Mock pool manager
        mock_pool = MagicMock()
        mock_pool.metrics = MagicMock()
        mock_pool.metrics.active_connections = 5
        mock_pool.metrics.idle_connections = 3
        mock_pool.metrics.overflow_connections = 0
        mock_pool.metrics.total_connections_created = 10
        mock_pool.metrics.total_checkouts = 100
        mock_pool.metrics.successful_checkouts = 100
        mock_pool.metrics.failed_checkouts = 0
        mock_pool.metrics.total_queries = 200
        mock_pool.metrics.successful_queries = 200
        mock_pool.metrics.failed_queries = 0
        mock_pool.metrics.health_check_passes = 50
        mock_pool.metrics.health_check_failures = 0
        mock_pool.metrics.connections_recycled = 5
        mock_pool.metrics.connections_invalidated = 0
        mock_pool.metrics.connection_timeouts = 0
        mock_pool.metrics.get_average_checkout_time.return_value = 0.1
        mock_pool.metrics.get_checkout_failure_rate.return_value = 0.0
        mock_pool.metrics.get_average_query_time.return_value = 0.05
        mock_pool.metrics.get_query_failure_rate.return_value = 0.0
        mock_pool.metrics.to_dict.return_value = {"test": "data"}
        
        mock_pool.health_check = AsyncMock(return_value={
            "status": "healthy",
            "checks": {"engine": "ok", "pool": "ok"}
        })
        
        mock_pool.config = MagicMock()
        mock_pool.config.max_pool_size = 20
        
        # Start monitoring
        await monitor.start_monitoring(mock_pool)
        
        # Let it run briefly
        await asyncio.sleep(0.3)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Verify monitoring occurred
        assert monitor.last_health_check is not None
        assert monitor.consecutive_health_failures == 0
        assert len(monitor.active_alerts) == 0  # No alerts for healthy system
    
    async def test_alert_escalation_scenario(self):
        """Test alert escalation scenario."""
        config = DatabaseMonitorConfig(
            health_check_interval=0.1,
            consecutive_failures_for_alert=2,
            alert_cooldown_minutes=0  # No cooldown for testing
        )
        
        monitor = DatabaseMonitor(config)
        
        # Mock failing pool manager
        mock_pool = MagicMock()
        mock_pool.health_check = AsyncMock(side_effect=Exception("Database connection failed"))
        
        alert_received = []
        
        def alert_callback(alert):
            alert_received.append(alert)
        
        monitor.add_alert_callback(alert_callback)
        
        # Start monitoring
        await monitor.start_monitoring(mock_pool)
        
        # Let it run long enough for multiple health check failures
        await asyncio.sleep(0.25)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Verify alert was triggered after consecutive failures
        assert monitor.consecutive_health_failures >= 2
        assert len(alert_received) > 0
        
        # Verify alert details
        alert = alert_received[0]
        assert alert.alert_type == "database_unhealthy"
        assert alert.severity == "critical"
    
    async def test_performance_degradation_detection(self):
        """Test performance degradation detection."""
        config = DatabaseMonitorConfig(
            metrics_collection_interval=0.1,
            max_checkout_time_threshold=1.0,
            slow_query_threshold=2.0,
            connection_failure_rate_threshold=0.05,
            alert_cooldown_minutes=0
        )
        
        monitor = DatabaseMonitor(config)
        
        # Mock pool with performance issues
        mock_pool = MagicMock()
        mock_pool.metrics = MagicMock()
        mock_pool.metrics.active_connections = 18
        mock_pool.metrics.idle_connections = 2
        mock_pool.metrics.get_average_checkout_time.return_value = 2.5  # Above threshold
        mock_pool.metrics.get_average_query_time.return_value = 3.0    # Above threshold
        mock_pool.metrics.get_checkout_failure_rate.return_value = 0.08  # Above threshold
        mock_pool.metrics.get_query_failure_rate.return_value = 0.02    # Below threshold
        
        # Add other required attributes
        for attr in ['overflow_connections', 'total_connections_created', 'total_checkouts',
                     'successful_checkouts', 'failed_checkouts', 'total_queries',
                     'successful_queries', 'failed_queries', 'health_check_passes',
                     'health_check_failures', 'connections_recycled',
                     'connections_invalidated', 'connection_timeouts']:
            setattr(mock_pool.metrics, attr, 0)
        
        mock_pool.config = MagicMock()
        mock_pool.config.max_pool_size = 20
        
        mock_pool.health_check = AsyncMock(return_value={"status": "healthy"})
        
        # Start monitoring
        await monitor.start_monitoring(mock_pool)
        
        # Let metrics collection run
        await asyncio.sleep(0.15)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Verify performance alerts were triggered
        alert_types = list(monitor.active_alerts.keys())
        assert "slow_checkouts" in alert_types
        assert "slow_queries" in alert_types
        assert "high_checkout_failure_rate" in alert_types
        assert "high_pool_usage" in alert_types
    
    async def test_connection_leak_monitoring(self):
        """Test connection leak monitoring."""
        config = DatabaseMonitorConfig(
            leak_detection_interval=0.1,
            connection_leak_threshold=2,
            alert_cooldown_minutes=0
        )
        
        monitor = DatabaseMonitor(config)
        
        # Mock pool with connection leaks
        mock_pool = MagicMock()
        mock_pool.health_check = AsyncMock(return_value={
            "status": "degraded",
            "connection_leaks": [
                {"session_id": 123, "age_seconds": 3600},
                {"session_id": 456, "age_seconds": 1800},
                {"session_id": 789, "age_seconds": 2400}
            ]
        })
        
        # Start monitoring
        await monitor.start_monitoring(mock_pool)
        
        # Let leak detection run
        await asyncio.sleep(0.15)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Verify leak detection
        assert monitor.connection_leak_count == 3
        assert "connection_leaks" in monitor.active_alerts
        
        alert = monitor.active_alerts["connection_leaks"]
        assert alert.severity == "error"
        assert "3 connection leaks" in alert.message
        assert alert.metrics["leak_count"] == 3


class TestDatabaseMonitoringErrorHandling:
    """Test error handling in database monitoring."""
    
    async def test_health_check_exception_handling(self):
        """Test health check exception handling."""
        monitor = DatabaseMonitor()
        
        # Mock pool that raises exception
        mock_pool = MagicMock()
        mock_pool.health_check = AsyncMock(side_effect=Exception("Connection failed"))
        
        monitor.pool_manager = mock_pool
        
        # Should not raise exception
        await monitor._perform_health_check()
        
        # Should track failure
        assert monitor.consecutive_health_failures == 1
    
    async def test_metrics_collection_exception_handling(self):
        """Test metrics collection exception handling."""
        monitor = DatabaseMonitor()
        
        # Mock pool with problematic metrics
        mock_pool = MagicMock()
        mock_pool.metrics = MagicMock()
        mock_pool.metrics.active_connections = property(lambda x: (_ for _ in ()).throw(Exception("Metrics error")))
        
        monitor.pool_manager = mock_pool
        
        # Should not raise exception
        await monitor._collect_metrics()
    
    async def test_leak_detection_exception_handling(self):
        """Test leak detection exception handling."""
        monitor = DatabaseMonitor()
        
        # Mock pool that raises exception during health check
        mock_pool = MagicMock()
        mock_pool.health_check = AsyncMock(side_effect=Exception("Health check failed"))
        
        monitor.pool_manager = mock_pool
        
        # Should not raise exception
        await monitor._detect_connection_leaks()
    
    async def test_performance_monitoring_exception_handling(self):
        """Test performance monitoring exception handling."""
        monitor = DatabaseMonitor()
        
        # Mock pool with problematic metrics
        mock_pool = MagicMock()
        mock_pool.metrics = MagicMock()
        mock_pool.metrics.get_average_query_time.side_effect = Exception("Metrics error")
        
        monitor.pool_manager = mock_pool
        
        # Should not raise exception
        await monitor._monitor_performance()
    
    async def test_monitor_task_exception_isolation(self):
        """Test that exceptions in one monitor task don't affect others."""
        config = DatabaseMonitorConfig(
            health_check_interval=0.1,
            metrics_collection_interval=0.1,
            leak_detection_interval=0.1
        )
        
        monitor = DatabaseMonitor(config)
        
        # Mock pool that fails in specific ways
        mock_pool = MagicMock()
        mock_pool.health_check = AsyncMock(side_effect=Exception("Health check error"))
        mock_pool.metrics = MagicMock()
        
        # Set up metrics to work partially
        for attr in ['active_connections', 'idle_connections', 'overflow_connections',
                     'total_connections_created', 'total_checkouts', 'successful_checkouts',
                     'failed_checkouts', 'total_queries', 'successful_queries',
                     'failed_queries', 'health_check_passes', 'health_check_failures',
                     'connections_recycled', 'connections_invalidated', 'connection_timeouts']:
            setattr(mock_pool.metrics, attr, 0)
        
        mock_pool.metrics.get_average_checkout_time.return_value = 0.1
        mock_pool.metrics.get_checkout_failure_rate.return_value = 0.0
        mock_pool.metrics.get_average_query_time.return_value = 0.1
        mock_pool.metrics.get_query_failure_rate.return_value = 0.0
        
        # Start monitoring
        await monitor.start_monitoring(mock_pool)
        
        # Let tasks run
        await asyncio.sleep(0.2)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Even with health check failures, other monitoring should continue
        assert monitor.consecutive_health_failures > 0  # Health checks failed
        # But metrics collection should have worked (no exception raised)