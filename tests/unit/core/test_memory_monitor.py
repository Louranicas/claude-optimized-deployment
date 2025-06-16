"""
Comprehensive test suite for memory_monitor module.

Tests cover:
- Memory metrics collection and pressure level detection
- Memory pressure action execution
- Circuit breaker integration
- Memory monitoring loop and scheduling
- Memory threshold configuration
- Performance impact measurement
- Error handling and recovery
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime

from src.core.memory_monitor import (
    MemoryPressureLevel,
    MemoryMetrics,
    MemoryThresholds,
    MemoryPressureAction,
    GarbageCollectionAction,
    ClearCachesAction,
    ReduceBuffersAction,
    MemoryCircuitBreaker,
    MemoryMonitor,
    check_memory_pressure,
    with_memory_monitoring,
    memory_monitor
)


class TestMemoryPressureLevel:
    """Test MemoryPressureLevel enum."""
    
    def test_pressure_levels(self):
        """Test all pressure level values."""
        assert MemoryPressureLevel.LOW.value == "low"
        assert MemoryPressureLevel.MODERATE.value == "moderate"
        assert MemoryPressureLevel.HIGH.value == "high"
        assert MemoryPressureLevel.CRITICAL.value == "critical"


class TestMemoryMetrics:
    """Test MemoryMetrics dataclass."""
    
    def test_memory_metrics_creation(self):
        """Test MemoryMetrics creation with all fields."""
        timestamp = datetime.now()
        metrics = MemoryMetrics(
            timestamp=timestamp,
            process_memory_mb=1024.5,
            system_memory_percent=75.2,
            available_memory_mb=2048.7,
            swap_memory_percent=10.5,
            gc_count=15,
            gc_time_ms=45.8,
            pressure_level=MemoryPressureLevel.MODERATE
        )
        
        assert metrics.timestamp == timestamp
        assert metrics.process_memory_mb == 1024.5
        assert metrics.system_memory_percent == 75.2
        assert metrics.available_memory_mb == 2048.7
        assert metrics.swap_memory_percent == 10.5
        assert metrics.gc_count == 15
        assert metrics.gc_time_ms == 45.8
        assert metrics.pressure_level == MemoryPressureLevel.MODERATE
    
    def test_is_pressure_high_property(self):
        """Test is_pressure_high property."""
        # High pressure
        high_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=1000,
            system_memory_percent=90,
            available_memory_mb=100,
            swap_memory_percent=50,
            gc_count=10,
            gc_time_ms=20,
            pressure_level=MemoryPressureLevel.HIGH
        )
        assert high_metrics.is_pressure_high is True
        
        # Critical pressure
        critical_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=2000,
            system_memory_percent=95,
            available_memory_mb=50,
            swap_memory_percent=80,
            gc_count=20,
            gc_time_ms=50,
            pressure_level=MemoryPressureLevel.CRITICAL
        )
        assert critical_metrics.is_pressure_high is True
        
        # Low pressure
        low_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=500,
            system_memory_percent=30,
            available_memory_mb=4000,
            swap_memory_percent=5,
            gc_count=5,
            gc_time_ms=10,
            pressure_level=MemoryPressureLevel.LOW
        )
        assert low_metrics.is_pressure_high is False


class TestMemoryThresholds:
    """Test MemoryThresholds configuration."""
    
    def test_default_thresholds(self):
        """Test default threshold values."""
        thresholds = MemoryThresholds()
        
        assert thresholds.moderate_system_percent == 70.0
        assert thresholds.high_system_percent == 85.0
        assert thresholds.critical_system_percent == 95.0
        assert thresholds.moderate_process_mb == 1024.0
        assert thresholds.high_process_mb == 2048.0
        assert thresholds.critical_process_mb == 4096.0
        assert thresholds.swap_warning_percent == 50.0
    
    def test_custom_thresholds(self):
        """Test custom threshold configuration."""
        thresholds = MemoryThresholds(
            moderate_system_percent=60.0,
            high_system_percent=80.0,
            critical_system_percent=90.0,
            moderate_process_mb=512.0,
            high_process_mb=1024.0,
            critical_process_mb=2048.0,
            swap_warning_percent=25.0
        )
        
        assert thresholds.moderate_system_percent == 60.0
        assert thresholds.high_system_percent == 80.0
        assert thresholds.critical_system_percent == 90.0
        assert thresholds.moderate_process_mb == 512.0
        assert thresholds.high_process_mb == 1024.0
        assert thresholds.critical_process_mb == 2048.0
        assert thresholds.swap_warning_percent == 25.0


class TestGarbageCollectionAction:
    """Test GarbageCollectionAction implementation."""
    
    @patch('src.core.memory_monitor.gc_optimizer')
    @pytest.mark.asyncio
    async def test_garbage_collection_action_success(self, mock_gc_optimizer):
        """Test successful garbage collection action."""
        # Mock GC metrics
        mock_gc_metrics = Mock()
        mock_gc_metrics.memory_freed_mb = 128.5
        mock_gc_optimizer.trigger_gc.return_value = mock_gc_metrics
        
        action = GarbageCollectionAction(force_gc=True)
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=2000,
            system_memory_percent=90,
            available_memory_mb=100,
            swap_memory_percent=20,
            gc_count=10,
            gc_time_ms=50,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        result = await action.execute(metrics)
        
        assert result is True
        assert action.name == "garbage_collection"
        mock_gc_optimizer.trigger_gc.assert_called_once_with(force=True)
    
    @patch('src.core.memory_monitor.gc_optimizer')
    @pytest.mark.asyncio
    async def test_garbage_collection_action_no_gc(self, mock_gc_optimizer):
        """Test garbage collection action when no GC triggered."""
        mock_gc_optimizer.trigger_gc.return_value = None
        
        action = GarbageCollectionAction(force_gc=False)
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=1000,
            system_memory_percent=70,
            available_memory_mb=1000,
            swap_memory_percent=10,
            gc_count=5,
            gc_time_ms=20,
            pressure_level=MemoryPressureLevel.MODERATE
        )
        
        result = await action.execute(metrics)
        
        assert result is False
        mock_gc_optimizer.trigger_gc.assert_called_once_with(force=False)
    
    @patch('src.core.memory_monitor.gc_optimizer')
    @pytest.mark.asyncio
    async def test_garbage_collection_action_error(self, mock_gc_optimizer):
        """Test garbage collection action error handling."""
        mock_gc_optimizer.trigger_gc.side_effect = Exception("GC failed")
        
        action = GarbageCollectionAction()
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=1000,
            system_memory_percent=80,
            available_memory_mb=500,
            swap_memory_percent=15,
            gc_count=8,
            gc_time_ms=30,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        result = await action.execute(metrics)
        
        assert result is False


class TestClearCachesAction:
    """Test ClearCachesAction implementation."""
    
    @pytest.mark.asyncio
    async def test_clear_caches_action_success(self):
        """Test successful cache clearing action."""
        cache_cleared = []
        
        def clear_cache_1():
            cache_cleared.append("cache1")
        
        def clear_cache_2():
            cache_cleared.append("cache2")
        
        action = ClearCachesAction([clear_cache_1, clear_cache_2])
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=1500,
            system_memory_percent=85,
            available_memory_mb=200,
            swap_memory_percent=30,
            gc_count=12,
            gc_time_ms=40,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        result = await action.execute(metrics)
        
        assert result is True
        assert action.name == "clear_caches"
        assert cache_cleared == ["cache1", "cache2"]
    
    @pytest.mark.asyncio
    async def test_clear_caches_action_partial_failure(self):
        """Test cache clearing action with partial failures."""
        cache_cleared = []
        
        def clear_cache_1():
            cache_cleared.append("cache1")
        
        def failing_cache_clear():
            raise Exception("Cache clear failed")
        
        def clear_cache_3():
            cache_cleared.append("cache3")
        
        action = ClearCachesAction([clear_cache_1, failing_cache_clear, clear_cache_3])
        metrics = Mock()
        
        result = await action.execute(metrics)
        
        assert result is True  # Should return True if at least one succeeded
        assert cache_cleared == ["cache1", "cache3"]
    
    @pytest.mark.asyncio
    async def test_clear_caches_action_no_clearers(self):
        """Test cache clearing action with no cache clearers."""
        action = ClearCachesAction([])
        metrics = Mock()
        
        result = await action.execute(metrics)
        
        assert result is False


class TestReduceBuffersAction:
    """Test ReduceBuffersAction implementation."""
    
    @pytest.mark.asyncio
    async def test_reduce_buffers_action_success(self):
        """Test successful buffer reduction action."""
        buffers_reduced = []
        
        def reduce_buffer_1():
            buffers_reduced.append("buffer1")
        
        def reduce_buffer_2():
            buffers_reduced.append("buffer2")
        
        action = ReduceBuffersAction([reduce_buffer_1, reduce_buffer_2])
        metrics = Mock()
        
        result = await action.execute(metrics)
        
        assert result is True
        assert action.name == "reduce_buffers"
        assert buffers_reduced == ["buffer1", "buffer2"]
    
    @pytest.mark.asyncio
    async def test_reduce_buffers_action_error_handling(self):
        """Test buffer reduction action error handling."""
        def failing_reducer():
            raise Exception("Reduction failed")
        
        action = ReduceBuffersAction([failing_reducer])
        metrics = Mock()
        
        result = await action.execute(metrics)
        
        assert result is False


class TestMemoryCircuitBreaker:
    """Test MemoryCircuitBreaker implementation."""
    
    @patch('src.core.memory_monitor.psutil.Process')
    def test_memory_circuit_breaker_process_threshold(self, mock_process):
        """Test circuit breaker trips on process memory threshold."""
        # Mock high process memory
        mock_memory_info = Mock()
        mock_memory_info.rss = 5 * 1024 * 1024 * 1024  # 5GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock low system memory to isolate process threshold test
        with patch('src.core.memory_monitor.psutil.virtual_memory') as mock_virtual_memory:
            mock_system_memory = Mock()
            mock_system_memory.percent = 50.0
            mock_virtual_memory.return_value = mock_system_memory
            
            breaker = MemoryCircuitBreaker(
                name="test_breaker",
                memory_threshold_mb=4096,  # 4GB threshold
                system_threshold_percent=90
            )
            
            assert breaker._should_trip() is True
    
    @patch('src.core.memory_monitor.psutil.virtual_memory')
    @patch('src.core.memory_monitor.psutil.Process')
    def test_memory_circuit_breaker_system_threshold(self, mock_process, mock_virtual_memory):
        """Test circuit breaker trips on system memory threshold."""
        # Mock low process memory
        mock_memory_info = Mock()
        mock_memory_info.rss = 1 * 1024 * 1024 * 1024  # 1GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock high system memory
        mock_system_memory = Mock()
        mock_system_memory.percent = 95.0
        mock_virtual_memory.return_value = mock_system_memory
        
        breaker = MemoryCircuitBreaker(
            name="test_breaker",
            memory_threshold_mb=4096,
            system_threshold_percent=90
        )
        
        assert breaker._should_trip() is True
    
    @patch('src.core.memory_monitor.psutil.virtual_memory')
    @patch('src.core.memory_monitor.psutil.Process')
    def test_memory_circuit_breaker_no_trip(self, mock_process, mock_virtual_memory):
        """Test circuit breaker doesn't trip under normal conditions."""
        # Mock normal process memory
        mock_memory_info = Mock()
        mock_memory_info.rss = 1 * 1024 * 1024 * 1024  # 1GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock normal system memory
        mock_system_memory = Mock()
        mock_system_memory.percent = 60.0
        mock_virtual_memory.return_value = mock_system_memory
        
        breaker = MemoryCircuitBreaker(
            name="test_breaker",
            memory_threshold_mb=4096,
            system_threshold_percent=90
        )
        
        assert breaker._should_trip() is False
    
    @patch('src.core.memory_monitor.psutil.Process')
    def test_memory_circuit_breaker_error_handling(self, mock_process):
        """Test circuit breaker error handling."""
        mock_process.side_effect = Exception("psutil error")
        
        breaker = MemoryCircuitBreaker("test_breaker")
        
        assert breaker._should_trip() is False  # Should not trip on error


class TestMemoryMonitor:
    """Test MemoryMonitor main class."""
    
    def test_memory_monitor_initialization(self):
        """Test MemoryMonitor initialization."""
        monitor = MemoryMonitor()
        
        assert isinstance(monitor.thresholds, MemoryThresholds)
        assert monitor.monitoring_interval == 30.0
        assert monitor.history_size == 100
        assert monitor.metrics_history == []
        assert isinstance(monitor.pressure_actions, dict)
        assert len(monitor.pressure_actions) == len(MemoryPressureLevel)
        assert monitor.circuit_breakers == []
        assert monitor.pressure_callbacks == []
    
    def test_memory_monitor_custom_config(self):
        """Test MemoryMonitor with custom configuration."""
        custom_thresholds = MemoryThresholds(moderate_system_percent=60.0)
        monitor = MemoryMonitor(
            thresholds=custom_thresholds,
            monitoring_interval=15.0,
            history_size=50
        )
        
        assert monitor.thresholds == custom_thresholds
        assert monitor.monitoring_interval == 15.0
        assert monitor.history_size == 50
    
    @patch('src.core.memory_monitor.psutil.virtual_memory')
    @patch('src.core.memory_monitor.psutil.swap_memory')
    @patch('src.core.memory_monitor.psutil.Process')
    @patch('src.core.memory_monitor.gc_optimizer')
    def test_get_current_metrics(self, mock_gc_optimizer, mock_process, mock_swap, mock_virtual):
        """Test getting current memory metrics."""
        # Mock process memory
        mock_memory_info = Mock()
        mock_memory_info.rss = 2 * 1024 * 1024 * 1024  # 2GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock system memory
        mock_system_memory = Mock()
        mock_system_memory.percent = 75.0
        mock_system_memory.available = 4 * 1024 * 1024 * 1024  # 4GB available
        mock_virtual.return_value = mock_system_memory
        
        # Mock swap memory
        mock_swap_memory = Mock()
        mock_swap_memory.percent = 20.0
        mock_swap.return_value = mock_swap_memory
        
        # Mock GC stats
        mock_gc_optimizer.get_gc_stats.return_value = {
            "gc_count": 10,
            "avg_pause_time_ms": 25.0
        }
        
        monitor = MemoryMonitor()
        metrics = monitor.get_current_metrics()
        
        assert isinstance(metrics, MemoryMetrics)
        assert metrics.process_memory_mb == 2048.0  # 2GB in MB
        assert metrics.system_memory_percent == 75.0
        assert metrics.available_memory_mb == 4096.0  # 4GB in MB
        assert metrics.swap_memory_percent == 20.0
        assert metrics.gc_count == 10
        assert metrics.gc_time_ms == 25.0
        assert isinstance(metrics.pressure_level, MemoryPressureLevel)
    
    def test_calculate_pressure_level_critical(self):
        """Test pressure level calculation for critical conditions."""
        monitor = MemoryMonitor()
        
        # Critical system memory
        level = monitor._calculate_pressure_level(1000, 96, 10)
        assert level == MemoryPressureLevel.CRITICAL
        
        # Critical process memory
        level = monitor._calculate_pressure_level(5000, 70, 10)
        assert level == MemoryPressureLevel.CRITICAL
    
    def test_calculate_pressure_level_high(self):
        """Test pressure level calculation for high conditions."""
        monitor = MemoryMonitor()
        
        # High system memory
        level = monitor._calculate_pressure_level(1000, 87, 10)
        assert level == MemoryPressureLevel.HIGH
        
        # High process memory
        level = monitor._calculate_pressure_level(2500, 70, 10)
        assert level == MemoryPressureLevel.HIGH
        
        # High swap usage
        level = monitor._calculate_pressure_level(1000, 70, 60)
        assert level == MemoryPressureLevel.HIGH
    
    def test_calculate_pressure_level_moderate(self):
        """Test pressure level calculation for moderate conditions."""
        monitor = MemoryMonitor()
        
        # Moderate system memory
        level = monitor._calculate_pressure_level(800, 72, 10)
        assert level == MemoryPressureLevel.MODERATE
        
        # Moderate process memory
        level = monitor._calculate_pressure_level(1200, 60, 10)
        assert level == MemoryPressureLevel.MODERATE
    
    def test_calculate_pressure_level_low(self):
        """Test pressure level calculation for low conditions."""
        monitor = MemoryMonitor()
        
        level = monitor._calculate_pressure_level(500, 50, 5)
        assert level == MemoryPressureLevel.LOW
    
    def test_add_pressure_action(self):
        """Test adding pressure actions."""
        monitor = MemoryMonitor()
        action = GarbageCollectionAction()
        
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, action)
        
        assert action in monitor.pressure_actions[MemoryPressureLevel.HIGH]
    
    def test_add_circuit_breaker(self):
        """Test adding circuit breakers."""
        monitor = MemoryMonitor()
        breaker = MemoryCircuitBreaker("test_breaker")
        
        monitor.add_circuit_breaker(breaker)
        
        assert breaker in monitor.circuit_breakers
    
    def test_add_pressure_callback(self):
        """Test adding pressure callbacks."""
        monitor = MemoryMonitor()
        callback = Mock()
        
        monitor.add_pressure_callback(callback)
        
        assert callback in monitor.pressure_callbacks
    
    @pytest.mark.asyncio
    async def test_handle_memory_pressure_low(self):
        """Test handling of low memory pressure (no action)."""
        monitor = MemoryMonitor()
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=500,
            system_memory_percent=40,
            available_memory_mb=4000,
            swap_memory_percent=5,
            gc_count=3,
            gc_time_ms=15,
            pressure_level=MemoryPressureLevel.LOW
        )
        
        # Should not raise any exceptions and complete quickly
        await monitor._handle_memory_pressure(metrics)
        assert True  # If we get here, no exceptions were raised
    
    @pytest.mark.asyncio
    async def test_handle_memory_pressure_high(self):
        """Test handling of high memory pressure."""
        monitor = MemoryMonitor()
        
        # Add mock action
        action = AsyncMock()
        action.execute.return_value = True
        action.name = "test_action"
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, action)
        
        # Add mock callback
        callback = Mock()
        monitor.add_pressure_callback(callback)
        
        # Add mock circuit breaker
        breaker = Mock()
        breaker._check_and_update_state = Mock()
        monitor.add_circuit_breaker(breaker)
        
        metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=2500,
            system_memory_percent=90,
            available_memory_mb=200,
            swap_memory_percent=30,
            gc_count=15,
            gc_time_ms=60,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        await monitor._handle_memory_pressure(metrics)
        
        # Verify action was executed
        action.execute.assert_called_once_with(metrics)
        
        # Verify callback was called
        callback.assert_called_once_with(metrics)
        
        # Verify circuit breaker was updated
        breaker._check_and_update_state.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self):
        """Test starting and stopping monitoring."""
        monitor = MemoryMonitor()
        
        # Start monitoring
        await monitor.start_monitoring()
        assert monitor._monitoring_active is True
        assert monitor._monitoring_task is not None
        
        # Stop monitoring
        await monitor.stop_monitoring()
        assert monitor._monitoring_active is False
    
    def test_get_metrics_history(self):
        """Test getting metrics history."""
        monitor = MemoryMonitor()
        
        # Add some test metrics
        for i in range(5):
            metrics = MemoryMetrics(
                timestamp=datetime.now(),
                process_memory_mb=1000 + i * 100,
                system_memory_percent=70 + i * 2,
                available_memory_mb=2000 - i * 100,
                swap_memory_percent=10 + i,
                gc_count=5 + i,
                gc_time_ms=20 + i * 5,
                pressure_level=MemoryPressureLevel.MODERATE
            )
            monitor.metrics_history.append(metrics)
        
        history = monitor.get_metrics_history()
        
        assert len(history) == 5
        assert isinstance(history, list)
        assert all(isinstance(m, MemoryMetrics) for m in history)
    
    def test_get_pressure_statistics_empty(self):
        """Test getting pressure statistics with no history."""
        monitor = MemoryMonitor()
        stats = monitor.get_pressure_statistics()
        
        assert stats["total_samples"] == 0
        assert stats["pressure_events"] == 0
        assert stats["avg_process_memory_mb"] == 0
        assert stats["avg_system_memory_percent"] == 0
        assert stats["pressure_distribution"] == {level.value: 0 for level in MemoryPressureLevel}
    
    def test_get_pressure_statistics_with_data(self):
        """Test getting pressure statistics with sample data."""
        monitor = MemoryMonitor()
        
        # Add mixed pressure level metrics
        pressure_levels = [
            MemoryPressureLevel.LOW,
            MemoryPressureLevel.MODERATE,
            MemoryPressureLevel.HIGH,
            MemoryPressureLevel.LOW,
            MemoryPressureLevel.CRITICAL
        ]
        
        for level in pressure_levels:
            metrics = MemoryMetrics(
                timestamp=datetime.now(),
                process_memory_mb=1000,
                system_memory_percent=70,
                available_memory_mb=2000,
                swap_memory_percent=10,
                gc_count=5,
                gc_time_ms=20,
                pressure_level=level
            )
            monitor.metrics_history.append(metrics)
        
        stats = monitor.get_pressure_statistics()
        
        assert stats["total_samples"] == 5
        assert stats["pressure_events"] == 3  # MODERATE, HIGH, CRITICAL
        assert stats["pressure_rate"] == 0.6  # 3/5
        assert stats["avg_process_memory_mb"] == 1000
        assert stats["avg_system_memory_percent"] == 70
        assert stats["pressure_distribution"]["low"] == 2
        assert stats["pressure_distribution"]["moderate"] == 1
        assert stats["pressure_distribution"]["high"] == 1
        assert stats["pressure_distribution"]["critical"] == 1


class TestMemoryMonitoringDecorator:
    """Test the with_memory_monitoring decorator."""
    
    @patch('src.core.memory_monitor.memory_monitor')
    @pytest.mark.asyncio
    async def test_async_decorator_high_pressure(self, mock_monitor):
        """Test decorator with async function and high memory pressure."""
        # Mock high pressure metrics
        mock_metrics = Mock()
        mock_metrics.is_pressure_high = True
        mock_monitor.get_current_metrics.return_value = mock_metrics
        mock_monitor._handle_memory_pressure = AsyncMock()
        
        @with_memory_monitoring
        async def test_async_function():
            return "async_result"
        
        result = await test_async_function()
        
        assert result == "async_result"
        # Should check memory twice (before and after)
        assert mock_monitor.get_current_metrics.call_count == 2
        # Should handle pressure twice if detected
        assert mock_monitor._handle_memory_pressure.call_count == 2
    
    @patch('src.core.memory_monitor.memory_monitor')
    def test_sync_decorator_high_pressure(self, mock_monitor):
        """Test decorator with sync function and high memory pressure."""
        # Mock high pressure metrics
        mock_metrics = Mock()
        mock_metrics.is_pressure_high = True
        mock_monitor.get_current_metrics.return_value = mock_metrics
        
        @with_memory_monitoring
        def test_sync_function():
            return "sync_result"
        
        result = test_sync_function()
        
        assert result == "sync_result"
        # Should check memory twice (before and after)
        assert mock_monitor.get_current_metrics.call_count == 2
    
    @patch('src.core.memory_monitor.memory_monitor')
    @pytest.mark.asyncio
    async def test_decorator_exception_handling(self, mock_monitor):
        """Test decorator handles exceptions properly."""
        mock_metrics = Mock()
        mock_metrics.is_pressure_high = False
        mock_monitor.get_current_metrics.return_value = mock_metrics
        
        @with_memory_monitoring
        async def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            await failing_function()
        
        # Should still check memory even with exception
        mock_monitor.get_current_metrics.assert_called()


class TestGlobalFunctions:
    """Test global convenience functions."""
    
    @patch('src.core.memory_monitor.memory_monitor')
    @pytest.mark.asyncio
    async def test_check_memory_pressure(self, mock_monitor):
        """Test global check_memory_pressure function."""
        mock_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=1500,
            system_memory_percent=80,
            available_memory_mb=1000,
            swap_memory_percent=20,
            gc_count=8,
            gc_time_ms=35,
            pressure_level=MemoryPressureLevel.HIGH
        )
        mock_monitor.get_current_metrics.return_value = mock_metrics
        
        result = await check_memory_pressure()
        
        assert result == mock_metrics
        mock_monitor.get_current_metrics.assert_called_once()


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_memory_monitoring_lifecycle(self):
        """Test complete memory monitoring lifecycle."""
        monitor = MemoryMonitor(monitoring_interval=0.1)  # Fast for testing
        
        # Add some actions
        gc_action = GarbageCollectionAction()
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, gc_action)
        
        # Add circuit breaker
        breaker = MemoryCircuitBreaker("test_breaker")
        monitor.add_circuit_breaker(breaker)
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Let it run briefly
        await asyncio.sleep(0.2)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Should have completed without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_memory_pressure_response_chain(self):
        """Test complete memory pressure response chain."""
        monitor = MemoryMonitor()
        
        # Track action executions
        actions_executed = []
        
        class TestAction(MemoryPressureAction):
            def __init__(self, action_name):
                self.action_name = action_name
            
            async def execute(self, metrics):
                actions_executed.append(self.action_name)
                return True
            
            @property
            def name(self):
                return self.action_name
        
        # Add multiple actions for high pressure
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, TestAction("action1"))
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, TestAction("action2"))
        
        # Create high pressure metrics
        high_pressure_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=3000,
            system_memory_percent=90,
            available_memory_mb=100,
            swap_memory_percent=60,
            gc_count=20,
            gc_time_ms=80,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        # Handle pressure
        await monitor._handle_memory_pressure(high_pressure_metrics)
        
        # Verify both actions were executed
        assert "action1" in actions_executed
        assert "action2" in actions_executed


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @patch('src.core.memory_monitor.psutil.Process')
    def test_get_current_metrics_error_handling(self, mock_process):
        """Test error handling in get_current_metrics."""
        mock_process.side_effect = Exception("psutil error")
        
        monitor = MemoryMonitor()
        metrics = monitor.get_current_metrics()
        
        # Should return default metrics on error
        assert isinstance(metrics, MemoryMetrics)
        assert metrics.process_memory_mb == 0
        assert metrics.system_memory_percent == 0
        assert metrics.pressure_level == MemoryPressureLevel.LOW
    
    @pytest.mark.asyncio
    async def test_action_execution_error_handling(self):
        """Test error handling during action execution."""
        monitor = MemoryMonitor()
        
        class FailingAction(MemoryPressureAction):
            async def execute(self, metrics):
                raise Exception("Action failed")
            
            @property
            def name(self):
                return "failing_action"
        
        monitor.add_pressure_action(MemoryPressureLevel.HIGH, FailingAction())
        
        high_pressure_metrics = MemoryMetrics(
            timestamp=datetime.now(),
            process_memory_mb=3000,
            system_memory_percent=90,
            available_memory_mb=100,
            swap_memory_percent=40,
            gc_count=15,
            gc_time_ms=50,
            pressure_level=MemoryPressureLevel.HIGH
        )
        
        # Should not raise exception despite action failure
        await monitor._handle_memory_pressure(high_pressure_metrics)
        assert True  # If we get here, error was handled gracefully
    
    @pytest.mark.asyncio
    async def test_monitoring_loop_error_recovery(self):
        """Test monitoring loop error recovery."""
        monitor = MemoryMonitor(monitoring_interval=0.05)  # Very fast for testing
        
        # Mock get_current_metrics to fail once, then succeed
        call_count = 0
        original_get_metrics = monitor.get_current_metrics
        
        def failing_get_metrics():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Metrics error")
            return original_get_metrics()
        
        monitor.get_current_metrics = failing_get_metrics
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Let it run briefly to encounter and recover from error
        await asyncio.sleep(0.15)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        
        # Should have recovered and continued running
        assert call_count > 1  # Should have been called multiple times


if __name__ == "__main__":
    pytest.main([__file__])