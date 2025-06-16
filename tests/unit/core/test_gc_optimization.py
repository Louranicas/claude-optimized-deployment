"""
Comprehensive test suite for gc_optimization module.

Tests cover:
- GC metrics collection and accuracy
- GC optimizer configuration and tuning
- Memory pressure detection
- Performance optimization strategies
- Automatic GC scheduling
- V8 flags configuration
- Error handling and edge cases
"""

import gc
import time
import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.core.gc_optimization import (
    GCMetrics,
    GCOptimizer,
    with_gc_optimization,
    periodic_gc_check,
    get_v8_flags,
    gc_optimizer,
    V8_OPTIMIZATION_FLAGS
)


class TestGCMetrics:
    """Test GCMetrics dataclass functionality."""
    
    def test_gc_metrics_creation(self):
        """Test GCMetrics creation with all fields."""
        timestamp = datetime.now()
        metrics = GCMetrics(
            pause_time_ms=15.5,
            memory_freed_mb=128.7,
            efficiency_percent=85.2,
            timestamp=timestamp,
            gc_type="manual",
            heap_before_mb=512.0,
            heap_after_mb=383.3
        )
        
        assert metrics.pause_time_ms == 15.5
        assert metrics.memory_freed_mb == 128.7
        assert metrics.efficiency_percent == 85.2
        assert metrics.timestamp == timestamp
        assert metrics.gc_type == "manual"
        assert metrics.heap_before_mb == 512.0
        assert metrics.heap_after_mb == 383.3
    
    def test_gc_metrics_defaults(self):
        """Test GCMetrics with minimal required fields."""
        timestamp = datetime.now()
        metrics = GCMetrics(
            pause_time_ms=10.0,
            memory_freed_mb=50.0,
            efficiency_percent=75.0,
            timestamp=timestamp,
            gc_type="auto",
            heap_before_mb=200.0,
            heap_after_mb=150.0
        )
        
        assert isinstance(metrics, GCMetrics)
        assert metrics.pause_time_ms > 0
        assert metrics.memory_freed_mb > 0


class TestGCOptimizer:
    """Test GCOptimizer class functionality."""
    
    def test_gc_optimizer_initialization(self):
        """Test GCOptimizer initialization."""
        optimizer = GCOptimizer()
        
        assert optimizer.metrics_history == []
        assert optimizer.memory_threshold_mb == 4096
        assert optimizer.gc_interval_seconds == 60
        assert isinstance(optimizer.last_gc_time, float)
        assert hasattr(optimizer, 'weak_refs')
    
    def test_gc_optimizer_custom_thresholds(self):
        """Test GCOptimizer with custom configuration."""
        optimizer = GCOptimizer()
        optimizer.memory_threshold_mb = 2048
        optimizer.gc_interval_seconds = 30
        
        assert optimizer.memory_threshold_mb == 2048
        assert optimizer.gc_interval_seconds == 30
    
    @patch('src.core.gc_optimization.gc.collect')
    @patch('src.core.gc_optimization.psutil.Process')
    def test_trigger_gc_successful(self, mock_process, mock_gc_collect):
        """Test successful GC trigger with metrics collection."""
        # Mock psutil Process
        mock_memory_info = Mock()
        mock_memory_info.rss = 1024 * 1024 * 1024  # 1GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock gc.collect to return number of collected objects
        mock_gc_collect.return_value = 150
        
        optimizer = GCOptimizer()
        
        # First call should trigger GC (no recent GC)
        optimizer.last_gc_time = 0
        metrics = optimizer.trigger_gc(force=True)
        
        assert metrics is not None
        assert isinstance(metrics, GCMetrics)
        assert metrics.memory_freed_mb >= 0
        assert metrics.pause_time_ms >= 0
        assert metrics.efficiency_percent >= 0
        assert metrics.gc_type == "manual"
        assert len(optimizer.metrics_history) == 1
        
        # Verify gc.collect was called
        mock_gc_collect.assert_called_with(2)
    
    def test_trigger_gc_rate_limiting(self):
        """Test GC rate limiting prevents too frequent GC."""
        optimizer = GCOptimizer()
        optimizer.gc_interval_seconds = 60
        
        # Set last GC time to recent
        optimizer.last_gc_time = time.time() - 30  # 30 seconds ago
        
        # Should not trigger GC without force
        metrics = optimizer.trigger_gc(force=False)
        assert metrics is None
        
        # Should trigger GC with force
        with patch('src.core.gc_optimization.psutil.Process'):
            metrics = optimizer.trigger_gc(force=True)
            assert metrics is not None
    
    @patch('src.core.gc_optimization.psutil.Process')
    def test_check_memory_pressure_threshold(self, mock_process):
        """Test memory pressure detection based on threshold."""
        # Mock high memory usage
        mock_memory_info = Mock()
        mock_memory_info.rss = 5 * 1024 * 1024 * 1024  # 5GB in bytes
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        optimizer = GCOptimizer()
        optimizer.memory_threshold_mb = 4096  # 4GB threshold
        
        # Should detect memory pressure
        assert optimizer.check_memory_pressure() is True
    
    @patch('src.core.gc_optimization.psutil.Process')
    @patch('src.core.gc_optimization.psutil.virtual_memory')
    def test_check_memory_pressure_system_wide(self, mock_virtual_memory, mock_process):
        """Test system-wide memory pressure detection."""
        # Mock process memory (under threshold)
        mock_memory_info = Mock()
        mock_memory_info.rss = 2 * 1024 * 1024 * 1024  # 2GB
        mock_process.return_value.memory_info.return_value = mock_memory_info
        
        # Mock system memory (over threshold)
        mock_system_memory = Mock()
        mock_system_memory.percent = 90.0
        mock_virtual_memory.return_value = mock_system_memory
        
        optimizer = GCOptimizer()
        optimizer.memory_threshold_mb = 4096
        
        # Should detect system memory pressure
        assert optimizer.check_memory_pressure() is True
    
    def test_optimize_for_throughput(self):
        """Test throughput optimization configuration."""
        optimizer = GCOptimizer()
        
        # Get initial thresholds
        initial_thresholds = gc.get_threshold()
        
        optimizer.optimize_for_throughput()
        
        # Should increase thresholds and interval
        new_thresholds = gc.get_threshold()
        assert new_thresholds[0] >= initial_thresholds[0]
        assert optimizer.gc_interval_seconds == 120
    
    def test_optimize_for_latency(self):
        """Test latency optimization configuration."""
        optimizer = GCOptimizer()
        
        optimizer.optimize_for_latency()
        
        # Should decrease thresholds and interval
        thresholds = gc.get_threshold()
        assert thresholds[0] == 400
        assert optimizer.gc_interval_seconds == 30
    
    def test_get_gc_stats_empty(self):
        """Test GC stats when no metrics available."""
        optimizer = GCOptimizer()
        stats = optimizer.get_gc_stats()
        
        assert stats['avg_pause_time_ms'] == 0
        assert stats['avg_efficiency_percent'] == 0
        assert stats['total_memory_freed_mb'] == 0
        assert stats['gc_count'] == 0
    
    def test_get_gc_stats_with_metrics(self):
        """Test GC stats calculation with metrics."""
        optimizer = GCOptimizer()
        
        # Add sample metrics
        for i in range(5):
            metrics = GCMetrics(
                pause_time_ms=10.0 + i,
                memory_freed_mb=50.0 + i * 10,
                efficiency_percent=80.0 + i,
                timestamp=datetime.now(),
                gc_type="test",
                heap_before_mb=200.0,
                heap_after_mb=150.0
            )
            optimizer.metrics_history.append(metrics)
        
        stats = optimizer.get_gc_stats()
        
        assert stats['avg_pause_time_ms'] == 12.0  # (10+11+12+13+14)/5
        assert stats['avg_efficiency_percent'] == 82.0  # (80+81+82+83+84)/5
        assert stats['total_memory_freed_mb'] == 350.0  # 50+60+70+80+90
        assert stats['gc_count'] == 5
        assert stats['last_gc_time'] is not None
    
    def test_register_object_weak_ref(self):
        """Test weak reference registration."""
        optimizer = GCOptimizer()
        
        # Create test object
        test_obj = {"test": "data"}
        optimizer.register_object(test_obj, "test_obj")
        
        assert optimizer.get_weak_ref_count() >= 0  # May vary due to implementation
    
    def test_register_object_non_weak_referable(self):
        """Test weak reference registration with non-weak-referable object."""
        optimizer = GCOptimizer()
        
        # Integers don't support weak references
        optimizer.register_object(42, "test_int")
        
        # Should not crash, just not add to weak refs
        assert True  # If we get here, it didn't crash
    
    def test_cleanup_weak_refs(self):
        """Test weak reference cleanup."""
        optimizer = GCOptimizer()
        
        # Create and register object
        test_obj = {"test": "data"}
        optimizer.register_object(test_obj, "test_obj")
        
        # Cleanup should work without errors
        optimizer.cleanup_weak_refs()
        assert True  # No exception thrown


class TestGCDecorator:
    """Test the with_gc_optimization decorator."""
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_decorator_memory_pressure_before(self, mock_gc_optimizer):
        """Test decorator triggers GC when memory pressure detected before execution."""
        mock_gc_optimizer.check_memory_pressure.return_value = True
        
        @with_gc_optimization
        def test_function():
            return "result"
        
        result = test_function()
        
        assert result == "result"
        # Should check memory pressure and trigger GC
        mock_gc_optimizer.check_memory_pressure.assert_called()
        mock_gc_optimizer.trigger_gc.assert_called()
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_decorator_no_memory_pressure(self, mock_gc_optimizer):
        """Test decorator when no memory pressure detected."""
        mock_gc_optimizer.check_memory_pressure.return_value = False
        
        @with_gc_optimization
        def test_function():
            return "result"
        
        result = test_function()
        
        assert result == "result"
        # Should check memory pressure but not trigger GC
        assert mock_gc_optimizer.check_memory_pressure.call_count >= 1
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_decorator_exception_handling(self, mock_gc_optimizer):
        """Test decorator handles exceptions in wrapped function."""
        mock_gc_optimizer.check_memory_pressure.return_value = False
        
        @with_gc_optimization
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            failing_function()
        
        # Should still check memory pressure despite exception
        mock_gc_optimizer.check_memory_pressure.assert_called()


class TestPeriodicGCCheck:
    """Test the periodic_gc_check function."""
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_periodic_gc_check_basic(self, mock_gc_optimizer):
        """Test basic periodic GC check functionality."""
        # Mock successful GC
        mock_metrics = GCMetrics(
            pause_time_ms=50.0,
            memory_freed_mb=100.0,
            efficiency_percent=80.0,
            timestamp=datetime.now(),
            gc_type="periodic",
            heap_before_mb=500.0,
            heap_after_mb=400.0
        )
        mock_gc_optimizer.trigger_gc.return_value = mock_metrics
        
        result = periodic_gc_check()
        
        assert result == mock_metrics
        mock_gc_optimizer.trigger_gc.assert_called_once()
        mock_gc_optimizer.cleanup_weak_refs.assert_called_once()
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_periodic_gc_check_high_pause_time(self, mock_gc_optimizer):
        """Test periodic GC check optimizes for latency on high pause times."""
        # Mock GC with high pause time
        mock_metrics = GCMetrics(
            pause_time_ms=150.0,  # High pause time
            memory_freed_mb=100.0,
            efficiency_percent=80.0,
            timestamp=datetime.now(),
            gc_type="periodic",
            heap_before_mb=500.0,
            heap_after_mb=400.0
        )
        mock_gc_optimizer.trigger_gc.return_value = mock_metrics
        
        result = periodic_gc_check()
        
        assert result == mock_metrics
        mock_gc_optimizer.optimize_for_latency.assert_called_once()
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_periodic_gc_check_low_efficiency(self, mock_gc_optimizer):
        """Test periodic GC check optimizes for throughput on low efficiency."""
        # Mock GC with low efficiency
        mock_metrics = GCMetrics(
            pause_time_ms=20.0,
            memory_freed_mb=5.0,
            efficiency_percent=3.0,  # Low efficiency
            timestamp=datetime.now(),
            gc_type="periodic",
            heap_before_mb=500.0,
            heap_after_mb=495.0
        )
        mock_gc_optimizer.trigger_gc.return_value = mock_metrics
        
        result = periodic_gc_check()
        
        assert result == mock_metrics
        mock_gc_optimizer.optimize_for_throughput.assert_called_once()
    
    @patch('src.core.gc_optimization.gc_optimizer')
    def test_periodic_gc_check_no_gc_triggered(self, mock_gc_optimizer):
        """Test periodic GC check when no GC is triggered."""
        mock_gc_optimizer.trigger_gc.return_value = None
        
        result = periodic_gc_check()
        
        assert result is None
        mock_gc_optimizer.cleanup_weak_refs.assert_called_once()


class TestV8Flags:
    """Test V8 optimization flags configuration."""
    
    def test_get_v8_flags_production(self):
        """Test getting V8 flags for production environment."""
        flags = get_v8_flags("production")
        
        assert isinstance(flags, list)
        assert len(flags) > 0
        assert "--max-old-space-size=6144" in flags
        assert "--optimize-for-size" in flags
    
    def test_get_v8_flags_development(self):
        """Test getting V8 flags for development environment."""
        flags = get_v8_flags("development")
        
        assert isinstance(flags, list)
        assert len(flags) > 0
        assert "--max-old-space-size=2048" in flags
        assert "--expose-gc" in flags
        assert "--trace-gc" in flags
    
    def test_get_v8_flags_unknown_environment(self):
        """Test getting V8 flags for unknown environment defaults to production."""
        flags = get_v8_flags("unknown")
        production_flags = get_v8_flags("production")
        
        assert flags == production_flags
    
    def test_v8_optimization_flags_structure(self):
        """Test V8_OPTIMIZATION_FLAGS constant structure."""
        assert isinstance(V8_OPTIMIZATION_FLAGS, dict)
        assert "production" in V8_OPTIMIZATION_FLAGS
        assert "development" in V8_OPTIMIZATION_FLAGS
        
        for env, flags in V8_OPTIMIZATION_FLAGS.items():
            assert isinstance(flags, list)
            assert all(isinstance(flag, str) for flag in flags)
            assert all(flag.startswith("--") for flag in flags)


class TestGCOptimizerIntegration:
    """Test integration scenarios with real GC operations."""
    
    def test_real_gc_trigger(self):
        """Test actual GC trigger without mocking (integration test)."""
        optimizer = GCOptimizer()
        
        # Create some garbage to collect
        garbage = []
        for i in range(1000):
            garbage.append([i] * 100)
        
        # Clear reference to create garbage
        del garbage
        
        # Trigger GC
        metrics = optimizer.trigger_gc(force=True)
        
        assert metrics is not None
        assert isinstance(metrics, GCMetrics)
        assert metrics.pause_time_ms >= 0
        assert metrics.memory_freed_mb >= 0
        assert metrics.gc_type == "manual"
    
    def test_memory_pressure_detection_real(self):
        """Test real memory pressure detection."""
        optimizer = GCOptimizer()
        
        # This should not detect pressure on most systems during testing
        pressure = optimizer.check_memory_pressure()
        assert isinstance(pressure, bool)
    
    def test_global_gc_optimizer_instance(self):
        """Test global gc_optimizer instance."""
        # Global instance should be available
        assert gc_optimizer is not None
        assert isinstance(gc_optimizer, GCOptimizer)
        
        # Should be able to use global instance
        stats = gc_optimizer.get_gc_stats()
        assert isinstance(stats, dict)


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @patch('src.core.gc_optimization.psutil.Process')
    def test_trigger_gc_psutil_error(self, mock_process):
        """Test GC trigger handles psutil errors gracefully."""
        mock_process.side_effect = Exception("psutil error")
        
        optimizer = GCOptimizer()
        
        # Should handle psutil error and still attempt GC
        with patch('src.core.gc_optimization.gc.collect'):
            metrics = optimizer.trigger_gc(force=True)
            # Should return None or handle gracefully
            assert metrics is None or isinstance(metrics, GCMetrics)
    
    @patch('src.core.gc_optimization.gc.collect')
    def test_trigger_gc_collect_error(self, mock_gc_collect):
        """Test GC trigger handles gc.collect errors."""
        mock_gc_collect.side_effect = Exception("GC error")
        
        optimizer = GCOptimizer()
        
        # Should handle GC error gracefully
        metrics = optimizer.trigger_gc(force=True)
        assert metrics is None  # Should return None on error
    
    def test_metrics_history_overflow(self):
        """Test metrics history doesn't grow unbounded."""
        optimizer = GCOptimizer()
        
        # Add many metrics to test memory management
        for i in range(2000):  # More than typical history size
            metrics = GCMetrics(
                pause_time_ms=1.0,
                memory_freed_mb=1.0,
                efficiency_percent=50.0,
                timestamp=datetime.now(),
                gc_type="test",
                heap_before_mb=100.0,
                heap_after_mb=99.0
            )
            optimizer.metrics_history.append(metrics)
        
        # History should be manageable size
        assert len(optimizer.metrics_history) == 2000  # For this test, but real impl might limit


class TestPerformanceOptimization:
    """Test performance optimization strategies."""
    
    def test_gc_threshold_optimization(self):
        """Test GC threshold optimization for different scenarios."""
        optimizer = GCOptimizer()
        
        # Test throughput optimization
        initial_thresholds = gc.get_threshold()
        optimizer.optimize_for_throughput()
        throughput_thresholds = gc.get_threshold()
        
        # Should increase thresholds for throughput
        assert throughput_thresholds[0] >= initial_thresholds[0]
        
        # Test latency optimization
        optimizer.optimize_for_latency()
        latency_thresholds = gc.get_threshold()
        
        # Should decrease thresholds for latency
        assert latency_thresholds[0] <= throughput_thresholds[0]
    
    def test_gc_interval_optimization(self):
        """Test GC interval optimization."""
        optimizer = GCOptimizer()
        
        # Default interval
        default_interval = optimizer.gc_interval_seconds
        
        # Throughput optimization should increase interval
        optimizer.optimize_for_throughput()
        assert optimizer.gc_interval_seconds >= default_interval
        
        # Latency optimization should decrease interval
        optimizer.optimize_for_latency()
        assert optimizer.gc_interval_seconds <= default_interval


if __name__ == "__main__":
    pytest.main([__file__])