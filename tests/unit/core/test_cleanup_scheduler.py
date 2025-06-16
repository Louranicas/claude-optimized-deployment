"""
Comprehensive test suite for cleanup_scheduler module.

Tests cover:
- CleanupTask functionality and validation
- CleanupStats metrics and calculations
- CleanupScheduler lifecycle management
- Task registration and execution
- Priority-based scheduling
- Memory monitoring and alerts
- Error handling and retry logic
- Object cleanup on shutdown
- Performance and timing scenarios
- Global scheduler instance management
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any

from src.core.cleanup_scheduler import (
    TaskPriority,
    CleanupTask,
    CleanupStats,
    CleanupScheduler,
    get_cleanup_scheduler,
    initialize_cleanup_scheduler,
    shutdown_cleanup_scheduler
)


class TestTaskPriority:
    """Test TaskPriority enum functionality."""
    
    def test_priority_values(self):
        """Test that priority values are correctly defined."""
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.MEDIUM.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4
    
    def test_priority_ordering(self):
        """Test that priorities can be ordered correctly."""
        priorities = [TaskPriority.HIGH, TaskPriority.LOW, TaskPriority.CRITICAL, TaskPriority.MEDIUM]
        sorted_priorities = sorted(priorities, key=lambda p: p.value)
        
        expected = [TaskPriority.LOW, TaskPriority.MEDIUM, TaskPriority.HIGH, TaskPriority.CRITICAL]
        assert sorted_priorities == expected


class TestCleanupTask:
    """Test CleanupTask dataclass functionality."""
    
    def test_task_creation_minimal(self):
        """Test creating task with minimal parameters."""
        callback = Mock()
        task = CleanupTask(
            name="test_task",
            callback=callback,
            interval_seconds=60.0
        )
        
        assert task.name == "test_task"
        assert task.callback == callback
        assert task.interval_seconds == 60.0
        assert task.priority == TaskPriority.MEDIUM
        assert task.last_run is None
        assert task.enabled is True
        assert task.max_duration is None
        assert task.error_count == 0
        assert task.max_errors == 3
        assert task.metadata == {}
    
    def test_task_creation_full(self):
        """Test creating task with all parameters."""
        callback = Mock()
        metadata = {"source": "test", "version": "1.0"}
        
        task = CleanupTask(
            name="full_task",
            callback=callback,
            interval_seconds=30.0,
            priority=TaskPriority.HIGH,
            last_run=datetime.utcnow(),
            enabled=False,
            max_duration=10.0,
            error_count=2,
            max_errors=5,
            metadata=metadata
        )
        
        assert task.name == "full_task"
        assert task.priority == TaskPriority.HIGH
        assert task.enabled is False
        assert task.max_duration == 10.0
        assert task.error_count == 2
        assert task.max_errors == 5
        assert task.metadata == metadata
    
    def test_is_due_never_run(self):
        """Test is_due returns True for task that never ran."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0
        )
        
        assert task.is_due() is True
    
    def test_is_due_recently_run(self):
        """Test is_due returns False for recently run task."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            last_run=datetime.utcnow()  # Just ran
        )
        
        assert task.is_due() is False
    
    def test_is_due_old_run(self):
        """Test is_due returns True for task that ran long ago."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            last_run=datetime.utcnow() - timedelta(seconds=120)  # 2 minutes ago
        )
        
        assert task.is_due() is True
    
    def test_is_due_disabled_task(self):
        """Test is_due returns False for disabled task."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            enabled=False
        )
        
        assert task.is_due() is False
    
    def test_should_skip_no_errors(self):
        """Test should_skip returns False when error count is below max."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            error_count=1,
            max_errors=3
        )
        
        assert task.should_skip() is False
    
    def test_should_skip_max_errors(self):
        """Test should_skip returns True when error count reaches max."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            error_count=3,
            max_errors=3
        )
        
        assert task.should_skip() is True
    
    def test_should_skip_over_max_errors(self):
        """Test should_skip returns True when error count exceeds max."""
        task = CleanupTask(
            name="test",
            callback=Mock(),
            interval_seconds=60.0,
            error_count=5,
            max_errors=3
        )
        
        assert task.should_skip() is True


class TestCleanupStats:
    """Test CleanupStats dataclass functionality."""
    
    def test_stats_creation_default(self):
        """Test creating stats with default values."""
        stats = CleanupStats()
        
        assert stats.total_tasks == 0
        assert stats.completed_tasks == 0
        assert stats.failed_tasks == 0
        assert stats.total_duration == 0.0
        assert stats.memory_freed_mb == 0.0
        assert stats.items_cleaned == 0
    
    def test_stats_creation_custom(self):
        """Test creating stats with custom values."""
        stats = CleanupStats(
            total_tasks=100,
            completed_tasks=95,
            failed_tasks=5,
            total_duration=120.5,
            memory_freed_mb=25.3,
            items_cleaned=1500
        )
        
        assert stats.total_tasks == 100
        assert stats.completed_tasks == 95
        assert stats.failed_tasks == 5
        assert stats.total_duration == 120.5
        assert stats.memory_freed_mb == 25.3
        assert stats.items_cleaned == 1500
    
    def test_to_dict_basic(self):
        """Test converting stats to dictionary."""
        stats = CleanupStats(
            total_tasks=10,
            completed_tasks=8,
            failed_tasks=2,
            total_duration=50.0
        )
        
        result = stats.to_dict()
        
        assert result["total_tasks"] == 10
        assert result["completed_tasks"] == 8
        assert result["failed_tasks"] == 2
        assert result["success_rate"] == 0.8  # 8/10
        assert result["total_duration"] == 50.0
        assert result["average_duration"] == 6.25  # 50/8
        assert result["memory_freed_mb"] == 0.0
        assert result["items_cleaned"] == 0
    
    def test_to_dict_zero_division_protection(self):
        """Test to_dict handles zero division correctly."""
        stats = CleanupStats()  # All zeros
        
        result = stats.to_dict()
        
        assert result["success_rate"] == 0.0  # 0/1 (protected)
        assert result["average_duration"] == 0.0  # 0/1 (protected)
    
    def test_to_dict_with_data(self):
        """Test to_dict with realistic data."""
        stats = CleanupStats(
            total_tasks=50,
            completed_tasks=47,
            failed_tasks=3,
            total_duration=150.75,
            memory_freed_mb=128.5,
            items_cleaned=2500
        )
        
        result = stats.to_dict()
        
        assert result["success_rate"] == 0.94  # 47/50
        assert result["average_duration"] == pytest.approx(3.208, rel=1e-3)  # 150.75/47
        assert result["memory_freed_mb"] == 128.5
        assert result["items_cleaned"] == 2500


class TestCleanupScheduler:
    """Test CleanupScheduler functionality."""
    
    @pytest.fixture
    def scheduler(self):
        """Create a scheduler instance for testing."""
        return CleanupScheduler(
            check_interval=1.0,
            memory_threshold_mb=50.0,
            enable_memory_alerts=True
        )
    
    @pytest.fixture
    def mock_callback(self):
        """Create a mock callback function."""
        return Mock()
    
    @pytest.fixture
    def mock_async_callback(self):
        """Create a mock async callback function."""
        return AsyncMock()
    
    def test_scheduler_initialization(self, scheduler):
        """Test scheduler initialization with parameters."""
        assert scheduler.check_interval == 1.0
        assert scheduler.memory_threshold_mb == 50.0
        assert scheduler.enable_memory_alerts is True
        assert scheduler.tasks == {}
        assert isinstance(scheduler.stats, CleanupStats)
        assert scheduler.running is False
        assert scheduler.scheduler_task is None
        assert scheduler.cleanable_objects == set()
        assert scheduler.alert_callbacks == []
    
    def test_scheduler_default_initialization(self):
        """Test scheduler initialization with default parameters."""
        scheduler = CleanupScheduler()
        
        assert scheduler.check_interval == 10.0
        assert scheduler.memory_threshold_mb == 100.0
        assert scheduler.enable_memory_alerts is True
    
    def test_register_task_basic(self, scheduler, mock_callback):
        """Test registering a basic task."""
        scheduler.register_task(
            name="test_task",
            callback=mock_callback,
            interval_seconds=30.0
        )
        
        assert "test_task" in scheduler.tasks
        task = scheduler.tasks["test_task"]
        assert task.name == "test_task"
        assert task.callback == mock_callback
        assert task.interval_seconds == 30.0
        assert task.priority == TaskPriority.MEDIUM
        assert task.max_duration is None
        assert task.metadata == {}
    
    def test_register_task_full_params(self, scheduler, mock_callback):
        """Test registering task with all parameters."""
        metadata = {"source": "test", "version": "1.0"}
        
        scheduler.register_task(
            name="full_task",
            callback=mock_callback,
            interval_seconds=60.0,
            priority=TaskPriority.HIGH,
            max_duration=30.0,
            **metadata
        )
        
        task = scheduler.tasks["full_task"]
        assert task.priority == TaskPriority.HIGH
        assert task.max_duration == 30.0
        assert task.metadata == metadata
    
    def test_register_task_replace_existing(self, scheduler, mock_callback, caplog):
        """Test replacing an existing task."""
        # Register first task
        scheduler.register_task("task", mock_callback, 30.0)
        first_task = scheduler.tasks["task"]
        
        # Register second task with same name
        new_callback = Mock()
        scheduler.register_task("task", new_callback, 60.0)
        
        # Should replace the first task
        assert scheduler.tasks["task"].callback == new_callback
        assert scheduler.tasks["task"].interval_seconds == 60.0
        assert "already registered, replacing" in caplog.text
    
    def test_unregister_task_existing(self, scheduler, mock_callback):
        """Test unregistering an existing task."""
        scheduler.register_task("task", mock_callback, 30.0)
        assert "task" in scheduler.tasks
        
        result = scheduler.unregister_task("task")
        
        assert result is True
        assert "task" not in scheduler.tasks
    
    def test_unregister_task_nonexistent(self, scheduler):
        """Test unregistering a non-existent task."""
        result = scheduler.unregister_task("nonexistent")
        assert result is False
    
    def test_enable_task(self, scheduler, mock_callback):
        """Test enabling a task."""
        scheduler.register_task("task", mock_callback, 30.0)
        scheduler.tasks["task"].enabled = False
        
        result = scheduler.enable_task("task")
        
        assert result is True
        assert scheduler.tasks["task"].enabled is True
    
    def test_enable_task_nonexistent(self, scheduler):
        """Test enabling a non-existent task."""
        result = scheduler.enable_task("nonexistent")
        assert result is False
    
    def test_disable_task(self, scheduler, mock_callback):
        """Test disabling a task."""
        scheduler.register_task("task", mock_callback, 30.0)
        
        result = scheduler.disable_task("task")
        
        assert result is True
        assert scheduler.tasks["task"].enabled is False
    
    def test_disable_task_nonexistent(self, scheduler):
        """Test disabling a non-existent task."""
        result = scheduler.disable_task("nonexistent")
        assert result is False
    
    def test_register_cleanable_object_with_cleanup(self, scheduler):
        """Test registering object with cleanup method."""
        obj = Mock()
        obj.cleanup = Mock()
        
        scheduler.register_cleanable_object(obj)
        
        assert len(scheduler.cleanable_objects) == 1
    
    def test_register_cleanable_object_with_close(self, scheduler):
        """Test registering object with close method."""
        obj = Mock()
        obj.close = Mock()
        
        scheduler.register_cleanable_object(obj)
        
        assert len(scheduler.cleanable_objects) == 1
    
    def test_register_cleanable_object_no_methods(self, scheduler, caplog):
        """Test registering object without cleanup/close methods."""
        obj = Mock(spec=[])  # No cleanup or close methods
        
        scheduler.register_cleanable_object(obj)
        
        assert len(scheduler.cleanable_objects) == 0
        assert "has no cleanup/close method" in caplog.text
    
    def test_add_alert_callback(self, scheduler):
        """Test adding alert callback."""
        callback = Mock()
        
        scheduler.add_alert_callback(callback)
        
        assert callback in scheduler.alert_callbacks
    
    @pytest.mark.asyncio
    async def test_trigger_alert_sync_callback(self, scheduler):
        """Test triggering alert with sync callback."""
        callback = Mock()
        scheduler.add_alert_callback(callback)
        
        await scheduler._trigger_alert("test_alert", {"data": "test"})
        
        callback.assert_called_once_with("test_alert", {"data": "test"})
    
    @pytest.mark.asyncio
    async def test_trigger_alert_async_callback(self, scheduler):
        """Test triggering alert with async callback."""
        callback = AsyncMock()
        scheduler.add_alert_callback(callback)
        
        await scheduler._trigger_alert("test_alert", {"data": "test"})
        
        callback.assert_called_once_with("test_alert", {"data": "test"})
    
    @pytest.mark.asyncio
    async def test_trigger_alert_callback_error(self, scheduler, caplog):
        """Test triggering alert when callback raises error."""
        def failing_callback(alert_type, data):
            raise ValueError("Callback failed")
        
        scheduler.add_alert_callback(failing_callback)
        
        await scheduler._trigger_alert("test_alert", {"data": "test"})
        
        assert "Alert callback error" in caplog.text
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_disabled(self, scheduler):
        """Test memory check when disabled."""
        scheduler.enable_memory_alerts = False
        
        # Should not raise any errors
        await scheduler._check_memory_usage()
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_too_soon(self, scheduler):
        """Test memory check called too soon after last check."""
        scheduler.last_memory_check = time.time()  # Just checked
        
        with patch('psutil.Process') as mock_process:
            await scheduler._check_memory_usage()
            
            # Should not check memory (too soon)
            mock_process.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_under_threshold(self, scheduler):
        """Test memory check when under threshold."""
        scheduler.last_memory_check = 0  # Force check
        
        with patch('psutil.Process') as mock_process:
            mock_memory_info = Mock()
            mock_memory_info.rss = 30 * 1024 * 1024  # 30MB
            mock_process.return_value.memory_info.return_value = mock_memory_info
            
            await scheduler._check_memory_usage()
            
            # Should not trigger alert (under 50MB threshold)
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_over_threshold(self, scheduler):
        """Test memory check when over threshold."""
        scheduler.last_memory_check = 0  # Force check
        alert_callback = Mock()
        scheduler.add_alert_callback(alert_callback)
        
        with patch('psutil.Process') as mock_process:
            mock_memory_info = Mock()
            mock_memory_info.rss = 100 * 1024 * 1024  # 100MB (over 50MB threshold)
            mock_process.return_value.memory_info.return_value = mock_memory_info
            
            await scheduler._check_memory_usage()
            
            # Should trigger alert
            alert_callback.assert_called_once()
            call_args = alert_callback.call_args
            assert call_args[0][0] == "memory_threshold_exceeded"
            assert call_args[0][1]["current_memory_mb"] == 100.0
            assert call_args[0][1]["threshold_mb"] == 50.0
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_psutil_not_available(self, scheduler):
        """Test memory check when psutil is not available."""
        scheduler.last_memory_check = 0  # Force check
        
        with patch('psutil.Process', side_effect=ImportError):
            # Should not raise error
            await scheduler._check_memory_usage()
    
    @pytest.mark.asyncio
    async def test_check_memory_usage_error(self, scheduler, caplog):
        """Test memory check when psutil raises error."""
        scheduler.last_memory_check = 0  # Force check
        
        with patch('psutil.Process', side_effect=Exception("Process error")):
            await scheduler._check_memory_usage()
            
            assert "Memory check error" in caplog.text
    
    @pytest.mark.asyncio
    async def test_execute_task_sync_success(self, scheduler, mock_callback):
        """Test executing sync task successfully."""
        task = CleanupTask("test", mock_callback, 30.0)
        
        result = await scheduler._execute_task(task)
        
        assert result is True
        assert task.last_run is not None
        assert task.error_count == 0
        assert scheduler.stats.completed_tasks == 1
        assert scheduler.stats.total_duration > 0
        mock_callback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_task_async_success(self, scheduler, mock_async_callback):
        """Test executing async task successfully."""
        task = CleanupTask("test", mock_async_callback, 30.0)
        
        result = await scheduler._execute_task(task)
        
        assert result is True
        assert task.last_run is not None
        assert task.error_count == 0
        assert scheduler.stats.completed_tasks == 1
        mock_async_callback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_task_should_skip(self, scheduler, mock_callback):
        """Test executing task that should be skipped."""
        task = CleanupTask("test", mock_callback, 30.0, error_count=5, max_errors=3)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        assert task.last_run is None  # Should not update last_run
        mock_callback.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_execute_task_sync_timeout(self, scheduler):
        """Test executing sync task that times out."""
        def slow_callback():
            time.sleep(2)  # Longer than max_duration
        
        task = CleanupTask("test", slow_callback, 30.0, max_duration=0.1)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        assert task.error_count == 1
        assert scheduler.stats.failed_tasks == 1
    
    @pytest.mark.asyncio
    async def test_execute_task_async_timeout(self, scheduler):
        """Test executing async task that times out."""
        async def slow_callback():
            await asyncio.sleep(2)  # Longer than max_duration
        
        task = CleanupTask("test", slow_callback, 30.0, max_duration=0.1)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        assert task.error_count == 1
        assert scheduler.stats.failed_tasks == 1
    
    @pytest.mark.asyncio
    async def test_execute_task_sync_error(self, scheduler):
        """Test executing sync task that raises error."""
        def failing_callback():
            raise ValueError("Task failed")
        
        task = CleanupTask("test", failing_callback, 30.0)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        assert task.error_count == 1
        assert scheduler.stats.failed_tasks == 1
    
    @pytest.mark.asyncio
    async def test_execute_task_async_error(self, scheduler):
        """Test executing async task that raises error."""
        async def failing_callback():
            raise ValueError("Task failed")
        
        task = CleanupTask("test", failing_callback, 30.0)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        assert task.error_count == 1
        assert scheduler.stats.failed_tasks == 1
    
    @pytest.mark.asyncio
    async def test_execute_task_critical_failure_alert(self, scheduler):
        """Test that critical task failures trigger alerts."""
        async def failing_callback():
            raise ValueError("Critical task failed")
        
        task = CleanupTask("critical_task", failing_callback, 30.0, priority=TaskPriority.CRITICAL)
        alert_callback = Mock()
        scheduler.add_alert_callback(alert_callback)
        
        result = await scheduler._execute_task(task)
        
        assert result is False
        alert_callback.assert_called_once()
        call_args = alert_callback.call_args
        assert call_args[0][0] == "critical_task_failed"
        assert call_args[0][1]["task_name"] == "critical_task"
    
    @pytest.mark.asyncio
    async def test_execute_task_reset_error_count_on_success(self, scheduler, mock_callback):
        """Test that error count is reset on successful execution."""
        task = CleanupTask("test", mock_callback, 30.0, error_count=2)
        
        result = await scheduler._execute_task(task)
        
        assert result is True
        assert task.error_count == 0  # Should be reset
    
    @pytest.mark.asyncio
    async def test_start_scheduler(self, scheduler):
        """Test starting the scheduler."""
        assert scheduler.running is False
        assert scheduler.scheduler_task is None
        
        await scheduler.start()
        
        assert scheduler.running is True
        assert scheduler.scheduler_task is not None
        assert isinstance(scheduler.scheduler_task, asyncio.Task)
        
        # Clean up
        await scheduler.stop()
    
    @pytest.mark.asyncio
    async def test_start_scheduler_already_running(self, scheduler, caplog):
        """Test starting scheduler when already running."""
        await scheduler.start()
        
        # Try to start again
        await scheduler.start()
        
        assert "already running" in caplog.text
        
        # Clean up
        await scheduler.stop()
    
    @pytest.mark.asyncio
    async def test_stop_scheduler(self, scheduler):
        """Test stopping the scheduler."""
        await scheduler.start()
        assert scheduler.running is True
        
        await scheduler.stop()
        
        assert scheduler.running is False
        assert scheduler.scheduler_task.cancelled()
    
    @pytest.mark.asyncio
    async def test_stop_scheduler_not_running(self, scheduler):
        """Test stopping scheduler when not running."""
        assert scheduler.running is False
        
        # Should not raise error
        await scheduler.stop()
        
        assert scheduler.running is False
    
    @pytest.mark.asyncio
    async def test_cleanup_registered_objects(self, scheduler):
        """Test cleanup of registered objects."""
        # Create objects with cleanup methods
        obj1 = Mock()
        obj1.cleanup = Mock()
        
        obj2 = Mock()
        obj2.close = Mock()
        
        scheduler.register_cleanable_object(obj1)
        scheduler.register_cleanable_object(obj2)
        
        await scheduler._cleanup_registered_objects()
        
        obj1.cleanup.assert_called_once()
        obj2.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_registered_objects_async(self, scheduler):
        """Test cleanup of registered objects with async methods."""
        obj = Mock()
        obj.cleanup = AsyncMock()
        
        scheduler.register_cleanable_object(obj)
        
        await scheduler._cleanup_registered_objects()
        
        obj.cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_registered_objects_error(self, scheduler, caplog):
        """Test cleanup when object cleanup raises error."""
        obj = Mock()
        obj.cleanup = Mock(side_effect=Exception("Cleanup failed"))
        
        scheduler.register_cleanable_object(obj)
        
        await scheduler._cleanup_registered_objects()
        
        assert "Error cleaning up object" in caplog.text
    
    @pytest.mark.asyncio
    async def test_cleanup_registered_objects_garbage_collected(self, scheduler):
        """Test cleanup when objects have been garbage collected."""
        # Create weak reference to None (simulating GC'd object)
        import weakref
        fake_ref = weakref.ref(lambda: None)  # Will return None when called
        scheduler.cleanable_objects.add(fake_ref)
        
        initial_count = len(scheduler.cleanable_objects)
        await scheduler._cleanup_registered_objects()
        
        # Should remove dead references
        assert len(scheduler.cleanable_objects) < initial_count
    
    @pytest.mark.asyncio
    async def test_run_task_now_success(self, scheduler, mock_callback):
        """Test running a specific task immediately."""
        scheduler.register_task("test_task", mock_callback, 30.0)
        
        result = await scheduler.run_task_now("test_task")
        
        assert result is True
        assert scheduler.stats.total_tasks == 1
        mock_callback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_task_now_not_found(self, scheduler):
        """Test running a non-existent task."""
        result = await scheduler.run_task_now("nonexistent")
        
        assert result is False
        assert scheduler.stats.total_tasks == 0
    
    def test_get_task_status(self, scheduler, mock_callback):
        """Test getting task status."""
        scheduler.register_task("test_task", mock_callback, 30.0, priority=TaskPriority.HIGH)
        
        status = scheduler.get_task_status()
        
        assert "test_task" in status
        task_status = status["test_task"]
        assert task_status["enabled"] is True
        assert task_status["priority"] == TaskPriority.HIGH.value
        assert task_status["interval_seconds"] == 30.0
        assert task_status["last_run"] is None
        assert task_status["error_count"] == 0
        assert task_status["max_errors"] == 3
        assert task_status["is_due"] is True
        assert task_status["should_skip"] is False
        assert task_status["metadata"] == {}
    
    def test_get_task_status_with_last_run(self, scheduler, mock_callback):
        """Test getting task status with last_run timestamp."""
        last_run = datetime.utcnow()
        scheduler.register_task("test_task", mock_callback, 30.0)
        scheduler.tasks["test_task"].last_run = last_run
        
        status = scheduler.get_task_status()
        
        assert status["test_task"]["last_run"] == last_run.isoformat()
    
    def test_get_stats(self, scheduler):
        """Test getting scheduler statistics."""
        scheduler.stats.total_tasks = 10
        scheduler.stats.completed_tasks = 8
        
        stats = scheduler.get_stats()
        
        assert stats["running"] is False
        assert stats["task_count"] == 0
        assert stats["cleanable_objects"] == 0
        assert stats["memory_threshold_mb"] == 50.0
        assert stats["check_interval"] == 1.0
        assert "stats" in stats
        assert stats["stats"]["total_tasks"] == 10
        assert stats["stats"]["completed_tasks"] == 8


class TestSchedulerLoop:
    """Test scheduler loop functionality."""
    
    @pytest.fixture
    def scheduler(self):
        """Create a scheduler with short intervals for testing."""
        return CleanupScheduler(check_interval=0.1, memory_threshold_mb=50.0)
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_basic(self, scheduler):
        """Test basic scheduler loop execution."""
        callback = Mock()
        scheduler.register_task("test_task", callback, 0.01)  # Very short interval
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for task to execute
        await asyncio.sleep(0.2)
        
        # Stop scheduler
        await scheduler.stop()
        
        # Task should have been executed
        assert callback.called
        assert scheduler.stats.total_tasks > 0
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_priority_ordering(self, scheduler):
        """Test that tasks are executed in priority order."""
        call_order = []
        
        def low_priority():
            call_order.append("low")
        
        def high_priority():
            call_order.append("high")
        
        def critical_priority():
            call_order.append("critical")
        
        # Register tasks (in reverse priority order)
        scheduler.register_task("low", low_priority, 0.01, TaskPriority.LOW)
        scheduler.register_task("high", high_priority, 0.01, TaskPriority.HIGH)
        scheduler.register_task("critical", critical_priority, 0.01, TaskPriority.CRITICAL)
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for tasks to execute
        await asyncio.sleep(0.2)
        
        # Stop scheduler
        await scheduler.stop()
        
        # Should execute in priority order (highest first)
        assert len(call_order) >= 3
        # First three executions should be in priority order
        assert call_order[:3] == ["critical", "high", "low"]
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_error_handling(self, scheduler, caplog):
        """Test scheduler loop handles errors gracefully."""
        def failing_task():
            raise ValueError("Task failed")
        
        scheduler.register_task("failing_task", failing_task, 0.01)
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for task to execute and fail
        await asyncio.sleep(0.2)
        
        # Stop scheduler
        await scheduler.stop()
        
        # Should log error but continue running
        assert "failed" in caplog.text
        assert scheduler.stats.failed_tasks > 0
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_memory_monitoring(self, scheduler):
        """Test that scheduler loop performs memory monitoring."""
        scheduler.memory_check_interval = 0.05  # Check more frequently
        scheduler.last_memory_check = 0  # Force check
        
        with patch.object(scheduler, '_check_memory_usage') as mock_check:
            mock_check.return_value = None
            
            # Start scheduler
            await scheduler.start()
            
            # Wait for memory check
            await asyncio.sleep(0.2)
            
            # Stop scheduler
            await scheduler.stop()
            
            # Memory check should have been called
            assert mock_check.called
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_cancellation(self, scheduler):
        """Test scheduler loop handles cancellation properly."""
        await scheduler.start()
        
        # Cancel the scheduler task directly
        scheduler.scheduler_task.cancel()
        
        # Wait for cancellation to take effect
        await asyncio.sleep(0.1)
        
        # Should handle cancellation gracefully
        assert scheduler.scheduler_task.cancelled()


class TestGlobalSchedulerFunctions:
    """Test global scheduler instance functions."""
    
    def teardown_method(self):
        """Clean up global scheduler after each test."""
        # Reset global scheduler
        import src.core.cleanup_scheduler
        src.core.cleanup_scheduler._cleanup_scheduler = None
    
    def test_get_cleanup_scheduler_creates_instance(self):
        """Test that get_cleanup_scheduler creates instance if none exists."""
        scheduler = get_cleanup_scheduler()
        
        assert isinstance(scheduler, CleanupScheduler)
        assert scheduler.check_interval == 10.0  # Default value
    
    def test_get_cleanup_scheduler_returns_same_instance(self):
        """Test that multiple calls return the same instance."""
        scheduler1 = get_cleanup_scheduler()
        scheduler2 = get_cleanup_scheduler()
        
        assert scheduler1 is scheduler2
    
    @pytest.mark.asyncio
    async def test_initialize_cleanup_scheduler_without_auto_start(self):
        """Test initializing scheduler without auto-start."""
        scheduler = await initialize_cleanup_scheduler(
            check_interval=5.0,
            memory_threshold_mb=200.0,
            auto_start=False
        )
        
        assert isinstance(scheduler, CleanupScheduler)
        assert scheduler.check_interval == 5.0
        assert scheduler.memory_threshold_mb == 200.0
        assert scheduler.running is False
    
    @pytest.mark.asyncio
    async def test_initialize_cleanup_scheduler_with_auto_start(self):
        """Test initializing scheduler with auto-start."""
        scheduler = await initialize_cleanup_scheduler(
            check_interval=5.0,
            memory_threshold_mb=200.0,
            auto_start=True
        )
        
        assert scheduler.running is True
        
        # Clean up
        await scheduler.stop()
    
    @pytest.mark.asyncio
    async def test_shutdown_cleanup_scheduler(self):
        """Test shutting down global scheduler."""
        # Initialize scheduler
        scheduler = await initialize_cleanup_scheduler(auto_start=True)
        assert scheduler.running is True
        
        # Shutdown
        await shutdown_cleanup_scheduler()
        
        # Should be stopped and reset
        assert scheduler.running is False
        
        # Global instance should be reset
        import src.core.cleanup_scheduler
        assert src.core.cleanup_scheduler._cleanup_scheduler is None
    
    @pytest.mark.asyncio
    async def test_shutdown_cleanup_scheduler_none(self):
        """Test shutting down when no global scheduler exists."""
        # Should not raise error
        await shutdown_cleanup_scheduler()


class TestPerformanceAndTiming:
    """Test performance and timing scenarios."""
    
    @pytest.fixture
    def scheduler(self):
        """Create scheduler for performance testing."""
        return CleanupScheduler(check_interval=0.01, memory_threshold_mb=50.0)
    
    @pytest.mark.asyncio
    async def test_many_tasks_performance(self, scheduler):
        """Test scheduler performance with many tasks."""
        # Register many tasks
        for i in range(50):
            callback = Mock()
            scheduler.register_task(f"task_{i}", callback, 0.1)
        
        start_time = time.time()
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for some executions
        await asyncio.sleep(0.5)
        
        # Stop scheduler
        await scheduler.stop()
        
        end_time = time.time()
        
        # Should complete in reasonable time
        assert end_time - start_time < 2.0
        assert scheduler.stats.total_tasks > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_task_execution(self, scheduler):
        """Test that multiple tasks can execute concurrently."""
        execution_times = []
        
        async def slow_task(task_id):
            start = time.time()
            await asyncio.sleep(0.1)
            end = time.time()
            execution_times.append((task_id, start, end))
        
        # Register multiple slow tasks
        for i in range(3):
            scheduler.register_task(f"slow_task_{i}", lambda i=i: asyncio.create_task(slow_task(i)), 0.01)
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for tasks to execute
        await asyncio.sleep(0.5)
        
        # Stop scheduler
        await scheduler.stop()
        
        # Should have executed tasks (though they may overlap due to async execution)
        assert len(execution_times) >= 3
    
    @pytest.mark.asyncio
    async def test_memory_monitoring_frequency(self, scheduler):
        """Test memory monitoring doesn't happen too frequently."""
        scheduler.memory_check_interval = 1.0  # Only check every second
        
        with patch.object(scheduler, '_check_memory_usage') as mock_check:
            mock_check.return_value = None
            
            # Start scheduler
            await scheduler.start()
            
            # Wait for multiple check intervals
            await asyncio.sleep(0.3)  # Less than memory check interval
            
            # Stop scheduler
            await scheduler.stop()
            
            # Should not have called memory check (too soon)
            assert mock_check.call_count <= 1  # At most once


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def scheduler(self):
        """Create scheduler for edge case testing."""
        return CleanupScheduler(check_interval=0.1)
    
    @pytest.mark.asyncio
    async def test_task_with_zero_interval(self, scheduler, mock_callback):
        """Test task with zero interval (should always be due)."""
        scheduler.register_task("zero_interval", mock_callback, 0.0)
        
        task = scheduler.tasks["zero_interval"]
        task.last_run = datetime.utcnow()  # Just ran
        
        # Should still be due (zero interval)
        assert task.is_due() is True
    
    @pytest.mark.asyncio
    async def test_task_with_negative_interval(self, scheduler, mock_callback):
        """Test task with negative interval (should always be due)."""
        scheduler.register_task("negative_interval", mock_callback, -10.0)
        
        task = scheduler.tasks["negative_interval"]
        task.last_run = datetime.utcnow()  # Just ran
        
        # Should still be due (negative interval)
        assert task.is_due() is True
    
    @pytest.mark.asyncio
    async def test_scheduler_loop_exception_handling(self, scheduler, caplog):
        """Test scheduler loop handles unexpected exceptions."""
        # Mock scheduler methods to raise exception
        original_check_memory = scheduler._check_memory_usage
        
        def failing_memory_check():
            raise RuntimeError("Unexpected error")
        
        scheduler._check_memory_usage = failing_memory_check
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for error to occur
        await asyncio.sleep(0.2)
        
        # Stop scheduler
        await scheduler.stop()
        
        # Should log error and continue
        assert "Scheduler loop error" in caplog.text
    
    @pytest.mark.asyncio
    async def test_task_callback_none(self, scheduler):
        """Test task with None callback."""
        with pytest.raises(Exception):
            # This should fail when trying to call None
            task = CleanupTask("none_callback", None, 30.0)
            await scheduler._execute_task(task)
    
    def test_task_very_long_name(self, scheduler, mock_callback):
        """Test task with very long name."""
        long_name = "x" * 1000
        
        scheduler.register_task(long_name, mock_callback, 30.0)
        
        assert long_name in scheduler.tasks
    
    def test_task_metadata_with_complex_objects(self, scheduler, mock_callback):
        """Test task metadata with complex objects."""
        complex_metadata = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "function": lambda x: x * 2
        }
        
        scheduler.register_task("complex_task", mock_callback, 30.0, **complex_metadata)
        
        task = scheduler.tasks["complex_task"]
        assert task.metadata["nested"]["key"] == "value"
        assert task.metadata["list"] == [1, 2, 3]
        assert callable(task.metadata["function"])
    
    @pytest.mark.asyncio
    async def test_cleanup_objects_with_no_references(self, scheduler):
        """Test cleanup when all object references are dead."""
        # Add dead references manually
        import weakref
        
        dead_refs = []
        for _ in range(5):
            dead_refs.append(weakref.ref(lambda: None))
        
        scheduler.cleanable_objects.update(dead_refs)
        
        initial_count = len(scheduler.cleanable_objects)
        await scheduler._cleanup_registered_objects()
        
        # All dead references should be removed
        assert len(scheduler.cleanable_objects) == 0
    
    @pytest.mark.asyncio
    async def test_stop_scheduler_during_task_execution(self, scheduler):
        """Test stopping scheduler while task is executing."""
        async def long_running_task():
            await asyncio.sleep(1.0)  # Longer than test duration
        
        scheduler.register_task("long_task", long_running_task, 0.01)
        
        # Start scheduler
        await scheduler.start()
        
        # Wait for task to start
        await asyncio.sleep(0.1)
        
        # Stop scheduler (should cancel running tasks)
        await scheduler.stop()
        
        # Should stop cleanly
        assert scheduler.running is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.core.cleanup_scheduler", "--cov-report=term-missing"])