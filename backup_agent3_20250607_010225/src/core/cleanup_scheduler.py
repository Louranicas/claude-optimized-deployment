"""
Cleanup Scheduler for periodic maintenance of bounded data structures.

This module provides a centralized scheduler for:
- Cache cleanup and TTL expiration
- Memory monitoring and alerts
- Periodic maintenance tasks
- Resource cleanup on shutdown
"""

from __future__ import annotations
import asyncio
import logging
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set
import time
from enum import Enum

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """Priority levels for cleanup tasks."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class CleanupTask:
    """Represents a cleanup task."""
    name: str
    callback: Callable[[], Any]
    interval_seconds: float
    priority: TaskPriority = TaskPriority.MEDIUM
    last_run: Optional[datetime] = None
    enabled: bool = True
    max_duration: Optional[float] = None  # Max execution time in seconds
    error_count: int = 0
    max_errors: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_due(self) -> bool:
        """Check if task is due to run."""
        if not self.enabled:
            return False
        
        if self.last_run is None:
            return True
        
        elapsed = datetime.utcnow() - self.last_run
        return elapsed.total_seconds() >= self.interval_seconds
    
    def should_skip(self) -> bool:
        """Check if task should be skipped due to errors."""
        return self.error_count >= self.max_errors


@dataclass
class CleanupStats:
    """Statistics for cleanup operations."""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_duration: float = 0.0
    memory_freed_mb: float = 0.0
    items_cleaned: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": self.completed_tasks / max(self.total_tasks, 1),
            "total_duration": self.total_duration,
            "average_duration": self.total_duration / max(self.completed_tasks, 1),
            "memory_freed_mb": self.memory_freed_mb,
            "items_cleaned": self.items_cleaned
        }


class CleanupScheduler:
    """
    Centralized scheduler for cleanup tasks.
    
    Features:
    - Periodic task execution
    - Priority-based scheduling
    - Error handling and retry logic
    - Memory monitoring
    - Performance statistics
    """
    
    def __init__(
        self,
        check_interval: float = 10.0,
        memory_threshold_mb: float = 100.0,
        enable_memory_alerts: bool = True
    ):
        """
        Initialize cleanup scheduler.
        
        Args:
            check_interval: How often to check for due tasks (seconds)
            memory_threshold_mb: Memory threshold for alerts (MB)
            enable_memory_alerts: Whether to enable memory monitoring
        """
        self.check_interval = check_interval
        self.memory_threshold_mb = memory_threshold_mb
        self.enable_memory_alerts = enable_memory_alerts
        
        self.tasks: Dict[str, CleanupTask] = {}
        self.stats = CleanupStats()
        self.running = False
        self.scheduler_task: Optional[asyncio.Task] = None
        
        # Weak references to cleanable objects
        self.cleanable_objects: Set[weakref.ReferenceType] = set()
        
        # Memory tracking
        self.last_memory_check = time.time()
        self.memory_check_interval = 60.0  # Check memory every minute
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
    
    def register_task(
        self,
        name: str,
        callback: Callable[[], Any],
        interval_seconds: float,
        priority: TaskPriority = TaskPriority.MEDIUM,
        max_duration: Optional[float] = None,
        **metadata
    ) -> None:
        """
        Register a cleanup task.
        
        Args:
            name: Unique task name
            callback: Function to call for cleanup
            interval_seconds: How often to run the task
            priority: Task priority
            max_duration: Maximum execution time (None for unlimited)
            **metadata: Additional task metadata
        """
        if name in self.tasks:
            logger.warning(f"Task '{name}' already registered, replacing")
        
        task = CleanupTask(
            name=name,
            callback=callback,
            interval_seconds=interval_seconds,
            priority=priority,
            max_duration=max_duration,
            metadata=metadata
        )
        
        self.tasks[name] = task
        logger.info(f"Registered cleanup task: {name} (interval: {interval_seconds}s)")
    
    def unregister_task(self, name: str) -> bool:
        """
        Unregister a cleanup task.
        
        Args:
            name: Task name to remove
            
        Returns:
            True if task was removed, False if not found
        """
        if name in self.tasks:
            del self.tasks[name]
            logger.info(f"Unregistered cleanup task: {name}")
            return True
        return False
    
    def enable_task(self, name: str) -> bool:
        """Enable a task."""
        if name in self.tasks:
            self.tasks[name].enabled = True
            return True
        return False
    
    def disable_task(self, name: str) -> bool:
        """Disable a task."""
        if name in self.tasks:
            self.tasks[name].enabled = False
            return True
        return False
    
    def register_cleanable_object(self, obj: Any) -> None:
        """
        Register an object for cleanup on shutdown.
        
        Uses weak references to avoid keeping objects alive.
        Objects should have a cleanup() or close() method.
        """
        if hasattr(obj, 'cleanup') or hasattr(obj, 'close'):
            self.cleanable_objects.add(weakref.ref(obj))
        else:
            logger.warning(f"Object {type(obj)} has no cleanup/close method")
    
    def add_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Add callback for alerts."""
        self.alert_callbacks.append(callback)
    
    async def _trigger_alert(self, alert_type: str, data: Dict[str, Any]) -> None:
        """Trigger alert callbacks."""
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_type, data)
                else:
                    callback(alert_type, data)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    async def _check_memory_usage(self) -> None:
        """Check memory usage and trigger alerts if needed."""
        if not self.enable_memory_alerts:
            return
        
        current_time = time.time()
        if current_time - self.last_memory_check < self.memory_check_interval:
            return
        
        self.last_memory_check = current_time
        
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            
            if memory_mb > self.memory_threshold_mb:
                await self._trigger_alert("memory_threshold_exceeded", {
                    "current_memory_mb": memory_mb,
                    "threshold_mb": self.memory_threshold_mb,
                    "timestamp": datetime.utcnow().isoformat()
                })
        except ImportError:
            # psutil not available, skip memory check
            pass
        except Exception as e:
            logger.error(f"Memory check error: {e}")
    
    async def _execute_task(self, task: CleanupTask) -> bool:
        """
        Execute a single cleanup task.
        
        Returns:
            True if task completed successfully, False otherwise
        """
        if task.should_skip():
            logger.warning(f"Skipping task '{task.name}' due to too many errors")
            return False
        
        start_time = time.time()
        
        try:
            logger.debug(f"Executing cleanup task: {task.name}")
            
            # Execute with timeout if specified
            if task.max_duration:
                if asyncio.iscoroutinefunction(task.callback):
                    await asyncio.wait_for(task.callback(), timeout=task.max_duration)
                else:
                    # Run sync function in thread pool with timeout
                    await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, task.callback),
                        timeout=task.max_duration
                    )
            else:
                if asyncio.iscoroutinefunction(task.callback):
                    await task.callback()
                else:
                    await asyncio.get_event_loop().run_in_executor(None, task.callback)
            
            # Task completed successfully
            duration = time.time() - start_time
            task.last_run = datetime.utcnow()
            task.error_count = 0  # Reset error count on success
            
            self.stats.completed_tasks += 1
            self.stats.total_duration += duration
            
            logger.debug(f"Completed cleanup task '{task.name}' in {duration:.3f}s")
            return True
            
        except asyncio.TimeoutError:
            logger.error(f"Cleanup task '{task.name}' timed out after {task.max_duration}s")
            task.error_count += 1
            self.stats.failed_tasks += 1
            return False
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Cleanup task '{task.name}' failed after {duration:.3f}s: {e}")
            task.error_count += 1
            self.stats.failed_tasks += 1
            
            # Trigger alert for critical task failures
            if task.priority == TaskPriority.CRITICAL:
                await self._trigger_alert("critical_task_failed", {
                    "task_name": task.name,
                    "error": str(e),
                    "error_count": task.error_count,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            return False
    
    async def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        logger.info("Cleanup scheduler started")
        
        while self.running:
            try:
                # Check memory usage
                await self._check_memory_usage()
                
                # Get due tasks sorted by priority
                due_tasks = [
                    task for task in self.tasks.values()
                    if task.is_due() and not task.should_skip()
                ]
                
                # Sort by priority (highest first)
                due_tasks.sort(key=lambda t: t.priority.value, reverse=True)
                
                # Execute due tasks
                for task in due_tasks:
                    self.stats.total_tasks += 1
                    await self._execute_task(task)
                
                # Wait for next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(1)  # Brief pause before retrying
        
        logger.info("Cleanup scheduler stopped")
    
    async def start(self) -> None:
        """Start the cleanup scheduler."""
        if self.running:
            logger.warning("Cleanup scheduler is already running")
            return
        
        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Cleanup scheduler initialized")
    
    async def stop(self) -> None:
        """Stop the cleanup scheduler."""
        if not self.running:
            return
        
        logger.info("Stopping cleanup scheduler...")
        self.running = False
        
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Cleanup registered objects
        await self._cleanup_registered_objects()
        
        logger.info("Cleanup scheduler stopped")
    
    async def _cleanup_registered_objects(self) -> None:
        """Cleanup all registered objects."""
        cleanup_count = 0
        
        for obj_ref in list(self.cleanable_objects):
            obj = obj_ref()
            if obj is None:
                # Object has been garbage collected
                self.cleanable_objects.discard(obj_ref)
                continue
            
            try:
                if hasattr(obj, 'cleanup'):
                    if asyncio.iscoroutinefunction(obj.cleanup):
                        await obj.cleanup()
                    else:
                        obj.cleanup()
                elif hasattr(obj, 'close'):
                    if asyncio.iscoroutinefunction(obj.close):
                        await obj.close()
                    else:
                        obj.close()
                cleanup_count += 1
            except Exception as e:
                logger.error(f"Error cleaning up object {type(obj)}: {e}")
        
        logger.info(f"Cleaned up {cleanup_count} registered objects")
    
    async def run_task_now(self, name: str) -> bool:
        """
        Run a specific task immediately.
        
        Args:
            name: Task name to run
            
        Returns:
            True if task completed successfully
        """
        if name not in self.tasks:
            logger.error(f"Task '{name}' not found")
            return False
        
        task = self.tasks[name]
        self.stats.total_tasks += 1
        return await self._execute_task(task)
    
    def get_task_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all tasks."""
        status = {}
        
        for name, task in self.tasks.items():
            status[name] = {
                "enabled": task.enabled,
                "priority": task.priority.value,
                "interval_seconds": task.interval_seconds,
                "last_run": task.last_run.isoformat() if task.last_run else None,
                "error_count": task.error_count,
                "max_errors": task.max_errors,
                "is_due": task.is_due(),
                "should_skip": task.should_skip(),
                "metadata": task.metadata
            }
        
        return status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        return {
            "running": self.running,
            "task_count": len(self.tasks),
            "cleanable_objects": len(self.cleanable_objects),
            "stats": self.stats.to_dict(),
            "memory_threshold_mb": self.memory_threshold_mb,
            "check_interval": self.check_interval
        }


# Global scheduler instance
_cleanup_scheduler: Optional[CleanupScheduler] = None


def get_cleanup_scheduler() -> CleanupScheduler:
    """Get the global cleanup scheduler instance."""
    global _cleanup_scheduler
    if _cleanup_scheduler is None:
        _cleanup_scheduler = CleanupScheduler()
    return _cleanup_scheduler


async def initialize_cleanup_scheduler(
    check_interval: float = 10.0,
    memory_threshold_mb: float = 100.0,
    auto_start: bool = True
) -> CleanupScheduler:
    """Initialize and optionally start the global cleanup scheduler."""
    global _cleanup_scheduler
    _cleanup_scheduler = CleanupScheduler(
        check_interval=check_interval,
        memory_threshold_mb=memory_threshold_mb
    )
    
    if auto_start:
        await _cleanup_scheduler.start()
    
    return _cleanup_scheduler


async def shutdown_cleanup_scheduler() -> None:
    """Shutdown the global cleanup scheduler."""
    global _cleanup_scheduler
    if _cleanup_scheduler:
        await _cleanup_scheduler.stop()
        _cleanup_scheduler = None