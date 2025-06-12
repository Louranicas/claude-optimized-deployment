"""
Lifecycle GC Integration Module

This module provides integration points for manual GC triggers at appropriate
lifecycle events in the application, ensuring optimal memory management.
"""

import asyncio
import atexit
import signal
import threading
from typing import Callable, List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from enum import Enum

from .gc_optimization import gc_optimizer, GCMetrics
from .memory_monitor import memory_monitor, MemoryPressureLevel
from .object_pool import PoolManager

logger = logging.getLogger(__name__)


class LifecycleEvent(Enum):
    """Application lifecycle events where GC should be triggered"""
    APPLICATION_START = "application_start"
    APPLICATION_SHUTDOWN = "application_shutdown"
    REQUEST_COMPLETE = "request_complete"
    BATCH_COMPLETE = "batch_complete"
    EXPERT_CONSULTATION_COMPLETE = "expert_consultation_complete"
    LARGE_OPERATION_COMPLETE = "large_operation_complete"
    MEMORY_PRESSURE_HIGH = "memory_pressure_high"
    PERIODIC_MAINTENANCE = "periodic_maintenance"
    ERROR_RECOVERY = "error_recovery"
    CACHE_CLEANUP = "cache_cleanup"


class GCTriggerStrategy(Enum):
    """Strategies for when to trigger GC"""
    ALWAYS = "always"
    ON_PRESSURE = "on_pressure"
    ADAPTIVE = "adaptive"
    SCHEDULED = "scheduled"


class LifecycleGCManager:
    """
    Manager for lifecycle-based garbage collection triggers.
    
    Automatically triggers GC at appropriate application lifecycle
    events to maintain optimal memory usage.
    """
    
    def __init__(self):
        self.event_handlers: Dict[LifecycleEvent, List[Callable]] = {
            event: [] for event in LifecycleEvent
        }
        self.gc_strategies: Dict[LifecycleEvent, GCTriggerStrategy] = {}
        self.event_counters: Dict[LifecycleEvent, int] = {
            event: 0 for event in LifecycleEvent
        }
        self.last_gc_times: Dict[LifecycleEvent, datetime] = {}
        self.gc_metrics_history: List[GCMetrics] = []
        
        # Configuration
        self.min_gc_interval_seconds = 30  # Minimum time between GCs
        self.adaptive_threshold_mb = 256  # Memory threshold for adaptive GC
        self.batch_size_threshold = 1000  # Trigger GC after processing this many items
        
        # Setup default strategies
        self._setup_default_strategies()
        
        # Register shutdown handlers
        self._register_shutdown_handlers()
        
        # Start periodic maintenance
        self._start_periodic_maintenance()
        
    def _setup_default_strategies(self):
        """Setup default GC strategies for each lifecycle event"""
        self.gc_strategies.update({
            LifecycleEvent.APPLICATION_START: GCTriggerStrategy.ALWAYS,
            LifecycleEvent.APPLICATION_SHUTDOWN: GCTriggerStrategy.ALWAYS,
            LifecycleEvent.REQUEST_COMPLETE: GCTriggerStrategy.ON_PRESSURE,
            LifecycleEvent.BATCH_COMPLETE: GCTriggerStrategy.ADAPTIVE,
            LifecycleEvent.EXPERT_CONSULTATION_COMPLETE: GCTriggerStrategy.ADAPTIVE,
            LifecycleEvent.LARGE_OPERATION_COMPLETE: GCTriggerStrategy.ALWAYS,
            LifecycleEvent.MEMORY_PRESSURE_HIGH: GCTriggerStrategy.ALWAYS,
            LifecycleEvent.PERIODIC_MAINTENANCE: GCTriggerStrategy.SCHEDULED,
            LifecycleEvent.ERROR_RECOVERY: GCTriggerStrategy.ALWAYS,
            LifecycleEvent.CACHE_CLEANUP: GCTriggerStrategy.ADAPTIVE
        })
        
    def set_strategy(self, event: LifecycleEvent, strategy: GCTriggerStrategy):
        """Set GC strategy for a specific lifecycle event"""
        self.gc_strategies[event] = strategy
        logger.info(f"Set GC strategy for {event.value} to {strategy.value}")
        
    def register_event_handler(self, event: LifecycleEvent, handler: Callable):
        """Register a custom handler for a lifecycle event"""
        self.event_handlers[event].append(handler)
        logger.debug(f"Registered handler for {event.value}")
        
    async def trigger_lifecycle_event(
        self, 
        event: LifecycleEvent, 
        context: Optional[Dict[str, Any]] = None,
        force_gc: bool = False
    ) -> Optional[GCMetrics]:
        """
        Trigger a lifecycle event and perform appropriate GC actions.
        
        Args:
            event: Lifecycle event that occurred
            context: Additional context about the event
            force_gc: Force GC regardless of strategy
            
        Returns:
            GC metrics if GC was triggered, None otherwise
        """
        self.event_counters[event] += 1
        context = context or {}
        
        logger.debug(f"Lifecycle event triggered: {event.value} (count: {self.event_counters[event]})")
        
        # Run custom handlers
        for handler in self.event_handlers[event]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event, context)
                else:
                    handler(event, context)
            except Exception as e:
                logger.error(f"Error in lifecycle event handler: {e}")
                
        # Determine if GC should be triggered
        should_gc = force_gc or self._should_trigger_gc(event, context)
        
        if should_gc:
            gc_metrics = await self._perform_lifecycle_gc(event, context)
            return gc_metrics
            
        return None
        
    def _should_trigger_gc(self, event: LifecycleEvent, context: Dict[str, Any]) -> bool:
        """Determine if GC should be triggered for this event"""
        strategy = self.gc_strategies.get(event, GCTriggerStrategy.ON_PRESSURE)
        
        # Check minimum interval
        last_gc = self.last_gc_times.get(event)
        if last_gc:
            time_since_last = (datetime.now() - last_gc).total_seconds()
            if time_since_last < self.min_gc_interval_seconds:
                return False
                
        if strategy == GCTriggerStrategy.ALWAYS:
            return True
            
        elif strategy == GCTriggerStrategy.ON_PRESSURE:
            metrics = memory_monitor.get_current_metrics()
            return metrics.pressure_level in [
                MemoryPressureLevel.HIGH, 
                MemoryPressureLevel.CRITICAL
            ]
            
        elif strategy == GCTriggerStrategy.ADAPTIVE:
            # Adaptive strategy based on memory usage and event frequency
            metrics = memory_monitor.get_current_metrics()
            
            # High memory usage
            if metrics.process_memory_mb > self.adaptive_threshold_mb:
                return True
                
            # High event frequency
            event_count = self.event_counters[event]
            if event_count % self.batch_size_threshold == 0:
                return True
                
            # Moderate pressure with frequent events
            if (metrics.pressure_level == MemoryPressureLevel.MODERATE and 
                event_count % (self.batch_size_threshold // 2) == 0):
                return True
                
            return False
            
        elif strategy == GCTriggerStrategy.SCHEDULED:
            # Only trigger during scheduled maintenance
            return event == LifecycleEvent.PERIODIC_MAINTENANCE
            
        return False
        
    async def _perform_lifecycle_gc(
        self, 
        event: LifecycleEvent, 
        context: Dict[str, Any]
    ) -> Optional[GCMetrics]:
        """Perform GC with lifecycle-specific optimizations"""
        try:
            logger.info(f"Triggering GC for lifecycle event: {event.value}")
            
            # Pre-GC optimizations based on event type
            await self._pre_gc_optimizations(event, context)
            
            # Trigger GC
            force_gc = event in [
                LifecycleEvent.APPLICATION_SHUTDOWN,
                LifecycleEvent.MEMORY_PRESSURE_HIGH,
                LifecycleEvent.ERROR_RECOVERY
            ]
            
            gc_metrics = gc_optimizer.trigger_gc(force=force_gc)
            
            if gc_metrics:
                self.last_gc_times[event] = datetime.now()
                self.gc_metrics_history.append(gc_metrics)
                
                # Keep history bounded
                if len(self.gc_metrics_history) > 1000:
                    self.gc_metrics_history = self.gc_metrics_history[-500:]
                    
                logger.info(
                    f"GC completed for {event.value}: "
                    f"{gc_metrics.memory_freed_mb:.2f}MB freed, "
                    f"{gc_metrics.pause_time_ms:.2f}ms pause, "
                    f"{gc_metrics.efficiency_percent:.2f}% efficiency"
                )
                
            # Post-GC optimizations
            await self._post_gc_optimizations(event, context, gc_metrics)
            
            return gc_metrics
            
        except Exception as e:
            logger.error(f"Error during lifecycle GC for {event.value}: {e}")
            return None
            
    async def _pre_gc_optimizations(self, event: LifecycleEvent, context: Dict[str, Any]):
        """Perform optimizations before GC based on event type"""
        if event in [
            LifecycleEvent.BATCH_COMPLETE,
            LifecycleEvent.EXPERT_CONSULTATION_COMPLETE,
            LifecycleEvent.CACHE_CLEANUP
        ]:
            # Clean up object pools
            PoolManager.cleanup_all_pools()
            
        if event == LifecycleEvent.APPLICATION_SHUTDOWN:
            # Clear all pools before shutdown
            PoolManager.clear_all_pools()
            
        if event == LifecycleEvent.MEMORY_PRESSURE_HIGH:
            # Aggressive cleanup
            PoolManager.clear_all_pools()
            
            # Optimize GC for latency during pressure
            gc_optimizer.optimize_for_latency()
            
    async def _post_gc_optimizations(
        self, 
        event: LifecycleEvent, 
        context: Dict[str, Any],
        gc_metrics: Optional[GCMetrics]
    ):
        """Perform optimizations after GC based on results"""
        if not gc_metrics:
            return
            
        # Adjust strategy based on GC performance
        if gc_metrics.pause_time_ms > 100:
            # Long pause time, optimize for latency
            if event not in [LifecycleEvent.APPLICATION_SHUTDOWN]:
                gc_optimizer.optimize_for_latency()
                logger.info("Switched to latency optimization due to long GC pause")
                
        elif gc_metrics.efficiency_percent < 5:
            # Low efficiency, might be too frequent
            if event in [LifecycleEvent.REQUEST_COMPLETE]:
                self.gc_strategies[event] = GCTriggerStrategy.ON_PRESSURE
                logger.info("Reduced GC frequency due to low efficiency")
                
    def _register_shutdown_handlers(self):
        """Register handlers for application shutdown"""
        def shutdown_handler(signum=None, frame=None):
            """Handle application shutdown"""
            logger.info("Application shutdown detected, triggering final GC")
            
            # Use asyncio.run for final cleanup if event loop is not running
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(
                        self.trigger_lifecycle_event(LifecycleEvent.APPLICATION_SHUTDOWN)
                    )
                else:
                    asyncio.run(
                        self.trigger_lifecycle_event(LifecycleEvent.APPLICATION_SHUTDOWN)
                    )
            except Exception as e:
                logger.error(f"Error during shutdown GC: {e}")
                
        # Register with atexit and signal handlers
        atexit.register(shutdown_handler)
        
        try:
            signal.signal(signal.SIGTERM, shutdown_handler)
            signal.signal(signal.SIGINT, shutdown_handler)
        except ValueError:
            # Signal handling not available (e.g., in threads)
            pass
            
    def _start_periodic_maintenance(self):
        """Start periodic maintenance task"""
        async def maintenance_task():
            while True:
                try:
                    await asyncio.sleep(300)  # 5 minutes
                    await self.trigger_lifecycle_event(LifecycleEvent.PERIODIC_MAINTENANCE)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in periodic maintenance: {e}")
                    
        # Start the task if we have an event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(maintenance_task())
        except RuntimeError:
            # No event loop, will be started later
            pass
            
    def get_lifecycle_stats(self) -> Dict[str, Any]:
        """Get statistics about lifecycle GC performance"""
        total_gcs = len(self.gc_metrics_history)
        
        if total_gcs == 0:
            return {
                "total_gcs": 0,
                "event_counters": dict(self.event_counters),
                "strategies": {k.value: v.value for k, v in self.gc_strategies.items()}
            }
            
        # Calculate averages
        avg_pause = sum(m.pause_time_ms for m in self.gc_metrics_history) / total_gcs
        avg_efficiency = sum(m.efficiency_percent for m in self.gc_metrics_history) / total_gcs
        total_freed = sum(m.memory_freed_mb for m in self.gc_metrics_history)
        
        # Recent performance (last 10 GCs)
        recent_metrics = self.gc_metrics_history[-10:]
        recent_avg_pause = sum(m.pause_time_ms for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        recent_avg_efficiency = sum(m.efficiency_percent for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        
        return {
            "total_gcs": total_gcs,
            "total_memory_freed_mb": total_freed,
            "average_pause_time_ms": avg_pause,
            "average_efficiency_percent": avg_efficiency,
            "recent_average_pause_time_ms": recent_avg_pause,
            "recent_average_efficiency_percent": recent_avg_efficiency,
            "event_counters": dict(self.event_counters),
            "strategies": {k.value: v.value for k, v in self.gc_strategies.items()},
            "last_gc_times": {
                k.value: v.isoformat() if v else None 
                for k, v in self.last_gc_times.items()
            }
        }


# Global lifecycle GC manager
lifecycle_gc_manager = LifecycleGCManager()


# Convenience functions for common lifecycle events
async def on_application_start():
    """Trigger GC for application start"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.APPLICATION_START
    )


async def on_application_shutdown():
    """Trigger GC for application shutdown"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.APPLICATION_SHUTDOWN
    )


async def on_request_complete(request_info: Optional[Dict[str, Any]] = None):
    """Trigger GC after request completion"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.REQUEST_COMPLETE,
        context=request_info or {}
    )


async def on_batch_complete(batch_size: int, processing_time: float):
    """Trigger GC after batch processing completion"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.BATCH_COMPLETE,
        context={"batch_size": batch_size, "processing_time": processing_time}
    )


async def on_expert_consultation_complete(
    query_id: str, 
    expert_count: int, 
    response_count: int
):
    """Trigger GC after expert consultation completion"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.EXPERT_CONSULTATION_COMPLETE,
        context={
            "query_id": query_id,
            "expert_count": expert_count,
            "response_count": response_count
        }
    )


async def on_large_operation_complete(operation_name: str, data_size_mb: float):
    """Trigger GC after large operation completion"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.LARGE_OPERATION_COMPLETE,
        context={"operation_name": operation_name, "data_size_mb": data_size_mb}
    )


async def on_memory_pressure_detected(pressure_level: MemoryPressureLevel):
    """Trigger GC when memory pressure is detected"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.MEMORY_PRESSURE_HIGH,
        context={"pressure_level": pressure_level.value}
    )


async def on_error_recovery(error_type: str, recovery_action: str):
    """Trigger GC during error recovery"""
    return await lifecycle_gc_manager.trigger_lifecycle_event(
        LifecycleEvent.ERROR_RECOVERY,
        context={"error_type": error_type, "recovery_action": recovery_action}
    )


# Context manager for automatic lifecycle GC
class lifecycle_gc_context:
    """Context manager that triggers GC at the end of an operation"""
    
    def __init__(self, event: LifecycleEvent, context: Optional[Dict[str, Any]] = None):
        self.event = event
        self.context = context or {}
        self.start_time = None
        
    async def __aenter__(self):
        self.start_time = datetime.now()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Add timing information
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.context["duration_seconds"] = duration
            
        # Add error information if there was an exception
        if exc_type:
            self.context["had_error"] = True
            self.context["error_type"] = exc_type.__name__
            
        # Trigger lifecycle event
        await lifecycle_gc_manager.trigger_lifecycle_event(self.event, self.context)