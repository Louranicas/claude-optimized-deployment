"""
Memory Pressure Detection and Monitoring Module

This module provides comprehensive memory monitoring capabilities with
circuit breakers for memory pressure situations and automatic optimization.
"""

import asyncio
import psutil
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable, Any, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import warnings

from .circuit_breaker import CircuitBreaker, CircuitState
from .gc_optimization import gc_optimizer, GCMetrics

logger = logging.getLogger(__name__)


class MemoryPressureLevel(Enum):
    """Memory pressure severity levels"""
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MemoryMetrics:
    """Memory usage metrics"""
    timestamp: datetime
    process_memory_mb: float
    system_memory_percent: float
    available_memory_mb: float
    swap_memory_percent: float
    gc_count: int
    gc_time_ms: float
    pressure_level: MemoryPressureLevel
    
    @property
    def is_pressure_high(self) -> bool:
        """Check if memory pressure is high or critical"""
        return self.pressure_level in [MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL]


@dataclass
class MemoryThresholds:
    """Configurable memory pressure thresholds"""
    moderate_system_percent: float = 70.0
    high_system_percent: float = 85.0
    critical_system_percent: float = 95.0
    moderate_process_mb: float = 1024.0
    high_process_mb: float = 2048.0
    critical_process_mb: float = 4096.0
    swap_warning_percent: float = 50.0


class MemoryPressureAction(ABC):
    """Abstract base class for memory pressure response actions"""
    
    @abstractmethod
    async def execute(self, metrics: MemoryMetrics) -> bool:
        """
        Execute the pressure response action.
        
        Returns:
            True if action was successful, False otherwise
        """
        pass
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the action for logging"""
        pass


class GarbageCollectionAction(MemoryPressureAction):
    """Action to trigger garbage collection"""
    
    def __init__(self, force_gc: bool = True):
        self.force_gc = force_gc
        
    async def execute(self, metrics: MemoryMetrics) -> bool:
        """Trigger garbage collection"""
        try:
            gc_metrics = gc_optimizer.trigger_gc(force=self.force_gc)
            if gc_metrics:
                logger.info(
                    f"GC triggered due to memory pressure: "
                    f"{gc_metrics.memory_freed_mb:.2f}MB freed"
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to trigger GC: {e}")
            return False
            
    @property
    def name(self) -> str:
        return "garbage_collection"


class ClearCachesAction(MemoryPressureAction):
    """Action to clear various caches"""
    
    def __init__(self, cache_clearers: List[Callable[[], None]]):
        self.cache_clearers = cache_clearers
        
    async def execute(self, metrics: MemoryMetrics) -> bool:
        """Clear registered caches"""
        try:
            cleared_count = 0
            for clearer in self.cache_clearers:
                try:
                    clearer()
                    cleared_count += 1
                except Exception as e:
                    logger.warning(f"Failed to clear cache: {e}")
                    
            logger.info(f"Cleared {cleared_count} caches due to memory pressure")
            return cleared_count > 0
        except Exception as e:
            logger.error(f"Failed to clear caches: {e}")
            return False
            
    @property
    def name(self) -> str:
        return "clear_caches"


class ReduceBuffersAction(MemoryPressureAction):
    """Action to reduce buffer sizes"""
    
    def __init__(self, buffer_reducers: List[Callable[[], None]]):
        self.buffer_reducers = buffer_reducers
        
    async def execute(self, metrics: MemoryMetrics) -> bool:
        """Reduce buffer sizes"""
        try:
            reduced_count = 0
            for reducer in self.buffer_reducers:
                try:
                    reducer()
                    reduced_count += 1
                except Exception as e:
                    logger.warning(f"Failed to reduce buffer: {e}")
                    
            logger.info(f"Reduced {reduced_count} buffers due to memory pressure")
            return reduced_count > 0
        except Exception as e:
            logger.error(f"Failed to reduce buffers: {e}")
            return False
            
    @property
    def name(self) -> str:
        return "reduce_buffers"


class MemoryCircuitBreaker(CircuitBreaker):
    """
    Circuit breaker that trips based on memory pressure.
    
    Prevents operations when memory usage is critically high.
    """
    
    def __init__(
        self,
        name: str,
        memory_threshold_mb: float = 4096,
        system_threshold_percent: float = 90,
        **kwargs
    ):
        super().__init__(name=name, **kwargs)
        self.memory_threshold_mb = memory_threshold_mb
        self.system_threshold_percent = system_threshold_percent
        
    def _should_trip(self) -> bool:
        """Check if circuit should trip based on memory pressure"""
        try:
            # Check process memory
            process = psutil.Process()
            process_memory_mb = process.memory_info().rss / 1024 / 1024
            
            if process_memory_mb > self.memory_threshold_mb:
                logger.warning(
                    f"Memory circuit breaker {self.name} tripping: "
                    f"process memory {process_memory_mb:.2f}MB > {self.memory_threshold_mb}MB"
                )
                return True
                
            # Check system memory
            system_memory = psutil.virtual_memory()
            if system_memory.percent > self.system_threshold_percent:
                logger.warning(
                    f"Memory circuit breaker {self.name} tripping: "
                    f"system memory {system_memory.percent:.1f}% > {self.system_threshold_percent}%"
                )
                return True
                
            return False
        except Exception as e:
            logger.error(f"Error checking memory for circuit breaker {self.name}: {e}")
            return False


class MemoryMonitor:
    """
    Comprehensive memory monitoring system with pressure detection,
    circuit breakers, and automatic response actions.
    """
    
    def __init__(
        self,
        thresholds: Optional[MemoryThresholds] = None,
        monitoring_interval: float = 30.0,  # seconds
        history_size: int = 100
    ):
        self.thresholds = thresholds or MemoryThresholds()
        self.monitoring_interval = monitoring_interval
        self.history_size = history_size
        
        self.metrics_history: List[MemoryMetrics] = []
        self.pressure_actions: Dict[MemoryPressureLevel, List[MemoryPressureAction]] = {
            level: [] for level in MemoryPressureLevel
        }
        self.circuit_breakers: List[MemoryCircuitBreaker] = []
        
        self._monitoring_task: Optional[asyncio.Task] = None
        self._monitoring_active = False
        self._lock = threading.Lock()
        
        # Callbacks
        self.pressure_callbacks: List[Callable[[MemoryMetrics], None]] = []
        
        # Setup default actions
        self._setup_default_actions()
        
    def _setup_default_actions(self):
        """Setup default memory pressure response actions"""
        # Moderate pressure: trigger GC
        self.add_pressure_action(
            MemoryPressureLevel.MODERATE,
            GarbageCollectionAction(force_gc=False)
        )
        
        # High pressure: force GC and clear object pools
        self.add_pressure_action(
            MemoryPressureLevel.HIGH,
            GarbageCollectionAction(force_gc=True)
        )
        
        from .object_pool import PoolManager
        self.add_pressure_action(
            MemoryPressureLevel.HIGH,
            ClearCachesAction([PoolManager.cleanup_all_pools])
        )
        
        # Critical pressure: all actions plus clear all pools
        self.add_pressure_action(
            MemoryPressureLevel.CRITICAL,
            ClearCachesAction([PoolManager.clear_all_pools])
        )
        
    def add_pressure_action(
        self,
        level: MemoryPressureLevel,
        action: MemoryPressureAction
    ):
        """Add an action to execute at a specific pressure level"""
        with self._lock:
            self.pressure_actions[level].append(action)
            logger.info(f"Added pressure action '{action.name}' for level {level.value}")
            
    def add_circuit_breaker(self, circuit_breaker: MemoryCircuitBreaker):
        """Add a memory-based circuit breaker"""
        with self._lock:
            self.circuit_breakers.append(circuit_breaker)
            logger.info(f"Added memory circuit breaker: {circuit_breaker.name}")
            
    def add_pressure_callback(self, callback: Callable[[MemoryMetrics], None]):
        """Add a callback to be called when pressure is detected"""
        with self._lock:
            self.pressure_callbacks.append(callback)
            
    def get_current_metrics(self) -> MemoryMetrics:
        """Get current memory metrics"""
        try:
            # Process memory
            process = psutil.Process()
            process_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # System memory
            system_memory = psutil.virtual_memory()
            available_memory = system_memory.available / 1024 / 1024  # MB
            
            # Swap memory
            swap_memory = psutil.swap_memory()
            
            # GC metrics
            gc_stats = gc_optimizer.get_gc_stats()
            
            # Determine pressure level
            pressure_level = self._calculate_pressure_level(
                process_memory, system_memory.percent, swap_memory.percent
            )
            
            return MemoryMetrics(
                timestamp=datetime.now(),
                process_memory_mb=process_memory,
                system_memory_percent=system_memory.percent,
                available_memory_mb=available_memory,
                swap_memory_percent=swap_memory.percent,
                gc_count=gc_stats.get("gc_count", 0),
                gc_time_ms=gc_stats.get("avg_pause_time_ms", 0),
                pressure_level=pressure_level
            )
            
        except Exception as e:
            logger.error(f"Failed to get memory metrics: {e}")
            return MemoryMetrics(
                timestamp=datetime.now(),
                process_memory_mb=0,
                system_memory_percent=0,
                available_memory_mb=0,
                swap_memory_percent=0,
                gc_count=0,
                gc_time_ms=0,
                pressure_level=MemoryPressureLevel.LOW
            )
            
    def _calculate_pressure_level(
        self,
        process_memory_mb: float,
        system_memory_percent: float,
        swap_percent: float
    ) -> MemoryPressureLevel:
        """Calculate memory pressure level based on metrics"""
        # Check critical thresholds first
        if (system_memory_percent >= self.thresholds.critical_system_percent or
            process_memory_mb >= self.thresholds.critical_process_mb):
            return MemoryPressureLevel.CRITICAL
            
        # Check high thresholds
        if (system_memory_percent >= self.thresholds.high_system_percent or
            process_memory_mb >= self.thresholds.high_process_mb or
            swap_percent >= self.thresholds.swap_warning_percent):
            return MemoryPressureLevel.HIGH
            
        # Check moderate thresholds
        if (system_memory_percent >= self.thresholds.moderate_system_percent or
            process_memory_mb >= self.thresholds.moderate_process_mb):
            return MemoryPressureLevel.MODERATE
            
        return MemoryPressureLevel.LOW
        
    async def _handle_memory_pressure(self, metrics: MemoryMetrics):
        """Handle detected memory pressure"""
        if metrics.pressure_level == MemoryPressureLevel.LOW:
            return
            
        logger.warning(
            f"Memory pressure detected ({metrics.pressure_level.value}): "
            f"Process: {metrics.process_memory_mb:.2f}MB, "
            f"System: {metrics.system_memory_percent:.1f}%, "
            f"Swap: {metrics.swap_memory_percent:.1f}%"
        )
        
        # Execute pressure actions
        actions = self.pressure_actions.get(metrics.pressure_level, [])
        for action in actions:
            try:
                success = await action.execute(metrics)
                if success:
                    logger.info(f"Successfully executed pressure action: {action.name}")
                else:
                    logger.warning(f"Pressure action failed: {action.name}")
            except Exception as e:
                logger.error(f"Error executing pressure action {action.name}: {e}")
                
        # Update circuit breakers
        for circuit_breaker in self.circuit_breakers:
            circuit_breaker._check_and_update_state()
            
        # Call callbacks
        for callback in self.pressure_callbacks:
            try:
                callback(metrics)
            except Exception as e:
                logger.error(f"Error in pressure callback: {e}")
                
    async def start_monitoring(self):
        """Start continuous memory monitoring"""
        if self._monitoring_active:
            logger.warning("Memory monitoring already active")
            return
            
        self._monitoring_active = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Started memory monitoring")
        
    async def stop_monitoring(self):
        """Stop memory monitoring"""
        self._monitoring_active = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
            
        logger.info("Stopped memory monitoring")
        
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        try:
            while self._monitoring_active:
                # Get current metrics
                metrics = self.get_current_metrics()
                
                # Store in history
                with self._lock:
                    self.metrics_history.append(metrics)
                    if len(self.metrics_history) > self.history_size:
                        self.metrics_history.pop(0)
                        
                # Handle pressure
                await self._handle_memory_pressure(metrics)
                
                # Wait for next check
                await asyncio.sleep(self.monitoring_interval)
                
        except asyncio.CancelledError:
            logger.info("Memory monitoring loop cancelled")
        except Exception as e:
            logger.error(f"Error in memory monitoring loop: {e}")
            
    def get_metrics_history(self) -> List[MemoryMetrics]:
        """Get memory metrics history"""
        with self._lock:
            return self.metrics_history.copy()
            
    def get_pressure_statistics(self) -> Dict[str, Any]:
        """Get memory pressure statistics"""
        with self._lock:
            if not self.metrics_history:
                return {
                    "total_samples": 0,
                    "pressure_events": 0,
                    "avg_process_memory_mb": 0,
                    "avg_system_memory_percent": 0,
                    "pressure_distribution": {}
                }
                
            total_samples = len(self.metrics_history)
            pressure_events = sum(1 for m in self.metrics_history 
                                if m.pressure_level != MemoryPressureLevel.LOW)
            
            avg_process_memory = sum(m.process_memory_mb for m in self.metrics_history) / total_samples
            avg_system_memory = sum(m.system_memory_percent for m in self.metrics_history) / total_samples
            
            # Pressure level distribution
            pressure_dist = {}
            for level in MemoryPressureLevel:
                count = sum(1 for m in self.metrics_history if m.pressure_level == level)
                pressure_dist[level.value] = count
                
            return {
                "total_samples": total_samples,
                "pressure_events": pressure_events,
                "pressure_rate": pressure_events / total_samples if total_samples > 0 else 0,
                "avg_process_memory_mb": avg_process_memory,
                "avg_system_memory_percent": avg_system_memory,
                "pressure_distribution": pressure_dist
            }


# Global memory monitor instance
memory_monitor = MemoryMonitor()


async def check_memory_pressure() -> MemoryMetrics:
    """
    Quick memory pressure check without full monitoring.
    
    Returns:
        Current memory metrics
    """
    return memory_monitor.get_current_metrics()


def with_memory_monitoring(func: Callable) -> Callable:
    """
    Decorator to monitor memory usage around function execution.
    
    Triggers memory pressure actions if needed before and after function execution.
    """
    async def async_wrapper(*args, **kwargs):
        # Check memory before
        before_metrics = memory_monitor.get_current_metrics()
        if before_metrics.is_pressure_high:
            await memory_monitor._handle_memory_pressure(before_metrics)
            
        # Execute function
        result = await func(*args, **kwargs)
        
        # Check memory after
        after_metrics = memory_monitor.get_current_metrics()
        if after_metrics.is_pressure_high:
            await memory_monitor._handle_memory_pressure(after_metrics)
            
        return result
        
    def sync_wrapper(*args, **kwargs):
        # For sync functions, just check and log
        before_metrics = memory_monitor.get_current_metrics()
        if before_metrics.is_pressure_high:
            logger.warning(f"High memory pressure before {func.__name__}")
            
        result = func(*args, **kwargs)
        
        after_metrics = memory_monitor.get_current_metrics()
        if after_metrics.is_pressure_high:
            logger.warning(f"High memory pressure after {func.__name__}")
            
        return result
        
    # Return appropriate wrapper based on function type
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper