"""
Garbage Collection Optimization Module

This module provides utilities for optimizing garbage collection performance
in Node.js/V8 environments, including manual GC triggers, memory monitoring,
and performance tuning.
"""

import gc
import os
import psutil
import time
import weakref
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass
from datetime import datetime
import logging

__all__ = [
    "GCMetrics",
    "GCOptimizer",
    "with_gc_optimization",
    "periodic_gc_check",
    "get_v8_flags"
]


logger = logging.getLogger(__name__)


@dataclass
class GCMetrics:
    """Metrics for garbage collection performance"""
    pause_time_ms: float
    memory_freed_mb: float
    efficiency_percent: float
    timestamp: datetime
    gc_type: str
    heap_before_mb: float
    heap_after_mb: float


class GCOptimizer:
    """
    Garbage Collection Optimizer for Python and V8 environments.
    
    Provides utilities for:
    - Manual GC triggering with timing
    - Memory pressure detection
    - GC performance monitoring
    - Automatic GC scheduling
    """
    
    def __init__(self):
        self.metrics_history: List[GCMetrics] = []
        self.memory_threshold_mb = 4096  # 4GB threshold
        self.gc_interval_seconds = 60  # Default GC interval
        self.last_gc_time = time.time()
        self.weak_refs: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._setup_python_gc()
        
    def _setup_python_gc(self):
        """Configure Python's garbage collector for optimal performance"""
        # Set collection thresholds (generation 0, 1, 2)
        gc.set_threshold(700, 10, 10)
        
        # Enable automatic collection
        gc.enable()
        
        # Log current settings
        logger.info(f"GC thresholds set to: {gc.get_threshold()}")
        logger.info(f"GC enabled: {gc.isenabled()}")
        
    def trigger_gc(self, force: bool = False) -> Optional[GCMetrics]:
        """
        Trigger garbage collection manually with performance metrics.
        
        Args:
            force: Force GC even if recently run
            
        Returns:
            GCMetrics if GC was triggered, None otherwise
        """
        current_time = time.time()
        
        # Check if we should run GC
        if not force and (current_time - self.last_gc_time) < self.gc_interval_seconds:
            return None
            
        # Get memory before GC
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024  # Convert to MB
        
        # Time the GC
        start_time = time.time()
        
        # Run Python GC
        collected = gc.collect(2)  # Full collection
        
        # Get memory after GC
        memory_after = process.memory_info().rss / 1024 / 1024
        
        # Calculate metrics
        gc_time = (time.time() - start_time) * 1000  # Convert to ms
        memory_freed = max(0, memory_before - memory_after)
        efficiency = (memory_freed / memory_before * 100) if memory_before > 0 else 0
        
        # Create metrics
        metrics = GCMetrics(
            pause_time_ms=gc_time,
            memory_freed_mb=memory_freed,
            efficiency_percent=efficiency,
            timestamp=datetime.now(),
            gc_type="manual",
            heap_before_mb=memory_before,
            heap_after_mb=memory_after
        )
        
        # Store metrics
        self.metrics_history.append(metrics)
        self.last_gc_time = current_time
        
        # Log results
        logger.info(
            f"GC completed: {collected} objects collected, "
            f"{memory_freed:.2f}MB freed ({efficiency:.2f}% efficiency), "
            f"pause time: {gc_time:.2f}ms"
        )
        
        return metrics
        
    def check_memory_pressure(self) -> bool:
        """
        Check if system is under memory pressure.
        
        Returns:
            True if memory pressure detected
        """
        process = psutil.Process()
        memory_usage = process.memory_info().rss / 1024 / 1024  # MB
        
        # Check against threshold
        if memory_usage > self.memory_threshold_mb:
            logger.warning(
                f"Memory pressure detected: {memory_usage:.2f}MB > "
                f"{self.memory_threshold_mb}MB threshold"
            )
            return True
            
        # Check system-wide memory
        system_memory = psutil.virtual_memory()
        if system_memory.percent > 85:
            logger.warning(
                f"System memory pressure: {system_memory.percent}% used"
            )
            return True
            
        return False
        
    def optimize_for_throughput(self):
        """Configure GC for maximum throughput (batch operations)"""
        # Increase thresholds to reduce GC frequency
        gc.set_threshold(1000, 15, 15)
        self.gc_interval_seconds = 120  # Less frequent GC
        logger.info("GC optimized for throughput")
        
    def optimize_for_latency(self):
        """Configure GC for minimum latency (interactive operations)"""
        # Decrease thresholds for more frequent, smaller GCs
        gc.set_threshold(400, 5, 5)
        self.gc_interval_seconds = 30  # More frequent GC
        logger.info("GC optimized for latency")
        
    def get_gc_stats(self) -> Dict[str, Any]:
        """Get current GC statistics"""
        recent_metrics = self.metrics_history[-10:] if self.metrics_history else []
        
        if not recent_metrics:
            return {
                "avg_pause_time_ms": 0,
                "avg_efficiency_percent": 0,
                "total_memory_freed_mb": 0,
                "gc_count": 0
            }
            
        avg_pause = sum(m.pause_time_ms for m in recent_metrics) / len(recent_metrics)
        avg_efficiency = sum(m.efficiency_percent for m in recent_metrics) / len(recent_metrics)
        total_freed = sum(m.memory_freed_mb for m in recent_metrics)
        
        return {
            "avg_pause_time_ms": avg_pause,
            "avg_efficiency_percent": avg_efficiency,
            "total_memory_freed_mb": total_freed,
            "gc_count": len(recent_metrics),
            "last_gc_time": self.metrics_history[-1].timestamp if self.metrics_history else None
        }
        
    def register_object(self, obj: Any, name: str):
        """Register an object for weak reference tracking"""
        try:
            self.weak_refs[name] = obj
        except TypeError:
            # Object doesn't support weak references
            pass
            
    def get_weak_ref_count(self) -> int:
        """Get count of tracked weak references"""
        return len(self.weak_refs)
        
    def cleanup_weak_refs(self):
        """Clean up dead weak references"""
        # Accessing the dict automatically cleans up dead refs
        count = len(self.weak_refs)
        logger.debug(f"Active weak references: {count}")
        

# Global GC optimizer instance
gc_optimizer = GCOptimizer()


def with_gc_optimization(func: Callable) -> Callable:
    """
    Decorator to optimize GC around function execution.
    
    Triggers GC before expensive operations and checks memory pressure after.
    """
    def wrapper(*args, **kwargs):
        # Check memory pressure before
        if gc_optimizer.check_memory_pressure():
            gc_optimizer.trigger_gc(force=True)
            
        # Execute function
        result = func(*args, **kwargs)
        
        # Check if we should GC after
        if gc_optimizer.check_memory_pressure():
            gc_optimizer.trigger_gc()
            
        return result
        
    return wrapper


def periodic_gc_check():
    """
    Perform periodic GC check and optimization.
    
    Should be called from a background task or scheduler.
    """
    # Trigger GC if needed
    metrics = gc_optimizer.trigger_gc()
    
    if metrics:
        # Adjust strategy based on metrics
        if metrics.pause_time_ms > 100:
            # Pause times too high, optimize for latency
            gc_optimizer.optimize_for_latency()
        elif metrics.efficiency_percent < 5:
            # Efficiency too low, maybe too frequent
            gc_optimizer.optimize_for_throughput()
            
    # Clean up weak references
    gc_optimizer.cleanup_weak_refs()
    
    return metrics


# V8 optimization flags for Node.js environments
V8_OPTIMIZATION_FLAGS = {
    "production": [
        "--max-old-space-size=6144",
        "--max-semi-space-size=64", 
        "--initial-old-space-size=512",
        "--gc-interval=100",
        "--optimize-for-size",
        "--max-heap-size=6144"
    ],
    "development": [
        "--max-old-space-size=2048",
        "--expose-gc",
        "--trace-gc"
    ]
}


def get_v8_flags(environment: str = "production") -> List[str]:
    """Get recommended V8 flags for the environment"""
    return V8_OPTIMIZATION_FLAGS.get(environment, V8_OPTIMIZATION_FLAGS["production"])