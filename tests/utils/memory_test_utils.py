"""
Memory Testing Utilities
Common utilities for memory testing and validation.
"""

import gc
import time
import psutil
import tracemalloc
import threading
import asyncio
from typing import Dict, List, Any, Optional, Callable, ContextManager
from dataclasses import dataclass
from contextlib import contextmanager, asynccontextmanager
import weakref
import sys
import os


@dataclass
class MemorySnapshot:
    """Memory state snapshot"""
    timestamp: float
    rss_mb: float
    vms_mb: float
    available_mb: float
    peak_mb: float
    gc_counts: List[int]
    active_objects: int
    tracemalloc_current: Optional[int] = None
    tracemalloc_peak: Optional[int] = None
    description: str = ""


@dataclass
class MemoryDelta:
    """Memory change between two snapshots"""
    rss_delta_mb: float
    vms_delta_mb: float
    available_delta_mb: float
    gc_delta: List[int]
    objects_delta: int
    duration_seconds: float
    growth_rate_mb_per_sec: float


class MemoryMonitor:
    """Real-time memory monitoring utilities"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.snapshots: List[MemorySnapshot] = []
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
    def take_snapshot(self, description: str = "") -> MemorySnapshot:
        """Take a detailed memory snapshot"""
        timestamp = time.time()
        memory_info = self.process.memory_info()
        virtual_mem = psutil.virtual_memory()
        
        # Get tracemalloc data if available
        tracemalloc_current = None
        tracemalloc_peak = None
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc_current = current
            tracemalloc_peak = peak
        
        snapshot = MemorySnapshot(
            timestamp=timestamp,
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            available_mb=virtual_mem.available / 1024 / 1024,
            peak_mb=memory_info.peak_wset / 1024 / 1024 if hasattr(memory_info, 'peak_wset') else 0,
            gc_counts=list(gc.get_count()),
            active_objects=len(gc.get_objects()),
            tracemalloc_current=tracemalloc_current,
            tracemalloc_peak=tracemalloc_peak,
            description=description
        )
        
        self.snapshots.append(snapshot)
        return snapshot
    
    def calculate_delta(self, snapshot1: MemorySnapshot, snapshot2: MemorySnapshot) -> MemoryDelta:
        """Calculate memory delta between two snapshots"""
        duration = snapshot2.timestamp - snapshot1.timestamp
        rss_delta = snapshot2.rss_mb - snapshot1.rss_mb
        
        return MemoryDelta(
            rss_delta_mb=rss_delta,
            vms_delta_mb=snapshot2.vms_mb - snapshot1.vms_mb,
            available_delta_mb=snapshot2.available_mb - snapshot1.available_mb,
            gc_delta=[
                snapshot2.gc_counts[i] - snapshot1.gc_counts[i] 
                for i in range(len(snapshot1.gc_counts))
            ],
            objects_delta=snapshot2.active_objects - snapshot1.active_objects,
            duration_seconds=duration,
            growth_rate_mb_per_sec=rss_delta / duration if duration > 0 else 0
        )
    
    def start_continuous_monitoring(self, interval: float = 1.0):
        """Start continuous memory monitoring in background thread"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_continuous_monitoring(self):
        """Stop continuous memory monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self.stop_event.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitoring_loop(self, interval: float):
        """Background monitoring loop"""
        while not self.stop_event.wait(interval):
            if self.monitoring_active:
                self.take_snapshot("continuous_monitoring")
    
    def get_peak_memory(self) -> float:
        """Get peak memory usage from all snapshots"""
        if not self.snapshots:
            return 0.0
        return max(snapshot.rss_mb for snapshot in self.snapshots)
    
    def get_memory_trend(self) -> Dict[str, float]:
        """Analyze memory usage trend"""
        if len(self.snapshots) < 2:
            return {"trend": "insufficient_data", "slope": 0.0, "r_squared": 0.0}
        
        # Simple linear regression
        n = len(self.snapshots)
        x = list(range(n))
        y = [snapshot.rss_mb for snapshot in self.snapshots]
        
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
        
        # Calculate R-squared
        y_pred = [slope * x[i] + (y_mean - slope * x_mean) for i in range(n)]
        ss_res = sum((y[i] - y_pred[i]) ** 2 for i in range(n))
        ss_tot = sum((y[i] - y_mean) ** 2 for i in range(n))
        
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
        
        return {
            "trend": "increasing" if slope > 0.1 else "stable",
            "slope": slope,
            "r_squared": r_squared
        }


class ObjectTracker:
    """Track object lifecycle and references"""
    
    def __init__(self):
        self.tracked_objects = weakref.WeakSet()
        self.object_counts = {}
        self.allocation_history = []
    
    def track_object(self, obj: Any, description: str = ""):
        """Add object to tracking"""
        self.tracked_objects.add(obj)
        obj_type = type(obj).__name__
        
        self.object_counts[obj_type] = self.object_counts.get(obj_type, 0) + 1
        self.allocation_history.append({
            'timestamp': time.time(),
            'type': obj_type,
            'description': description,
            'action': 'allocated'
        })
    
    def get_object_stats(self) -> Dict[str, Any]:
        """Get object tracking statistics"""
        return {
            'tracked_objects_count': len(self.tracked_objects),
            'object_type_counts': self.object_counts.copy(),
            'allocation_history_count': len(self.allocation_history),
            'most_allocated_type': max(self.object_counts.items(), key=lambda x: x[1]) if self.object_counts else None
        }
    
    def force_cleanup(self):
        """Force cleanup of tracked objects"""
        self.tracked_objects.clear()
        gc.collect()


@contextmanager
def memory_profiling_context(component_name: str = "test"):
    """Context manager for memory profiling"""
    monitor = MemoryMonitor()
    
    # Start profiling
    tracemalloc.start()
    gc.collect()
    
    initial_snapshot = monitor.take_snapshot(f"{component_name}_start")
    
    try:
        yield monitor
    finally:
        # Final snapshot
        gc.collect()
        final_snapshot = monitor.take_snapshot(f"{component_name}_end")
        
        # Calculate and print delta
        delta = monitor.calculate_delta(initial_snapshot, final_snapshot)
        print(f"\n📊 Memory Profile for {component_name}:")
        print(f"   RSS Delta: {delta.rss_delta_mb:+.2f} MB")
        print(f"   Duration: {delta.duration_seconds:.2f}s")
        print(f"   Growth Rate: {delta.growth_rate_mb_per_sec:.3f} MB/s")
        print(f"   GC Collections: {delta.gc_delta}")
        print(f"   Objects Delta: {delta.objects_delta:+d}")
        
        # Stop profiling
        if tracemalloc.is_tracing():
            tracemalloc.stop()


@asynccontextmanager
async def async_memory_profiling_context(component_name: str = "async_test"):
    """Async context manager for memory profiling"""
    monitor = MemoryMonitor()
    
    # Start profiling
    tracemalloc.start()
    gc.collect()
    
    initial_snapshot = monitor.take_snapshot(f"{component_name}_start")
    
    try:
        yield monitor
    finally:
        # Final snapshot
        gc.collect()
        final_snapshot = monitor.take_snapshot(f"{component_name}_end")
        
        # Calculate and print delta
        delta = monitor.calculate_delta(initial_snapshot, final_snapshot)
        print(f"\n📊 Async Memory Profile for {component_name}:")
        print(f"   RSS Delta: {delta.rss_delta_mb:+.2f} MB")
        print(f"   Duration: {delta.duration_seconds:.2f}s")
        print(f"   Growth Rate: {delta.growth_rate_mb_per_sec:.3f} MB/s")
        print(f"   GC Collections: {delta.gc_delta}")
        print(f"   Objects Delta: {delta.objects_delta:+d}")
        
        # Stop profiling
        if tracemalloc.is_tracing():
            tracemalloc.stop()


def measure_memory_usage(func: Callable) -> Callable:
    """Decorator to measure memory usage of functions"""
    def wrapper(*args, **kwargs):
        with memory_profiling_context(func.__name__) as monitor:
            result = func(*args, **kwargs)
        return result
    return wrapper


def measure_async_memory_usage(func: Callable) -> Callable:
    """Decorator to measure memory usage of async functions"""
    async def wrapper(*args, **kwargs):
        async with async_memory_profiling_context(func.__name__) as monitor:
            result = await func(*args, **kwargs)
        return result
    return wrapper


class MemoryPressureSimulator:
    """Simulate memory pressure for testing"""
    
    def __init__(self):
        self.pressure_objects = []
        self.pressure_active = False
    
    def create_memory_pressure(self, target_mb: int, chunk_size_mb: int = 10):
        """Create memory pressure by allocating objects"""
        self.pressure_objects = []
        
        chunks_needed = target_mb // chunk_size_mb
        chunk_size_bytes = chunk_size_mb * 1024 * 1024
        
        for i in range(chunks_needed):
            try:
                chunk = bytearray(chunk_size_bytes)
                self.pressure_objects.append(chunk)
            except MemoryError:
                print(f"Memory pressure creation failed at {i * chunk_size_mb}MB")
                break
        
        self.pressure_active = True
        return len(self.pressure_objects) * chunk_size_mb
    
    def release_memory_pressure(self):
        """Release memory pressure"""
        self.pressure_objects.clear()
        gc.collect()
        self.pressure_active = False
    
    @contextmanager
    def memory_pressure_context(self, target_mb: int):
        """Context manager for memory pressure"""
        try:
            actual_mb = self.create_memory_pressure(target_mb)
            print(f"Created {actual_mb}MB memory pressure")
            yield actual_mb
        finally:
            self.release_memory_pressure()


class GCController:
    """Control garbage collection for testing"""
    
    def __init__(self):
        self.original_thresholds = gc.get_threshold()
        self.original_debug = gc.get_debug()
    
    def disable_gc(self):
        """Disable automatic garbage collection"""
        gc.disable()
    
    def enable_gc(self):
        """Enable automatic garbage collection"""
        gc.enable()
    
    def set_aggressive_gc(self):
        """Set aggressive GC thresholds"""
        gc.set_threshold(10, 5, 5)  # Very aggressive
    
    def set_conservative_gc(self):
        """Set conservative GC thresholds"""
        gc.set_threshold(2000, 200, 20)  # Very conservative
    
    def restore_gc_settings(self):
        """Restore original GC settings"""
        gc.set_threshold(*self.original_thresholds)
        gc.set_debug(self.original_debug)
    
    @contextmanager
    def gc_control_context(self, mode: str = "disabled"):
        """Context manager for GC control"""
        try:
            if mode == "disabled":
                self.disable_gc()
            elif mode == "aggressive":
                self.set_aggressive_gc()
            elif mode == "conservative":
                self.set_conservative_gc()
            
            yield
        finally:
            self.restore_gc_settings()
            self.enable_gc()


def get_memory_info() -> Dict[str, float]:
    """Get current memory information"""
    process = psutil.Process()
    memory_info = process.memory_info()
    virtual_mem = psutil.virtual_memory()
    
    return {
        'rss_mb': memory_info.rss / 1024 / 1024,
        'vms_mb': memory_info.vms / 1024 / 1024,
        'available_mb': virtual_mem.available / 1024 / 1024,
        'used_percent': virtual_mem.percent,
        'gc_objects': len(gc.get_objects()),
        'gc_counts': list(gc.get_count())
    }


def format_memory_size(bytes_value: int) -> str:
    """Format memory size in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"


def check_memory_available(required_mb: int) -> bool:
    """Check if enough memory is available"""
    virtual_mem = psutil.virtual_memory()
    available_mb = virtual_mem.available / 1024 / 1024
    return available_mb >= required_mb


async def wait_for_memory_stabilization(timeout: float = 10.0, threshold_mb: float = 1.0) -> bool:
    """Wait for memory usage to stabilize"""
    monitor = MemoryMonitor()
    start_time = time.time()
    
    # Take initial snapshot
    previous_snapshot = monitor.take_snapshot("stabilization_start")
    stable_count = 0
    
    while time.time() - start_time < timeout:
        await asyncio.sleep(0.5)
        
        current_snapshot = monitor.take_snapshot("stabilization_check")
        delta = monitor.calculate_delta(previous_snapshot, current_snapshot)
        
        if abs(delta.rss_delta_mb) < threshold_mb:
            stable_count += 1
            if stable_count >= 3:  # Stable for 3 consecutive checks
                return True
        else:
            stable_count = 0
        
        previous_snapshot = current_snapshot
    
    return False


class MemoryTestHelper:
    """Helper class for common memory testing patterns"""
    
    @staticmethod
    def create_test_objects(count: int, size_kb: int = 1) -> List[Dict]:
        """Create test objects of specified size"""
        objects = []
        data_size = 'x' * (size_kb * 1024)
        
        for i in range(count):
            obj = {
                'id': i,
                'data': data_size,
                'metadata': {
                    'created': time.time(),
                    'type': 'test_object'
                }
            }
            objects.append(obj)
        
        return objects
    
    @staticmethod
    def create_circular_references(count: int) -> List[Dict]:
        """Create objects with circular references for GC testing"""
        objects = []
        
        for i in range(count):
            obj = {'id': i, 'data': f'circular_{i}'}
            objects.append(obj)
        
        # Create circular references
        for i in range(count):
            objects[i]['next'] = objects[(i + 1) % count]
            objects[i]['prev'] = objects[(i - 1) % count]
        
        return objects
    
    @staticmethod
    def simulate_memory_leak(iterations: int, leak_size_kb: int = 1) -> List:
        """Simulate a memory leak by accumulating objects"""
        leaked_objects = []
        
        for i in range(iterations):
            # Create object that won't be collected
            leak_obj = {
                'iteration': i,
                'data': 'x' * (leak_size_kb * 1024),
                'timestamp': time.time()
            }
            leaked_objects.append(leak_obj)
        
        return leaked_objects


# Example usage and testing
if __name__ == "__main__":
    # Test memory monitoring
    print("Testing Memory Utilities...")
    
    monitor = MemoryMonitor()
    
    with memory_profiling_context("test_operation"):
        # Simulate some memory usage
        test_objects = MemoryTestHelper.create_test_objects(1000, 10)
        time.sleep(0.1)
        
        # Create memory pressure
        simulator = MemoryPressureSimulator()
        with simulator.memory_pressure_context(50):  # 50MB pressure
            time.sleep(0.1)
    
    print("Memory utilities test completed!")