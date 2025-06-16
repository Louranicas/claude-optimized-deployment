"""
Enhanced memory metrics collection for proactive memory monitoring.

This module provides comprehensive memory metrics that would have prevented
the fatal memory issue by detecting problems early.
"""

import gc
import os
import sys
import time
import psutil
import tracemalloc
import resource
import threading
import statistics
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from prometheus_client import (
    Counter, Gauge, Histogram, Summary, Info,
    CollectorRegistry, generate_latest
)

__all__ = [
    "MemorySnapshot",
    "GCStats",
    "EnhancedMemoryMetrics",
    "get_enhanced_memory_metrics",
    "record_memory_allocation",
    "record_memory_event",
    "monitor_memory_usage"
]

from .metrics import get_metrics_collector
from ..core.log_sanitization import sanitize_for_logging, SanitizationLevel


@dataclass
class MemorySnapshot:
    """Snapshot of memory state at a point in time."""
    timestamp: datetime
    rss_bytes: int
    vms_bytes: int
    available_bytes: int
    percent_used: float
    gc_objects: int
    open_files: int
    threads: int
    
    
@dataclass
class GCStats:
    """Garbage collection statistics."""
    collections: Dict[int, int]
    collected_objects: Dict[int, int]
    uncollectable_objects: Dict[int, int]
    collection_time: float


class EnhancedMemoryMetrics:
    """Enhanced memory metrics collection for proactive monitoring."""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or get_metrics_collector().registry
        self._setup_metrics()
        self._init_tracking()
        
        # Start background monitoring
        self._monitoring_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitoring_active = True
        self._monitoring_thread.start()
    
    def _setup_metrics(self):
        """Setup all memory-related metrics."""
        
        # Python-specific memory metrics
        self.python_gc_objects_collected = Counter(
            'python_gc_objects_collected_total',
            'Objects collected during gc',
            ['generation'],
            registry=self.registry
        )
        
        self.python_gc_objects_uncollectable = Counter(
            'python_gc_objects_uncollectable_total', 
            'Uncollectable objects found during gc',
            ['generation'],
            registry=self.registry
        )
        
        self.python_gc_collections = Counter(
            'python_gc_collections_total',
            'Number of garbage collections',
            ['generation'],
            registry=self.registry
        )
        
        self.python_gc_time_seconds = Counter(
            'python_gc_time_seconds_total',
            'Time spent in garbage collection',
            ['generation'], 
            registry=self.registry
        )
        
        self.python_memory_objects = Gauge(
            'python_memory_objects_total',
            'Number of objects by type',
            ['type'],
            registry=self.registry
        )
        
        self.python_memory_heap_size = Gauge(
            'python_memory_heap_size_bytes',
            'Python heap size in bytes',
            registry=self.registry
        )
        
        self.python_memory_heap_free = Gauge(
            'python_memory_heap_free_bytes',
            'Python heap free bytes',
            registry=self.registry
        )
        
        # Process memory metrics
        self.process_memory_peak_rss = Gauge(
            'process_memory_peak_rss_bytes',
            'Peak RSS memory usage',
            registry=self.registry
        )
        
        self.memory_growth_rate = Gauge(
            'memory_growth_rate_bytes_per_second',
            'Memory growth rate',
            registry=self.registry
        )
        
        self.memory_growth_rate_5m = Gauge(
            'memory_growth_rate_5m_bytes_per_second',
            'Memory growth rate over 5 minutes',
            registry=self.registry
        )
        
        self.memory_allocation_rate = Gauge(
            'memory_allocation_rate_bytes_per_second',
            'Memory allocation rate',
            registry=self.registry
        )
        
        # Memory pressure and health metrics
        self.memory_pressure_index = Gauge(
            'memory_pressure_index',
            'Memory pressure index (0-100)',
            registry=self.registry
        )
        
        self.memory_health_score = Gauge(
            'memory_health_score',
            'Memory health score (0-100)',
            registry=self.registry
        )
        
        self.memory_leak_confidence = Gauge(
            'memory_leak_confidence_score',
            'Memory leak confidence score (0-100)',
            registry=self.registry
        )
        
        # Memory fragmentation
        self.memory_fragmentation_percent = Gauge(
            'memory_fragmentation_percent',
            'Memory fragmentation percentage',
            registry=self.registry
        )
        
        # Predictive metrics
        self.memory_exhaustion_time_seconds = Gauge(
            'memory_exhaustion_time_seconds',
            'Predicted time until memory exhaustion',
            registry=self.registry
        )
        
        # GC efficiency metrics
        self.gc_efficiency_score = Gauge(
            'gc_efficiency_score',
            'Garbage collection efficiency score (0-100)',
            registry=self.registry
        )
        
        self.gc_cpu_overhead_percent = Gauge(
            'gc_cpu_overhead_percent',
            'CPU overhead from garbage collection',
            registry=self.registry
        )
        
        # Memory allocation patterns
        self.memory_allocation_histogram = Histogram(
            'memory_allocation_bytes',
            'Memory allocation size distribution',
            buckets=(1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216),
            registry=self.registry
        )
        
        # Thread and resource metrics
        self.open_file_descriptors = Gauge(
            'open_file_descriptors_total',
            'Number of open file descriptors',
            registry=self.registry
        )
        
        self.thread_count = Gauge(
            'thread_count_total',
            'Number of active threads',
            registry=self.registry
        )
        
        # Memory events counter
        self.memory_events = Counter(
            'memory_events_total',
            'Memory-related events',
            ['event_type'],
            registry=self.registry
        )
    
    def _init_tracking(self):
        """Initialize memory tracking state."""
        # Enable tracemalloc for detailed memory tracking
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        
        # Initialize tracking variables
        self._last_memory_check = time.time()
        self._last_memory_value = 0
        self._memory_history: List[MemorySnapshot] = []
        self._gc_stats_history: List[GCStats] = []
        self._last_gc_stats = self._get_gc_stats()
        
        # Baseline calculation
        self._baseline_collection_start = time.time()
        self._baseline_samples: List[MemorySnapshot] = []
        self._memory_baseline: Optional[Dict[str, float]] = None
        
        # Leak detection state
        self._sustained_growth_start: Optional[float] = None
        self._last_leak_check = time.time()
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._monitoring_active:
            try:
                self.update_all_metrics()
                time.sleep(10)  # Update every 10 seconds
            except Exception as e:
                # Log error but don't crash monitoring
                import logging
                logger = logging.getLogger(__name__)
                safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "monitor_error")
                logger.error(f"Memory monitoring error: {safe_error}")
                time.sleep(30)  # Wait longer on error
    
    def update_all_metrics(self):
        """Update all memory metrics."""
        try:
            self._update_python_memory_metrics()
            self._update_process_memory_metrics()
            self._update_gc_metrics()
            self._update_health_metrics()
            self._update_predictive_metrics()
            self._collect_memory_snapshot()
            self._check_baseline_collection()
            
        except Exception as e:
            # Don't let metrics collection affect the application
            self.memory_events.labels(event_type='metrics_error').inc()
    
    def _update_python_memory_metrics(self):
        """Update Python-specific memory metrics."""
        try:
            # Object counts by type
            object_counts = {}
            total_objects = 0
            
            # Sample objects to avoid performance impact
            objects = gc.get_objects()
            sample_size = min(len(objects), 10000)  # Sample max 10k objects
            
            for obj in objects[:sample_size]:
                obj_type = type(obj).__name__
                object_counts[obj_type] = object_counts.get(obj_type, 0) + 1
                total_objects += 1
            
            # Scale up to estimate total
            scale_factor = len(objects) / sample_size if sample_size > 0 else 1
            
            # Only track major object types to avoid label explosion
            major_types = ['dict', 'list', 'tuple', 'set', 'function', 'type', 'module', 'frame']
            for obj_type in major_types:
                count = object_counts.get(obj_type, 0) * scale_factor
                self.python_memory_objects.labels(type=obj_type).set(count)
            
            # Tracemalloc statistics
            if tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                self.python_memory_heap_size.set(current)
                # Estimate free heap (this is approximate)
                estimated_free = max(0, peak - current)
                self.python_memory_heap_free.set(estimated_free)
            
        except Exception:
            self.memory_events.labels(event_type='python_metrics_error').inc()
    
    def _update_process_memory_metrics(self):
        """Update process-level memory metrics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            # Basic memory info
            current_memory = memory_info.rss
            
            # Calculate memory growth rate
            current_time = time.time()
            if self._last_memory_value > 0:
                time_diff = current_time - self._last_memory_check
                if time_diff > 0:
                    memory_diff = current_memory - self._last_memory_value
                    growth_rate = memory_diff / time_diff
                    self.memory_growth_rate.set(growth_rate)
                    
                    # 5-minute growth rate from history
                    five_min_ago = current_time - 300  # 5 minutes
                    old_samples = [s for s in self._memory_history if s.timestamp.timestamp() >= five_min_ago]
                    if old_samples:
                        oldest_sample = min(old_samples, key=lambda s: s.timestamp)
                        time_diff_5m = current_time - oldest_sample.timestamp.timestamp()
                        if time_diff_5m > 0:
                            memory_diff_5m = current_memory - oldest_sample.rss_bytes
                            growth_rate_5m = memory_diff_5m / time_diff_5m
                            self.memory_growth_rate_5m.set(growth_rate_5m)
            
            self._last_memory_check = current_time
            self._last_memory_value = current_memory
            
            # Peak RSS from resource module
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # Convert from KB to bytes (on Linux, ru_maxrss is in KB)
            peak_rss = usage.ru_maxrss * 1024 if sys.platform == 'linux' else usage.ru_maxrss
            self.process_memory_peak_rss.set(peak_rss)
            
            # Memory fragmentation
            if memory_info.vms > 0:
                fragmentation = ((memory_info.vms - memory_info.rss) / memory_info.vms) * 100
                self.memory_fragmentation_percent.set(fragmentation)
            
            # File descriptors and threads
            try:
                self.open_file_descriptors.set(len(process.open_files()))
                self.thread_count.set(process.num_threads())
            except (psutil.AccessDenied, OSError):
                pass
            
        except Exception:
            self.memory_events.labels(event_type='process_metrics_error').inc()
    
    def _update_gc_metrics(self):
        """Update garbage collection metrics."""
        try:
            current_stats = self._get_gc_stats()
            
            # Calculate deltas since last check
            for generation in range(3):
                # Collections delta
                collections_delta = (current_stats.collections.get(generation, 0) - 
                                   self._last_gc_stats.collections.get(generation, 0))
                if collections_delta > 0:
                    self.python_gc_collections.labels(generation=str(generation)).inc(collections_delta)
                
                # Objects collected delta
                collected_delta = (current_stats.collected_objects.get(generation, 0) - 
                                 self._last_gc_stats.collected_objects.get(generation, 0))
                if collected_delta > 0:
                    self.python_gc_objects_collected.labels(generation=str(generation)).inc(collected_delta)
                
                # Uncollectable objects delta  
                uncollectable_delta = (current_stats.uncollectable_objects.get(generation, 0) - 
                                     self._last_gc_stats.uncollectable_objects.get(generation, 0))
                if uncollectable_delta > 0:
                    self.python_gc_objects_uncollectable.labels(generation=str(generation)).inc(uncollectable_delta)
            
            # GC time (estimate based on collection frequency)
            total_collections = sum(current_stats.collections.values())
            last_total_collections = sum(self._last_gc_stats.collections.values())
            collections_delta = total_collections - last_total_collections
            
            if collections_delta > 0:
                # Estimate GC time (this is approximate)
                estimated_gc_time = collections_delta * 0.001  # Assume 1ms per collection average
                self.python_gc_time_seconds.labels(generation='all').inc(estimated_gc_time)
                
                # Calculate GC efficiency
                total_collected = sum(current_stats.collected_objects.values())
                last_total_collected = sum(self._last_gc_stats.collected_objects.values())
                collected_delta = total_collected - last_total_collected
                
                if collections_delta > 0:
                    efficiency = min(100, (collected_delta / collections_delta) / 100)  # Objects per collection
                    self.gc_efficiency_score.set(efficiency)
                
                # CPU overhead estimate
                cpu_overhead = min(100, collections_delta * 0.1)  # Rough estimate
                self.gc_cpu_overhead_percent.set(cpu_overhead)
            
            self._last_gc_stats = current_stats
            
        except Exception:
            self.memory_events.labels(event_type='gc_metrics_error').inc()
    
    def _update_health_metrics(self):
        """Update memory health and pressure metrics."""
        try:
            # Get current memory state
            memory = psutil.virtual_memory()
            process = psutil.Process()
            process_memory = process.memory_info()
            
            # Memory pressure index calculation
            usage_factor = memory.percent * 0.4
            
            # Growth rate factor
            growth_factor = 0
            if hasattr(self, '_last_memory_value') and self._last_memory_value > 0:
                current_time = time.time()
                time_diff = current_time - self._last_memory_check
                if time_diff > 0:
                    growth_rate = (process_memory.rss - self._last_memory_value) / time_diff
                    growth_factor = min(50, (growth_rate / 1048576) * 10) * 0.3  # MB/s scaled
            
            # GC pressure factor
            gc_factor = min(50, self.gc_cpu_overhead_percent._value.get() or 0) * 0.2
            
            # Swap factor
            swap_total = psutil.swap_memory().total
            swap_factor = 0
            if swap_total > 0:
                swap_percent = (psutil.swap_memory().used / swap_total) * 100
                swap_factor = min(50, swap_percent) * 0.1
            
            pressure_index = usage_factor + growth_factor + gc_factor + swap_factor
            self.memory_pressure_index.set(pressure_index)
            
            # Memory health score (100 = perfect, 0 = critical)
            health_score = max(0, 100 - (
                max(0, memory.percent - 50) * 0.8 +  # Penalty after 50% usage
                min(40, growth_factor * 2) +          # Growth penalty
                min(20, gc_factor * 2) +              # GC penalty
                min(10, self.memory_fragmentation_percent._value.get() or 0 * 0.5)  # Fragmentation penalty
            ))
            self.memory_health_score.set(health_score)
            
            # Memory leak confidence
            leak_confidence = self._calculate_leak_confidence()
            self.memory_leak_confidence.set(leak_confidence)
            
        except Exception:
            self.memory_events.labels(event_type='health_metrics_error').inc()
    
    def _update_predictive_metrics(self):
        """Update predictive memory metrics."""
        try:
            memory = psutil.virtual_memory()
            
            # Predict memory exhaustion time
            if len(self._memory_history) >= 2:
                # Use linear regression on recent memory usage
                recent_samples = self._memory_history[-10:]  # Last 10 samples
                if len(recent_samples) >= 2:
                    times = [(s.timestamp.timestamp() - recent_samples[0].timestamp.timestamp()) 
                            for s in recent_samples]
                    memory_values = [s.rss_bytes for s in recent_samples]
                    
                    # Simple linear regression
                    n = len(times)
                    sum_t = sum(times)
                    sum_m = sum(memory_values)
                    sum_tm = sum(t * m for t, m in zip(times, memory_values))
                    sum_t2 = sum(t * t for t in times)
                    
                    denominator = n * sum_t2 - sum_t * sum_t
                    if denominator != 0:
                        slope = (n * sum_tm - sum_t * sum_m) / denominator
                        
                        if slope > 0:  # Memory is growing
                            current_memory = memory_values[-1]
                            available_memory = memory.available
                            
                            # Time until exhaustion
                            exhaustion_time = available_memory / slope
                            self.memory_exhaustion_time_seconds.set(max(0, exhaustion_time))
                        else:
                            self.memory_exhaustion_time_seconds.set(0)
            
        except Exception:
            self.memory_events.labels(event_type='predictive_metrics_error').inc()
    
    def _get_gc_stats(self) -> GCStats:
        """Get current garbage collection statistics."""
        stats = gc.get_stats()
        
        collections = {}
        collected_objects = {}
        uncollectable_objects = {}
        
        for i, gen_stats in enumerate(stats):
            collections[i] = gen_stats.get('collections', 0)
            collected_objects[i] = gen_stats.get('collected', 0)
            uncollectable_objects[i] = gen_stats.get('uncollectable', 0)
        
        return GCStats(
            collections=collections,
            collected_objects=collected_objects,
            uncollectable_objects=uncollectable_objects,
            collection_time=0  # Not available in Python's GC stats
        )
    
    def _collect_memory_snapshot(self):
        """Collect a memory snapshot for history tracking."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            snapshot = MemorySnapshot(
                timestamp=datetime.now(),
                rss_bytes=memory_info.rss,
                vms_bytes=memory_info.vms,
                available_bytes=system_memory.available,
                percent_used=system_memory.percent,
                gc_objects=len(gc.get_objects()) if len(gc.get_objects()) < 100000 else -1,  # Skip if too many
                open_files=len(process.open_files()),
                threads=process.num_threads()
            )
            
            self._memory_history.append(snapshot)
            
            # Keep only last hour of snapshots (360 samples at 10s intervals)
            if len(self._memory_history) > 360:
                self._memory_history = self._memory_history[-360:]
            
            # Add to baseline collection if still collecting
            if len(self._baseline_samples) < 2880:  # 24 hours worth (10s intervals)
                self._baseline_samples.append(snapshot)
                
        except Exception:
            self.memory_events.labels(event_type='snapshot_error').inc()
    
    def _check_baseline_collection(self):
        """Check if baseline collection is complete and calculate baseline."""
        if (self._memory_baseline is None and 
            len(self._baseline_samples) >= 144):  # At least 24 minutes of data
            
            try:
                self._memory_baseline = self._calculate_baseline()
            except Exception:
                self.memory_events.labels(event_type='baseline_error').inc()
    
    def _calculate_baseline(self) -> Dict[str, float]:
        """Calculate memory baseline statistics."""
        if not self._baseline_samples:
            return {}
        
        rss_values = [s.rss_bytes for s in self._baseline_samples]
        percent_values = [s.percent_used for s in self._baseline_samples]
        
        baseline = {
            'rss_mean': statistics.mean(rss_values),
            'rss_median': statistics.median(rss_values),
            'rss_std': statistics.stdev(rss_values) if len(rss_values) > 1 else 0,
            'rss_p95': statistics.quantiles(rss_values, n=20)[18] if len(rss_values) >= 20 else max(rss_values),
            'percent_mean': statistics.mean(percent_values),
            'percent_p95': statistics.quantiles(percent_values, n=20)[18] if len(percent_values) >= 20 else max(percent_values),
        }
        
        return baseline
    
    def _calculate_leak_confidence(self) -> float:
        """Calculate memory leak confidence score (0-100)."""
        try:
            if len(self._memory_history) < 6:  # Need at least 1 minute of data
                return 0
            
            recent_samples = self._memory_history[-30:]  # Last 5 minutes
            
            # Check for sustained growth
            growth_periods = 0
            total_periods = len(recent_samples) - 1
            
            for i in range(1, len(recent_samples)):
                if recent_samples[i].rss_bytes > recent_samples[i-1].rss_bytes:
                    growth_periods += 1
            
            if total_periods == 0:
                return 0
            
            growth_ratio = growth_periods / total_periods
            
            # Calculate growth rate
            if len(recent_samples) >= 2:
                time_span = (recent_samples[-1].timestamp - recent_samples[0].timestamp).total_seconds()
                if time_span > 0:
                    memory_growth = recent_samples[-1].rss_bytes - recent_samples[0].rss_bytes
                    growth_rate_mb_per_min = (memory_growth / 1048576) / (time_span / 60)
                    
                    # Confidence based on growth consistency and rate
                    consistency_factor = growth_ratio * 50  # 0-50 points
                    rate_factor = min(50, growth_rate_mb_per_min * 5)  # 0-50 points
                    
                    confidence = consistency_factor + rate_factor
                    
                    # Track sustained growth periods
                    current_time = time.time()
                    if growth_rate_mb_per_min > 1:  # Growing more than 1MB/min
                        if self._sustained_growth_start is None:
                            self._sustained_growth_start = current_time
                    else:
                        self._sustained_growth_start = None
                    
                    # Add duration factor if sustained growth
                    if self._sustained_growth_start:
                        duration_hours = (current_time - self._sustained_growth_start) / 3600
                        duration_factor = min(20, duration_hours * 5)  # Up to 20 more points
                        confidence += duration_factor
                    
                    return min(100, confidence)
            
            return 0
            
        except Exception:
            return 0
    
    def get_memory_health_report(self) -> Dict[str, Any]:
        """Get comprehensive memory health report."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'memory_usage': {
                    'rss_mb': memory_info.rss / 1024 / 1024,
                    'vms_mb': memory_info.vms / 1024 / 1024,
                    'percent': process.memory_percent(),
                    'available_mb': system_memory.available / 1024 / 1024,
                },
                'health_metrics': {
                    'pressure_index': self.memory_pressure_index._value.get() or 0,
                    'health_score': self.memory_health_score._value.get() or 0,
                    'leak_confidence': self.memory_leak_confidence._value.get() or 0,
                    'fragmentation_percent': self.memory_fragmentation_percent._value.get() or 0,
                },
                'growth_metrics': {
                    'growth_rate_bytes_per_sec': self.memory_growth_rate._value.get() or 0,
                    'growth_rate_5m_bytes_per_sec': self.memory_growth_rate_5m._value.get() or 0,
                },
                'gc_metrics': {
                    'efficiency_score': self.gc_efficiency_score._value.get() or 0,
                    'cpu_overhead_percent': self.gc_cpu_overhead_percent._value.get() or 0,
                },
                'predictive': {
                    'exhaustion_time_seconds': self.memory_exhaustion_time_seconds._value.get() or 0,
                },
                'baseline': self._memory_baseline,
                'history_samples': len(self._memory_history)
            }
            
            return report
            
        except Exception as e:
            return {'error': sanitize_for_logging(str(e), SanitizationLevel.STRICT, "health_report_error")}
    
    def force_gc_and_measure(self) -> Dict[str, Any]:
        """Force garbage collection and measure impact."""
        try:
            # Measure before GC
            before_memory = psutil.Process().memory_info().rss
            before_objects = len(gc.get_objects())
            
            # Force GC for all generations
            collected_counts = []
            start_time = time.time()
            
            for generation in range(3):
                collected = gc.collect(generation)
                collected_counts.append(collected)
            
            gc_time = time.time() - start_time
            
            # Measure after GC
            after_memory = psutil.Process().memory_info().rss
            after_objects = len(gc.get_objects())
            
            result = {
                'gc_time_seconds': gc_time,
                'memory_freed_mb': (before_memory - after_memory) / 1024 / 1024,
                'objects_before': before_objects,
                'objects_after': after_objects,
                'objects_collected': collected_counts,
                'memory_before_mb': before_memory / 1024 / 1024,
                'memory_after_mb': after_memory / 1024 / 1024,
            }
            
            # Record the GC event
            self.memory_events.labels(event_type='manual_gc').inc()
            
            return result
            
        except Exception as e:
            return {'error': sanitize_for_logging(str(e), SanitizationLevel.STRICT, "gc_measure_error")}
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self._monitoring_active = False
        if self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=5)


# Global instance
_enhanced_memory_metrics: Optional[EnhancedMemoryMetrics] = None


def get_enhanced_memory_metrics() -> EnhancedMemoryMetrics:
    """Get the global enhanced memory metrics instance."""
    global _enhanced_memory_metrics
    if _enhanced_memory_metrics is None:
        _enhanced_memory_metrics = EnhancedMemoryMetrics()
    return _enhanced_memory_metrics


def record_memory_allocation(size_bytes: int):
    """Record a memory allocation event."""
    metrics = get_enhanced_memory_metrics()
    metrics.memory_allocation_histogram.observe(size_bytes)
    metrics.memory_events.labels(event_type='allocation').inc()


def record_memory_event(event_type: str):
    """Record a memory-related event."""
    metrics = get_enhanced_memory_metrics()
    metrics.memory_events.labels(event_type=event_type).inc()


# Decorator for monitoring memory usage of functions
def monitor_memory_usage(func_name: Optional[str] = None):
    """Decorator to monitor memory usage of functions."""
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            name = func_name or f"{func.__module__}.{func.__name__}"
            
            # Record memory before
            before_memory = psutil.Process().memory_info().rss
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Record memory after
                after_memory = psutil.Process().memory_info().rss
                memory_diff = after_memory - before_memory
                
                if memory_diff > 0:
                    record_memory_allocation(memory_diff)
                
                # Record function-specific event
                record_memory_event(f'function_{name}')
        
        return wrapper
    return decorator