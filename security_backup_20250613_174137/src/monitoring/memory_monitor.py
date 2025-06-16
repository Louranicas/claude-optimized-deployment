"""
Memory Monitor - Real-time memory usage tracking and monitoring.

This module provides comprehensive memory monitoring capabilities including:
- Real-time memory usage tracking
- Component-specific memory monitoring
- Historical data collection
- Memory pressure detection
- Integration with Prometheus metrics
"""

import os
import psutil
import asyncio
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass, field
import logging
from prometheus_client import Gauge, Histogram, Counter, generate_latest

from ..core.logging_config import get_logger
from ..core.exceptions import MonitoringError

__all__ = [
    "MemorySnapshot",
    "MemoryTrend",
    "MemoryMonitor",
    "get_memory_monitor",
    "shutdown_memory_monitor"
]


logger = get_logger(__name__)

# Prometheus metrics
memory_usage_gauge = Gauge(
    'memory_usage_bytes',
    'Current memory usage in bytes',
    ['component', 'memory_type']
)

memory_usage_percent_gauge = Gauge(
    'memory_usage_percent',
    'Current memory usage percentage',
    ['component']
)

memory_pressure_gauge = Gauge(
    'memory_pressure_level',
    'Current memory pressure level (0-4)',
    ['component']
)

memory_allocation_histogram = Histogram(
    'memory_allocation_bytes',
    'Memory allocation size distribution',
    ['component'],
    buckets=(1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824)
)

memory_cleanup_counter = Counter(
    'memory_cleanup_total',
    'Total number of memory cleanup operations',
    ['component', 'trigger_level']
)

gc_collection_counter = Counter(
    'gc_collection_total',
    'Total number of garbage collection runs',
    ['generation']
)


@dataclass
class MemorySnapshot:
    """Represents a point-in-time memory snapshot."""
    timestamp: datetime
    total_memory: int
    used_memory: int
    available_memory: int
    percent_used: float
    swap_used: int
    swap_percent: float
    component_usage: Dict[str, int] = field(default_factory=dict)
    
    @property
    def pressure_level(self) -> int:
        """Calculate memory pressure level (0-4)."""
        if self.percent_used < 70:
            return 0  # Normal
        elif self.percent_used < 80:
            return 1  # Warning
        elif self.percent_used < 90:
            return 2  # High
        elif self.percent_used < 95:
            return 3  # Critical
        else:
            return 4  # Emergency


@dataclass
class MemoryTrend:
    """Represents memory usage trend analysis."""
    current_usage: float
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    rate_of_change: float  # MB/s
    time_to_threshold: Optional[float]  # seconds to next threshold
    predicted_peak: float  # predicted peak usage percentage


class MemoryMonitor:
    """Real-time memory monitoring and tracking system."""
    
    def __init__(
        self,
        sampling_interval: float = 1.0,
        history_size: int = 3600,  # 1 hour of second-by-second data
        component_trackers: Optional[Dict[str, Any]] = None
    ):
        self.sampling_interval = sampling_interval
        self.history_size = history_size
        self.component_trackers = component_trackers or {}
        
        # Historical data storage
        self.history: deque = deque(maxlen=history_size)
        self.component_histories: Dict[str, deque] = {}
        
        # Monitoring state
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_gc_stats: Dict[int, int] = {}
        
        # Initialize component histories
        for component in self.component_trackers:
            self.component_histories[component] = deque(maxlen=history_size)
    
    def start(self) -> None:
        """Start the memory monitoring thread."""
        if self._monitoring:
            logger.warning("Memory monitoring already started")
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="MemoryMonitor"
        )
        self._monitor_thread.start()
        logger.info("Memory monitoring started")
    
    def stop(self) -> None:
        """Stop the memory monitoring thread."""
        if not self._monitoring:
            return
        
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("Memory monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop running in separate thread."""
        import gc
        
        while self._monitoring:
            try:
                # Collect memory snapshot
                snapshot = self._collect_snapshot()
                self.history.append(snapshot)
                
                # Update Prometheus metrics
                self._update_metrics(snapshot)
                
                # Track garbage collection
                self._track_gc_stats()
                
                # Component-specific monitoring
                self._monitor_components(snapshot)
                
                # Sleep until next sample
                time.sleep(self.sampling_interval)
                
            except Exception as e:
                logger.error(f"Error in memory monitor loop: {e}")
                time.sleep(self.sampling_interval)
    
    def _collect_snapshot(self) -> MemorySnapshot:
        """Collect current memory usage snapshot."""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Get process-specific memory if available
        try:
            process = psutil.Process(os.getpid())
            process_memory = process.memory_info()
            rss = process_memory.rss
        except Exception:
            rss = memory.used
        
        # Collect component-specific usage
        component_usage = {}
        for component, tracker in self.component_trackers.items():
            try:
                if hasattr(tracker, 'get_memory_usage'):
                    component_usage[component] = tracker.get_memory_usage()
                elif hasattr(tracker, 'memory_usage'):
                    component_usage[component] = tracker.memory_usage
            except Exception as e:
                logger.error(f"Error tracking {component} memory: {e}")
        
        return MemorySnapshot(
            timestamp=datetime.now(),
            total_memory=memory.total,
            used_memory=rss,
            available_memory=memory.available,
            percent_used=memory.percent,
            swap_used=swap.used,
            swap_percent=swap.percent,
            component_usage=component_usage
        )
    
    def _update_metrics(self, snapshot: MemorySnapshot) -> None:
        """Update Prometheus metrics with snapshot data."""
        # System-wide metrics
        memory_usage_gauge.labels(
            component='system',
            memory_type='physical'
        ).set(snapshot.used_memory)
        
        memory_usage_gauge.labels(
            component='system',
            memory_type='swap'
        ).set(snapshot.swap_used)
        
        memory_usage_percent_gauge.labels(
            component='system'
        ).set(snapshot.percent_used)
        
        memory_pressure_gauge.labels(
            component='system'
        ).set(snapshot.pressure_level)
        
        # Component-specific metrics
        for component, usage in snapshot.component_usage.items():
            memory_usage_gauge.labels(
                component=component,
                memory_type='rss'
            ).set(usage)
            
            # Calculate component percentage
            component_percent = (usage / snapshot.total_memory) * 100
            memory_usage_percent_gauge.labels(
                component=component
            ).set(component_percent)
    
    def _track_gc_stats(self) -> None:
        """Track garbage collection statistics."""
        import gc
        
        for generation in range(gc.get_count().__len__()):
            stats = gc.get_stats()[generation]
            collections = stats.get('collections', 0)
            
            # Track new collections
            if generation in self._last_gc_stats:
                new_collections = collections - self._last_gc_stats[generation]
                if new_collections > 0:
                    gc_collection_counter.labels(
                        generation=str(generation)
                    ).inc(new_collections)
            
            self._last_gc_stats[generation] = collections
    
    def _monitor_components(self, snapshot: MemorySnapshot) -> None:
        """Monitor component-specific memory usage."""
        for component, usage in snapshot.component_usage.items():
            if component not in self.component_histories:
                self.component_histories[component] = deque(maxlen=self.history_size)
            
            self.component_histories[component].append({
                'timestamp': snapshot.timestamp,
                'usage': usage,
                'percent': (usage / snapshot.total_memory) * 100
            })
    
    def get_current_snapshot(self) -> Optional[MemorySnapshot]:
        """Get the most recent memory snapshot."""
        if not self.history:
            return None
        return self.history[-1]
    
    def get_memory_trend(self, window_seconds: int = 300) -> MemoryTrend:
        """Analyze memory usage trend over specified window."""
        if len(self.history) < 2:
            return MemoryTrend(
                current_usage=0.0,
                trend_direction='stable',
                rate_of_change=0.0,
                time_to_threshold=None,
                predicted_peak=0.0
            )
        
        # Get samples within window
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        window_samples = [
            s for s in self.history
            if s.timestamp >= window_start
        ]
        
        if len(window_samples) < 2:
            current = self.history[-1]
            return MemoryTrend(
                current_usage=current.percent_used,
                trend_direction='stable',
                rate_of_change=0.0,
                time_to_threshold=None,
                predicted_peak=current.percent_used
            )
        
        # Calculate trend
        first = window_samples[0]
        last = window_samples[-1]
        time_diff = (last.timestamp - first.timestamp).total_seconds()
        
        if time_diff == 0:
            rate_of_change = 0.0
        else:
            # MB/s
            memory_diff = (last.used_memory - first.used_memory) / (1024 * 1024)
            rate_of_change = memory_diff / time_diff
        
        # Determine trend direction
        if rate_of_change > 0.1:  # More than 100KB/s increase
            trend_direction = 'increasing'
        elif rate_of_change < -0.1:  # More than 100KB/s decrease
            trend_direction = 'decreasing'
        else:
            trend_direction = 'stable'
        
        # Calculate time to next threshold
        time_to_threshold = None
        if trend_direction == 'increasing' and rate_of_change > 0:
            current_percent = last.percent_used
            next_threshold = None
            
            if current_percent < 70:
                next_threshold = 70
            elif current_percent < 80:
                next_threshold = 80
            elif current_percent < 90:
                next_threshold = 90
            elif current_percent < 95:
                next_threshold = 95
            
            if next_threshold:
                percent_to_threshold = next_threshold - current_percent
                mb_to_threshold = (last.total_memory * percent_to_threshold / 100) / (1024 * 1024)
                time_to_threshold = mb_to_threshold / rate_of_change
        
        # Predict peak usage
        predicted_peak = last.percent_used
        if trend_direction == 'increasing' and time_to_threshold:
            # Predict usage in next 15 minutes
            prediction_window = min(900, time_to_threshold)  # 15 minutes or time to threshold
            predicted_increase = rate_of_change * prediction_window * 1024 * 1024
            predicted_usage = last.used_memory + predicted_increase
            predicted_peak = min(100.0, (predicted_usage / last.total_memory) * 100)
        
        return MemoryTrend(
            current_usage=last.percent_used,
            trend_direction=trend_direction,
            rate_of_change=rate_of_change,
            time_to_threshold=time_to_threshold,
            predicted_peak=predicted_peak
        )
    
    def get_component_trend(self, component: str, window_seconds: int = 300) -> Optional[MemoryTrend]:
        """Get memory trend for specific component."""
        if component not in self.component_histories:
            return None
        
        history = self.component_histories[component]
        if len(history) < 2:
            return None
        
        # Similar analysis as system trend but for component
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        window_samples = [
            s for s in history
            if s['timestamp'] >= window_start
        ]
        
        if len(window_samples) < 2:
            return None
        
        first = window_samples[0]
        last = window_samples[-1]
        time_diff = (last['timestamp'] - first['timestamp']).total_seconds()
        
        if time_diff == 0:
            rate_of_change = 0.0
        else:
            usage_diff = (last['usage'] - first['usage']) / (1024 * 1024)
            rate_of_change = usage_diff / time_diff
        
        return MemoryTrend(
            current_usage=last['percent'],
            trend_direction='increasing' if rate_of_change > 0.1 else 'decreasing' if rate_of_change < -0.1 else 'stable',
            rate_of_change=rate_of_change,
            time_to_threshold=None,  # Component-specific thresholds would need to be defined
            predicted_peak=last['percent']
        )
    
    def register_component(self, name: str, tracker: Any) -> None:
        """Register a component for memory tracking."""
        self.component_trackers[name] = tracker
        self.component_histories[name] = deque(maxlen=self.history_size)
        logger.info(f"Registered component '{name}' for memory tracking")
    
    def unregister_component(self, name: str) -> None:
        """Unregister a component from memory tracking."""
        if name in self.component_trackers:
            del self.component_trackers[name]
        if name in self.component_histories:
            del self.component_histories[name]
        logger.info(f"Unregistered component '{name}' from memory tracking")
    
    def get_metrics(self) -> bytes:
        """Get Prometheus metrics in text format."""
        return generate_latest()


# Global memory monitor instance
_memory_monitor: Optional[MemoryMonitor] = None


def get_memory_monitor() -> MemoryMonitor:
    """Get or create the global memory monitor instance."""
    global _memory_monitor
    if _memory_monitor is None:
        _memory_monitor = MemoryMonitor()
        _memory_monitor.start()
    return _memory_monitor


def shutdown_memory_monitor() -> None:
    """Shutdown the global memory monitor."""
    global _memory_monitor
    if _memory_monitor is not None:
        _memory_monitor.stop()
        _memory_monitor = None