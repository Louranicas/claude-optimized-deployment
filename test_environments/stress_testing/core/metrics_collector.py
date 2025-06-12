"""
Metrics Collector for Stress Testing Framework

Collects detailed performance metrics during stress testing with high precision
timing and comprehensive system monitoring capabilities.
"""

import asyncio
import time
import logging
import psutil
import threading
import json
import os
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import statistics
import numpy as np


@dataclass
class MetricPoint:
    """Single metric measurement point"""
    timestamp: float
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricSeries:
    """Time series of metric measurements"""
    name: str
    unit: str
    points: List[MetricPoint] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    
    def add_point(self, value: float, timestamp: Optional[float] = None, 
                  metadata: Optional[Dict] = None):
        """Add a measurement point"""
        point = MetricPoint(
            timestamp=timestamp or time.time(),
            value=value,
            metadata=metadata or {}
        )
        self.points.append(point)
    
    def get_values(self, start_time: Optional[float] = None, 
                   end_time: Optional[float] = None) -> List[float]:
        """Get values within time range"""
        start_time = start_time or 0
        end_time = end_time or float('inf')
        
        return [
            point.value for point in self.points
            if start_time <= point.timestamp <= end_time
        ]
    
    def get_statistics(self, start_time: Optional[float] = None, 
                      end_time: Optional[float] = None) -> Dict[str, float]:
        """Calculate statistics for time range"""
        values = self.get_values(start_time, end_time)
        
        if not values:
            return {}
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'p95': np.percentile(values, 95),
            'p99': np.percentile(values, 99)
        }


@dataclass
class SystemSnapshot:
    """Complete system state snapshot"""
    timestamp: float
    cpu_usage: float
    cpu_per_core: List[float]
    memory_usage: float
    memory_available: int
    memory_used: int
    swap_usage: float
    disk_usage: float
    disk_io_read: int
    disk_io_write: int
    network_io_sent: int
    network_io_recv: int
    load_average: List[float]
    process_count: int
    thread_count: int
    open_files: int
    network_connections: int
    temperature: Optional[float] = None


class PerformanceProfiler:
    """High-precision performance profiling"""
    
    def __init__(self, name: str):
        self.name = name
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.checkpoints: List[Tuple[str, float]] = []
        self.metadata: Dict[str, Any] = {}
    
    def start(self):
        """Start profiling"""
        self.start_time = time.perf_counter()
        self.checkpoints = [("start", self.start_time)]
    
    def checkpoint(self, name: str):
        """Add a checkpoint"""
        if self.start_time is None:
            self.start()
        
        checkpoint_time = time.perf_counter()
        self.checkpoints.append((name, checkpoint_time))
    
    def end(self):
        """End profiling"""
        self.end_time = time.perf_counter()
        self.checkpoints.append(("end", self.end_time))
    
    def get_duration(self) -> float:
        """Get total duration"""
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time
    
    def get_checkpoint_durations(self) -> Dict[str, float]:
        """Get durations between checkpoints"""
        if len(self.checkpoints) < 2:
            return {}
        
        durations = {}
        for i in range(1, len(self.checkpoints)):
            prev_name, prev_time = self.checkpoints[i-1]
            curr_name, curr_time = self.checkpoints[i]
            durations[f"{prev_name}_to_{curr_name}"] = curr_time - prev_time
        
        return durations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'total_duration': self.get_duration(),
            'checkpoint_durations': self.get_checkpoint_durations(),
            'metadata': self.metadata
        }


class MetricsCollector:
    """
    Comprehensive metrics collection for stress testing
    """
    
    def __init__(self, collection_interval: float = 0.1):
        self.collection_interval = collection_interval
        self.logger = logging.getLogger(__name__)
        
        # Metric storage
        self.metrics: Dict[str, MetricSeries] = {}
        self.snapshots: List[SystemSnapshot] = []
        self.profilers: Dict[str, PerformanceProfiler] = {}
        
        # Collection state
        self.collecting = False
        self.collection_task: Optional[asyncio.Task] = None
        self.collection_start_time: Optional[float] = None
        
        # Baseline measurements
        self.baseline: Optional[SystemSnapshot] = None
        
        # Callbacks
        self.metric_callbacks: List[Callable] = []
        
        # Configuration
        self.max_snapshots = 10000  # Limit memory usage
        self.high_precision_metrics = {
            'cpu_usage', 'memory_usage', 'load_average'
        }
        
        # Performance tracking
        self.collection_performance: List[float] = []
    
    async def start_collection(self):
        """Start metrics collection"""
        if self.collecting:
            return
        
        self.logger.info(f"Starting metrics collection (interval: {self.collection_interval}s)")
        
        self.collecting = True
        self.collection_start_time = time.time()
        self.collection_task = asyncio.create_task(self._collection_loop())
        
        # Initialize metric series
        self._initialize_metrics()
    
    async def stop_collection(self):
        """Stop metrics collection"""
        if not self.collecting:
            return
        
        self.logger.info("Stopping metrics collection")
        self.collecting = False
        
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
    
    async def emergency_stop(self):
        """Emergency stop of metrics collection"""
        self.collecting = False
        if self.collection_task:
            self.collection_task.cancel()
    
    def _initialize_metrics(self):
        """Initialize metric series"""
        metric_definitions = [
            ('cpu_usage', '%'),
            ('memory_usage', '%'),
            ('swap_usage', '%'),
            ('disk_usage', '%'),
            ('load_average_1m', 'load'),
            ('process_count', 'count'),
            ('thread_count', 'count'),
            ('network_connections', 'count'),
            ('disk_io_read_rate', 'MB/s'),
            ('disk_io_write_rate', 'MB/s'),
            ('network_io_sent_rate', 'MB/s'),
            ('network_io_recv_rate', 'MB/s'),
            ('temperature', '°C'),
            ('collection_overhead', 'ms')
        ]
        
        for name, unit in metric_definitions:
            self.metrics[name] = MetricSeries(name=name, unit=unit)
    
    async def _collection_loop(self):
        """Main metrics collection loop"""
        last_disk_io = None
        last_network_io = None
        last_collection_time = time.time()
        
        while self.collecting:
            collection_start = time.perf_counter()
            
            try:
                # Collect system snapshot
                snapshot = await self._collect_system_snapshot()
                self.snapshots.append(snapshot)
                
                # Trim snapshots if needed
                if len(self.snapshots) > self.max_snapshots:
                    self.snapshots = self.snapshots[-self.max_snapshots:]
                
                # Calculate rates for I/O metrics
                current_time = time.time()
                time_delta = current_time - last_collection_time
                
                if last_disk_io and time_delta > 0:
                    read_rate = (snapshot.disk_io_read - last_disk_io[0]) / time_delta / (1024*1024)
                    write_rate = (snapshot.disk_io_write - last_disk_io[1]) / time_delta / (1024*1024)
                    self.metrics['disk_io_read_rate'].add_point(read_rate, snapshot.timestamp)
                    self.metrics['disk_io_write_rate'].add_point(write_rate, snapshot.timestamp)
                
                if last_network_io and time_delta > 0:
                    sent_rate = (snapshot.network_io_sent - last_network_io[0]) / time_delta / (1024*1024)
                    recv_rate = (snapshot.network_io_recv - last_network_io[1]) / time_delta / (1024*1024)
                    self.metrics['network_io_sent_rate'].add_point(sent_rate, snapshot.timestamp)
                    self.metrics['network_io_recv_rate'].add_point(recv_rate, snapshot.timestamp)
                
                # Store current I/O values for next iteration
                last_disk_io = (snapshot.disk_io_read, snapshot.disk_io_write)
                last_network_io = (snapshot.network_io_sent, snapshot.network_io_recv)
                last_collection_time = current_time
                
                # Add points to metric series
                self._add_snapshot_to_metrics(snapshot)
                
                # Measure collection overhead
                collection_time = (time.perf_counter() - collection_start) * 1000
                self.metrics['collection_overhead'].add_point(collection_time, snapshot.timestamp)
                self.collection_performance.append(collection_time)
                
                # Notify callbacks
                await self._notify_metric_callbacks(snapshot)
                
                # Calculate sleep time to maintain interval
                elapsed = time.perf_counter() - collection_start
                sleep_time = max(0, self.collection_interval - elapsed)
                
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                else:
                    # Collection is taking longer than interval
                    self.logger.warning(f"Collection overhead: {elapsed:.3f}s exceeds interval")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_system_snapshot(self) -> SystemSnapshot:
        """Collect comprehensive system snapshot"""
        timestamp = time.time()
        
        # CPU metrics
        cpu_usage = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network metrics
        network_io = psutil.net_io_counters()
        
        # System metrics
        load_avg = list(os.getloadavg()) if hasattr(os, 'getloadavg') else [0.0, 0.0, 0.0]
        
        # Process metrics
        process_count = len(psutil.pids())
        
        # Thread count
        thread_count = sum(proc.num_threads() for proc in psutil.process_iter(['num_threads']) 
                          if proc.info['num_threads'])
        
        # Open files
        try:
            open_files = len(psutil.Process().open_files())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            open_files = 0
        
        # Network connections
        network_connections = len(psutil.net_connections())
        
        # Temperature
        temperature = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                all_temps = []
                for sensor_list in temps.values():
                    for sensor in sensor_list:
                        if sensor.current:
                            all_temps.append(sensor.current)
                if all_temps:
                    temperature = statistics.mean(all_temps)
        except:
            pass
        
        return SystemSnapshot(
            timestamp=timestamp,
            cpu_usage=cpu_usage,
            cpu_per_core=cpu_per_core,
            memory_usage=memory.percent,
            memory_available=memory.available,
            memory_used=memory.used,
            swap_usage=swap.percent,
            disk_usage=disk.percent,
            disk_io_read=disk_io.read_bytes if disk_io else 0,
            disk_io_write=disk_io.write_bytes if disk_io else 0,
            network_io_sent=network_io.bytes_sent if network_io else 0,
            network_io_recv=network_io.bytes_recv if network_io else 0,
            load_average=load_avg,
            process_count=process_count,
            thread_count=thread_count,
            open_files=open_files,
            network_connections=network_connections,
            temperature=temperature
        )
    
    def _add_snapshot_to_metrics(self, snapshot: SystemSnapshot):
        """Add snapshot data to metric series"""
        metric_mappings = [
            ('cpu_usage', snapshot.cpu_usage),
            ('memory_usage', snapshot.memory_usage),
            ('swap_usage', snapshot.swap_usage),
            ('disk_usage', snapshot.disk_usage),
            ('load_average_1m', snapshot.load_average[0]),
            ('process_count', snapshot.process_count),
            ('thread_count', snapshot.thread_count),
            ('network_connections', snapshot.network_connections)
        ]
        
        if snapshot.temperature is not None:
            metric_mappings.append(('temperature', snapshot.temperature))
        
        for metric_name, value in metric_mappings:
            if metric_name in self.metrics:
                self.metrics[metric_name].add_point(value, snapshot.timestamp)
    
    async def collect_baseline(self) -> SystemSnapshot:
        """Collect baseline system measurements"""
        self.logger.info("Collecting baseline measurements")
        
        # Take multiple samples for accuracy
        samples = []
        for _ in range(5):
            sample = await self._collect_system_snapshot()
            samples.append(sample)
            await asyncio.sleep(0.2)
        
        # Calculate average baseline
        baseline = SystemSnapshot(
            timestamp=samples[0].timestamp,
            cpu_usage=statistics.mean([s.cpu_usage for s in samples]),
            cpu_per_core=[statistics.mean(cores) for cores in zip(*[s.cpu_per_core for s in samples])],
            memory_usage=statistics.mean([s.memory_usage for s in samples]),
            memory_available=int(statistics.mean([s.memory_available for s in samples])),
            memory_used=int(statistics.mean([s.memory_used for s in samples])),
            swap_usage=statistics.mean([s.swap_usage for s in samples]),
            disk_usage=statistics.mean([s.disk_usage for s in samples]),
            disk_io_read=samples[0].disk_io_read,  # Use first sample for absolute values
            disk_io_write=samples[0].disk_io_write,
            network_io_sent=samples[0].network_io_sent,
            network_io_recv=samples[0].network_io_recv,
            load_average=[statistics.mean(loads) for loads in zip(*[s.load_average for s in samples])],
            process_count=int(statistics.mean([s.process_count for s in samples])),
            thread_count=int(statistics.mean([s.thread_count for s in samples])),
            open_files=int(statistics.mean([s.open_files for s in samples])),
            network_connections=int(statistics.mean([s.network_connections for s in samples])),
            temperature=statistics.mean([s.temperature for s in samples if s.temperature])
            if any(s.temperature for s in samples) else None
        )
        
        self.baseline = baseline
        self.logger.info("Baseline measurements collected")
        return baseline
    
    async def collect_metrics(self) -> Dict[str, Any]:
        """Collect current metrics summary"""
        if not self.snapshots:
            return {}
        
        current_snapshot = self.snapshots[-1]
        
        # Calculate deltas from baseline if available
        deltas = {}
        if self.baseline:
            deltas = {
                'cpu_usage_delta': current_snapshot.cpu_usage - self.baseline.cpu_usage,
                'memory_usage_delta': current_snapshot.memory_usage - self.baseline.memory_usage,
                'load_average_delta': current_snapshot.load_average[0] - self.baseline.load_average[0],
                'process_count_delta': current_snapshot.process_count - self.baseline.process_count
            }
        
        # Get recent statistics (last 30 seconds)
        recent_time = time.time() - 30
        recent_stats = {}
        for name, series in self.metrics.items():
            stats = series.get_statistics(start_time=recent_time)
            if stats:
                recent_stats[name] = stats
        
        return {
            'timestamp': current_snapshot.timestamp,
            'current_snapshot': asdict(current_snapshot),
            'deltas_from_baseline': deltas,
            'recent_statistics': recent_stats,
            'collection_overhead': {
                'mean_ms': statistics.mean(self.collection_performance[-100:])
                if self.collection_performance else 0,
                'max_ms': max(self.collection_performance[-100:])
                if self.collection_performance else 0
            }
        }
    
    async def collect_final_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive final metrics summary"""
        if not self.snapshots:
            return {}
        
        collection_duration = time.time() - (self.collection_start_time or 0)
        
        # Overall statistics for all metrics
        overall_stats = {}
        for name, series in self.metrics.items():
            stats = series.get_statistics()
            if stats:
                overall_stats[name] = stats
        
        # Performance analysis
        performance_analysis = {
            'collection_duration': collection_duration,
            'total_snapshots': len(self.snapshots),
            'snapshot_rate': len(self.snapshots) / collection_duration if collection_duration > 0 else 0,
            'collection_overhead': {
                'mean_ms': statistics.mean(self.collection_performance) if self.collection_performance else 0,
                'median_ms': statistics.median(self.collection_performance) if self.collection_performance else 0,
                'max_ms': max(self.collection_performance) if self.collection_performance else 0,
                'p95_ms': np.percentile(self.collection_performance, 95) if self.collection_performance else 0
            }
        }
        
        # System stress analysis
        stress_analysis = {}
        if self.baseline and self.snapshots:
            final_snapshot = self.snapshots[-1]
            stress_analysis = {
                'peak_cpu_usage': max(s.cpu_usage for s in self.snapshots),
                'peak_memory_usage': max(s.memory_usage for s in self.snapshots),
                'peak_load_average': max(s.load_average[0] for s in self.snapshots),
                'cpu_usage_increase': final_snapshot.cpu_usage - self.baseline.cpu_usage,
                'memory_usage_increase': final_snapshot.memory_usage - self.baseline.memory_usage,
                'load_average_increase': final_snapshot.load_average[0] - self.baseline.load_average[0]
            }
        
        return {
            'summary': {
                'collection_start': self.collection_start_time,
                'collection_end': time.time(),
                'duration': collection_duration,
                'snapshot_count': len(self.snapshots)
            },
            'baseline': asdict(self.baseline) if self.baseline else None,
            'final_snapshot': asdict(self.snapshots[-1]) if self.snapshots else None,
            'overall_statistics': overall_stats,
            'performance_analysis': performance_analysis,
            'stress_analysis': stress_analysis
        }
    
    # Profiler methods
    def create_profiler(self, name: str) -> PerformanceProfiler:
        """Create a new performance profiler"""
        profiler = PerformanceProfiler(name)
        self.profilers[name] = profiler
        return profiler
    
    def get_profiler(self, name: str) -> Optional[PerformanceProfiler]:
        """Get existing profiler"""
        return self.profilers.get(name)
    
    def get_profiler_results(self) -> Dict[str, Dict[str, Any]]:
        """Get results from all profilers"""
        return {name: profiler.to_dict() for name, profiler in self.profilers.items()}
    
    # Callback methods
    def register_metric_callback(self, callback: Callable):
        """Register callback for metrics updates"""
        self.metric_callbacks.append(callback)
    
    async def _notify_metric_callbacks(self, snapshot: SystemSnapshot):
        """Notify registered callbacks of metrics update"""
        for callback in self.metric_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(snapshot)
                else:
                    callback(snapshot)
            except Exception as e:
                self.logger.error(f"Metric callback failed: {e}")
    
    # Export methods
    def export_metrics_json(self, filepath: str):
        """Export metrics to JSON file"""
        data = {
            'collection_info': {
                'start_time': self.collection_start_time,
                'interval': self.collection_interval,
                'snapshot_count': len(self.snapshots)
            },
            'baseline': asdict(self.baseline) if self.baseline else None,
            'snapshots': [asdict(snapshot) for snapshot in self.snapshots],
            'metrics': {
                name: {
                    'name': series.name,
                    'unit': series.unit,
                    'points': [asdict(point) for point in series.points],
                    'tags': series.tags
                }
                for name, series in self.metrics.items()
            },
            'profilers': self.get_profiler_results()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Metrics exported to {filepath}")
    
    # Utility methods
    def get_metric_series(self, name: str) -> Optional[MetricSeries]:
        """Get metric series by name"""
        return self.metrics.get(name)
    
    def get_snapshots(self, start_time: Optional[float] = None, 
                     end_time: Optional[float] = None) -> List[SystemSnapshot]:
        """Get snapshots within time range"""
        start_time = start_time or 0
        end_time = end_time or float('inf')
        
        return [
            snapshot for snapshot in self.snapshots
            if start_time <= snapshot.timestamp <= end_time
        ]
    
    def get_current_snapshot(self) -> Optional[SystemSnapshot]:
        """Get most recent snapshot"""
        return self.snapshots[-1] if self.snapshots else None