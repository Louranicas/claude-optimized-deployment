#!/usr/bin/env python3
"""
Advanced Multi-Source Metrics Collector
Comprehensive performance monitoring with real-time collection and processing
"""

import asyncio
import time
import threading
import queue
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import json
import statistics
import psutil
import gc
from datetime import datetime, timedelta

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class MetricValue:
    """Enhanced metric value with metadata"""
    name: str
    value: Union[int, float, str, bool]
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp,
            'tags': self.tags,
            'metadata': self.metadata,
            'source': self.source
        }

@dataclass
class MetricSeries:
    """Time series data for metrics with statistical analysis"""
    name: str
    values: deque = field(default_factory=lambda: deque(maxlen=1000))
    max_size: int = 1000
    
    def add_value(self, value: MetricValue):
        self.values.append(value)
    
    def get_latest(self) -> Optional[MetricValue]:
        return self.values[-1] if self.values else None
    
    def get_statistics(self, window_seconds: int = 60) -> Dict[str, float]:
        """Get statistical analysis for recent values"""
        cutoff_time = time.time() - window_seconds
        recent_values = [
            v.value for v in self.values 
            if v.timestamp >= cutoff_time and isinstance(v.value, (int, float))
        ]
        
        if not recent_values:
            return {}
        
        try:
            return {
                'count': len(recent_values),
                'mean': statistics.mean(recent_values),
                'median': statistics.median(recent_values),
                'min': min(recent_values),
                'max': max(recent_values),
                'stdev': statistics.stdev(recent_values) if len(recent_values) > 1 else 0,
                'p95': statistics.quantiles(recent_values, n=20)[18] if len(recent_values) >= 20 else max(recent_values),
                'p99': statistics.quantiles(recent_values, n=100)[98] if len(recent_values) >= 100 else max(recent_values)
            }
        except Exception as e:
            logger.warning(f"Statistics calculation error for {self.name}: {e}")
            return {'count': len(recent_values)}

class MetricsCollector:
    """Advanced multi-source metrics collector with real-time processing"""
    
    def __init__(self, collection_interval: float = 1.0, max_history: int = 1000):
        self.collection_interval = collection_interval
        self.max_history = max_history
        self.metrics: Dict[str, MetricSeries] = defaultdict(lambda: MetricSeries("", max_size=max_history))
        self.collectors: List[Callable] = []
        self.running = False
        self.collection_thread: Optional[threading.Thread] = None
        self.processing_queue = queue.Queue(maxsize=10000)
        self.processor_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable[[MetricValue], None]] = []
        
        # Performance tracking
        self.collection_stats = {
            'total_collections': 0,
            'collection_errors': 0,
            'processing_errors': 0,
            'queue_overflows': 0,
            'last_collection_time': 0
        }
        
        # Initialize built-in collectors
        self._initialize_system_collectors()
    
    def _initialize_system_collectors(self):
        """Initialize built-in system metric collectors"""
        self.add_collector(self._collect_cpu_metrics)
        self.add_collector(self._collect_memory_metrics)
        self.add_collector(self._collect_disk_metrics)
        self.add_collector(self._collect_network_metrics)
        self.add_collector(self._collect_process_metrics)
        self.add_collector(self._collect_gc_metrics)
    
    def add_collector(self, collector_func: Callable):
        """Add a metrics collector function"""
        self.collectors.append(collector_func)
        logger.info(f"Added collector: {collector_func.__name__}")
    
    def add_callback(self, callback: Callable[[MetricValue], None]):
        """Add callback for real-time metric processing"""
        self.callbacks.append(callback)
    
    def start(self):
        """Start metrics collection"""
        if self.running:
            logger.warning("Metrics collector already running")
            return
        
        self.running = True
        
        # Start processing thread
        self.processor_thread = threading.Thread(target=self._process_metrics, daemon=True)
        self.processor_thread.start()
        
        # Start collection thread
        self.collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collection_thread.start()
        
        logger.info(f"Started metrics collector with {len(self.collectors)} collectors")
    
    def stop(self):
        """Stop metrics collection"""
        self.running = False
        
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=5)
        
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)
        
        logger.info("Stopped metrics collector")
    
    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            start_time = time.time()
            
            try:
                # Collect from all registered collectors
                for collector in self.collectors:
                    try:
                        metrics = collector()
                        if metrics:
                            for metric in metrics:
                                if not self.processing_queue.full():
                                    self.processing_queue.put(metric)
                                else:
                                    self.collection_stats['queue_overflows'] += 1
                    except Exception as e:
                        logger.error(f"Error in collector {collector.__name__}: {e}")
                        self.collection_stats['collection_errors'] += 1
                
                self.collection_stats['total_collections'] += 1
                self.collection_stats['last_collection_time'] = time.time()
                
                # Sleep for remaining interval time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.collection_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                time.sleep(self.collection_interval)
    
    def _process_metrics(self):
        """Process collected metrics"""
        while self.running:
            try:
                # Process metrics from queue with timeout
                try:
                    metric = self.processing_queue.get(timeout=1.0)
                    self._store_metric(metric)
                    
                    # Call registered callbacks
                    for callback in self.callbacks:
                        try:
                            callback(metric)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                    
                    self.processing_queue.task_done()
                    
                except queue.Empty:
                    continue
                    
            except Exception as e:
                logger.error(f"Metric processing error: {e}")
                self.collection_stats['processing_errors'] += 1
    
    def _store_metric(self, metric: MetricValue):
        """Store metric in time series"""
        series_key = f"{metric.source}.{metric.name}"
        self.metrics[series_key].add_value(metric)
    
    def get_metric_statistics(self, metric_name: str, window_seconds: int = 60) -> Dict[str, float]:
        """Get statistical analysis for a metric"""
        if metric_name in self.metrics:
            return self.metrics[metric_name].get_statistics(window_seconds)
        return {}
    
    def get_latest_metrics(self) -> Dict[str, MetricValue]:
        """Get latest values for all metrics"""
        result = {}
        for name, series in self.metrics.items():
            latest = series.get_latest()
            if latest:
                result[name] = latest
        return result
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collector performance statistics"""
        stats = self.collection_stats.copy()
        stats['queue_size'] = self.processing_queue.qsize()
        stats['active_metrics'] = len(self.metrics)
        stats['running'] = self.running
        return stats
    
    # Built-in collectors
    def _collect_cpu_metrics(self) -> List[MetricValue]:
        """Collect CPU metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Overall CPU usage
            cpu_percent = psutil.cpu_percent(interval=None)
            metrics.append(MetricValue(
                name="cpu_usage_percent",
                value=cpu_percent,
                timestamp=timestamp,
                source="system",
                tags={"type": "cpu"}
            ))
            
            # Per-core CPU usage
            cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
            for i, core_usage in enumerate(cpu_per_core):
                metrics.append(MetricValue(
                    name="cpu_core_usage_percent",
                    value=core_usage,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "cpu", "core": str(i)}
                ))
            
            # Load averages (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()
                for i, period in enumerate(['1min', '5min', '15min']):
                    metrics.append(MetricValue(
                        name="load_average",
                        value=load_avg[i],
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "cpu", "period": period}
                    ))
            except AttributeError:
                pass  # Windows doesn't have load averages
            
            # CPU frequency
            try:
                cpu_freq = psutil.cpu_freq()
                if cpu_freq:
                    metrics.append(MetricValue(
                        name="cpu_frequency_mhz",
                        value=cpu_freq.current,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "cpu"}
                    ))
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"CPU metrics collection error: {e}")
        
        return metrics
    
    def _collect_memory_metrics(self) -> List[MetricValue]:
        """Collect memory metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Virtual memory
            vm = psutil.virtual_memory()
            metrics.extend([
                MetricValue("memory_total_bytes", vm.total, timestamp, source="system", tags={"type": "memory"}),
                MetricValue("memory_available_bytes", vm.available, timestamp, source="system", tags={"type": "memory"}),
                MetricValue("memory_used_bytes", vm.used, timestamp, source="system", tags={"type": "memory"}),
                MetricValue("memory_free_bytes", vm.free, timestamp, source="system", tags={"type": "memory"}),
                MetricValue("memory_usage_percent", vm.percent, timestamp, source="system", tags={"type": "memory"})
            ])
            
            # Swap memory
            swap = psutil.swap_memory()
            metrics.extend([
                MetricValue("swap_total_bytes", swap.total, timestamp, source="system", tags={"type": "swap"}),
                MetricValue("swap_used_bytes", swap.used, timestamp, source="system", tags={"type": "swap"}),
                MetricValue("swap_free_bytes", swap.free, timestamp, source="system", tags={"type": "swap"}),
                MetricValue("swap_usage_percent", swap.percent, timestamp, source="system", tags={"type": "swap"})
            ])
            
        except Exception as e:
            logger.error(f"Memory metrics collection error: {e}")
        
        return metrics
    
    def _collect_disk_metrics(self) -> List[MetricValue]:
        """Collect disk I/O metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Disk usage for mounted filesystems
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    device = partition.device.replace('/', '_').replace('\\', '_')
                    
                    metrics.extend([
                        MetricValue("disk_total_bytes", usage.total, timestamp, 
                                  source="system", tags={"type": "disk", "device": device}),
                        MetricValue("disk_used_bytes", usage.used, timestamp,
                                  source="system", tags={"type": "disk", "device": device}),
                        MetricValue("disk_free_bytes", usage.free, timestamp,
                                  source="system", tags={"type": "disk", "device": device}),
                        MetricValue("disk_usage_percent", (usage.used / usage.total) * 100, timestamp,
                                  source="system", tags={"type": "disk", "device": device})
                    ])
                except (PermissionError, OSError):
                    continue
            
            # Disk I/O statistics
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics.extend([
                    MetricValue("disk_read_bytes", disk_io.read_bytes, timestamp,
                              source="system", tags={"type": "disk_io"}),
                    MetricValue("disk_write_bytes", disk_io.write_bytes, timestamp,
                              source="system", tags={"type": "disk_io"}),
                    MetricValue("disk_read_count", disk_io.read_count, timestamp,
                              source="system", tags={"type": "disk_io"}),
                    MetricValue("disk_write_count", disk_io.write_count, timestamp,
                              source="system", tags={"type": "disk_io"})
                ])
            
        except Exception as e:
            logger.error(f"Disk metrics collection error: {e}")
        
        return metrics
    
    def _collect_network_metrics(self) -> List[MetricValue]:
        """Collect network metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Network I/O statistics
            net_io = psutil.net_io_counters()
            if net_io:
                metrics.extend([
                    MetricValue("network_bytes_sent", net_io.bytes_sent, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_bytes_recv", net_io.bytes_recv, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_packets_sent", net_io.packets_sent, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_packets_recv", net_io.packets_recv, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_errors_in", net_io.errin, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_errors_out", net_io.errout, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_drops_in", net_io.dropin, timestamp,
                              source="system", tags={"type": "network"}),
                    MetricValue("network_drops_out", net_io.dropout, timestamp,
                              source="system", tags={"type": "network"})
                ])
            
            # Connection counts
            connections = psutil.net_connections()
            connection_states = defaultdict(int)
            for conn in connections:
                if conn.status:
                    connection_states[conn.status] += 1
            
            for state, count in connection_states.items():
                metrics.append(MetricValue(
                    "network_connections", count, timestamp,
                    source="system", tags={"type": "network", "state": state}
                ))
            
        except Exception as e:
            logger.error(f"Network metrics collection error: {e}")
        
        return metrics
    
    def _collect_process_metrics(self) -> List[MetricValue]:
        """Collect process-specific metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            process = psutil.Process()
            
            # Memory info
            memory_info = process.memory_info()
            metrics.extend([
                MetricValue("process_memory_rss", memory_info.rss, timestamp,
                          source="process", tags={"type": "memory"}),
                MetricValue("process_memory_vms", memory_info.vms, timestamp,
                          source="process", tags={"type": "memory"})
            ])
            
            # CPU usage
            cpu_percent = process.cpu_percent()
            metrics.append(MetricValue(
                "process_cpu_percent", cpu_percent, timestamp,
                source="process", tags={"type": "cpu"}
            ))
            
            # Thread count
            thread_count = process.num_threads()
            metrics.append(MetricValue(
                "process_thread_count", thread_count, timestamp,
                source="process", tags={"type": "threads"}
            ))
            
            # File descriptors (Unix-like systems)
            try:
                fd_count = process.num_fds()
                metrics.append(MetricValue(
                    "process_file_descriptors", fd_count, timestamp,
                    source="process", tags={"type": "files"}
                ))
            except AttributeError:
                pass  # Windows doesn't have file descriptors
            
        except Exception as e:
            logger.error(f"Process metrics collection error: {e}")
        
        return metrics
    
    def _collect_gc_metrics(self) -> List[MetricValue]:
        """Collect Python garbage collection metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # GC statistics
            gc_stats = gc.get_stats()
            for i, stat in enumerate(gc_stats):
                metrics.extend([
                    MetricValue(f"gc_generation_{i}_collections", stat['collections'], timestamp,
                              source="python", tags={"type": "gc", "generation": str(i)}),
                    MetricValue(f"gc_generation_{i}_collected", stat['collected'], timestamp,
                              source="python", tags={"type": "gc", "generation": str(i)}),
                    MetricValue(f"gc_generation_{i}_uncollectable", stat['uncollectable'], timestamp,
                              source="python", tags={"type": "gc", "generation": str(i)})
                ])
            
            # Object counts by generation
            gc_counts = gc.get_count()
            for i, count in enumerate(gc_counts):
                metrics.append(MetricValue(
                    f"gc_generation_{i}_objects", count, timestamp,
                    source="python", tags={"type": "gc", "generation": str(i)}
                ))
            
        except Exception as e:
            logger.error(f"GC metrics collection error: {e}")
        
        return metrics

# Example usage and testing
async def main():
    """Example usage of the metrics collector"""
    collector = MetricsCollector(collection_interval=1.0)
    
    # Add a custom callback for real-time processing
    def metric_callback(metric: MetricValue):
        if "cpu_usage_percent" in metric.name:
            print(f"CPU Usage: {metric.value}%")
    
    collector.add_callback(metric_callback)
    
    # Start collection
    collector.start()
    
    try:
        # Run for 30 seconds
        await asyncio.sleep(30)
        
        # Print some statistics
        print("\n=== Collection Statistics ===")
        stats = collector.get_collection_stats()
        for key, value in stats.items():
            print(f"{key}: {value}")
        
        print("\n=== Latest Metrics Sample ===")
        latest = collector.get_latest_metrics()
        for name, metric in list(latest.items())[:10]:  # Show first 10
            print(f"{name}: {metric.value}")
        
        print("\n=== CPU Statistics (last 60s) ===")
        cpu_stats = collector.get_metric_statistics("system.cpu_usage_percent", 60)
        for key, value in cpu_stats.items():
            print(f"{key}: {value:.2f}")
    
    finally:
        collector.stop()

if __name__ == "__main__":
    asyncio.run(main())