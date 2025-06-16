"""
Pre-aggregation system for monitoring metrics to reduce data volume.

This module implements metric aggregation at collection time to reduce
the number of data points while maintaining statistical accuracy.
"""

import time
import statistics
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
import threading

logger = logging.getLogger(__name__)

__all__ = [
    "MetricAggregator",
    "AggregationWindow",
    "AggregatedMetric",
    "AggregationConfig"
]


@dataclass
class AggregatedMetric:
    """Aggregated metric statistics."""
    metric_name: str
    labels: Dict[str, str]
    window_start: float
    window_end: float
    count: int
    sum: float
    min: float
    max: float
    avg: float
    p50: Optional[float] = None
    p95: Optional[float] = None
    p99: Optional[float] = None
    stddev: Optional[float] = None
    
    def to_prometheus_format(self) -> List[str]:
        """Convert to Prometheus exposition format."""
        label_str = ','.join(f'{k}="{v}"' for k, v in sorted(self.labels.items()))
        base_name = self.metric_name.replace('.', '_')
        
        lines = [
            f'{base_name}_count{{{label_str}}} {self.count}',
            f'{base_name}_sum{{{label_str}}} {self.sum}',
            f'{base_name}_min{{{label_str}}} {self.min}',
            f'{base_name}_max{{{label_str}}} {self.max}',
            f'{base_name}_avg{{{label_str}}} {self.avg}',
        ]
        
        if self.p50 is not None:
            lines.append(f'{base_name}_p50{{{label_str}}} {self.p50}')
        if self.p95 is not None:
            lines.append(f'{base_name}_p95{{{label_str}}} {self.p95}')
        if self.p99 is not None:
            lines.append(f'{base_name}_p99{{{label_str}}} {self.p99}')
        if self.stddev is not None:
            lines.append(f'{base_name}_stddev{{{label_str}}} {self.stddev}')
            
        return lines


class AggregationWindow:
    """Time window for metric aggregation."""
    
    def __init__(self, window_size: int = 60, calculate_percentiles: bool = True):
        self.window_size = window_size
        self.calculate_percentiles = calculate_percentiles
        self.values: List[Tuple[float, float]] = []  # (timestamp, value)
        self.start_time = time.time()
        
    def add_value(self, value: float, timestamp: Optional[float] = None):
        """Add a value to the aggregation window."""
        ts = timestamp or time.time()
        self.values.append((ts, value))
        
    def is_complete(self) -> bool:
        """Check if the window period has elapsed."""
        return time.time() - self.start_time >= self.window_size
        
    def get_aggregates(self) -> Optional[Dict[str, float]]:
        """Calculate aggregated statistics for the window."""
        if not self.values:
            return None
            
        values_only = [v for _, v in self.values]
        
        aggregates = {
            'count': len(values_only),
            'sum': sum(values_only),
            'min': min(values_only),
            'max': max(values_only),
            'avg': statistics.mean(values_only)
        }
        
        if len(values_only) > 1:
            try:
                aggregates['stddev'] = statistics.stdev(values_only)
            except statistics.StatisticsError:
                aggregates['stddev'] = 0.0
                
        if self.calculate_percentiles and len(values_only) >= 3:
            sorted_values = sorted(values_only)
            aggregates['p50'] = statistics.median(sorted_values)
            
            if len(values_only) >= 20:
                # Calculate percentiles for larger samples
                aggregates['p95'] = sorted_values[int(len(sorted_values) * 0.95)]
                aggregates['p99'] = sorted_values[int(len(sorted_values) * 0.99)]
                
        return aggregates
    
    def clear(self):
        """Clear the window and reset start time."""
        self.values.clear()
        self.start_time = time.time()


@dataclass
class AggregationConfig:
    """Configuration for metric aggregation."""
    window_size: int = 60  # seconds
    max_windows_retained: int = 60  # Keep 1 hour of windows
    calculate_percentiles: bool = True
    percentiles: List[float] = None
    flush_on_shutdown: bool = True
    
    def __post_init__(self):
        if self.percentiles is None:
            self.percentiles = [0.5, 0.95, 0.99]


class MetricAggregator:
    """Pre-aggregation system for monitoring metrics."""
    
    def __init__(self, config: Optional[AggregationConfig] = None):
        self.config = config or AggregationConfig()
        self._lock = threading.RLock()
        
        # Active aggregation windows by metric key
        self.active_windows: Dict[str, AggregationWindow] = {}
        
        # Completed aggregations ready for export
        self.completed_aggregations: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.config.max_windows_retained)
        )
        
        # Metric metadata
        self.metric_types: Dict[str, str] = {}
        self.metric_descriptions: Dict[str, str] = {}
        
    def add_sample(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None,
                   timestamp: Optional[float] = None):
        """
        Add a metric sample for aggregation.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            labels: Optional metric labels
            timestamp: Optional timestamp (defaults to current time)
        """
        labels = labels or {}
        metric_key = self._get_metric_key(metric_name, labels)
        
        with self._lock:
            # Get or create aggregation window
            if metric_key not in self.active_windows:
                self.active_windows[metric_key] = AggregationWindow(
                    self.config.window_size,
                    self.config.calculate_percentiles
                )
                
            window = self.active_windows[metric_key]
            window.add_value(value, timestamp)
            
            # Check if window is complete
            if window.is_complete():
                self._complete_window(metric_name, labels, window)
                
    def _get_metric_key(self, metric_name: str, labels: Dict[str, str]) -> str:
        """Generate unique key for metric + labels combination."""
        label_str = ','.join(f'{k}={v}' for k, v in sorted(labels.items()))
        return f"{metric_name}:{label_str}"
        
    def _complete_window(self, metric_name: str, labels: Dict[str, str], window: AggregationWindow):
        """Complete an aggregation window and store results."""
        aggregates = window.get_aggregates()
        if not aggregates:
            return
            
        # Create aggregated metric
        aggregated = AggregatedMetric(
            metric_name=metric_name,
            labels=labels,
            window_start=window.start_time,
            window_end=time.time(),
            count=aggregates['count'],
            sum=aggregates['sum'],
            min=aggregates['min'],
            max=aggregates['max'],
            avg=aggregates['avg'],
            p50=aggregates.get('p50'),
            p95=aggregates.get('p95'),
            p99=aggregates.get('p99'),
            stddev=aggregates.get('stddev')
        )
        
        metric_key = self._get_metric_key(metric_name, labels)
        self.completed_aggregations[metric_key].append(aggregated)
        
        # Start new window
        window.clear()
        
    def get_aggregated_metrics(self, metric_name: Optional[str] = None,
                             since: Optional[float] = None) -> List[AggregatedMetric]:
        """
        Get aggregated metrics.
        
        Args:
            metric_name: Filter by metric name (optional)
            since: Only return metrics since this timestamp (optional)
            
        Returns:
            List of aggregated metrics
        """
        with self._lock:
            results = []
            
            for metric_key, aggregations in self.completed_aggregations.items():
                # Apply metric name filter
                if metric_name and not metric_key.startswith(metric_name + ":"):
                    continue
                    
                # Apply time filter
                for agg in aggregations:
                    if since is None or agg.window_end >= since:
                        results.append(agg)
                        
            return results
            
    def flush_all(self) -> List[AggregatedMetric]:
        """
        Flush all active windows and return aggregated metrics.
        
        Returns:
            List of all aggregated metrics
        """
        with self._lock:
            # Complete all active windows
            for metric_key, window in list(self.active_windows.items()):
                # Parse metric name and labels from key
                parts = metric_key.split(':', 1)
                metric_name = parts[0]
                labels = {}
                
                if len(parts) > 1 and parts[1]:
                    for label_pair in parts[1].split(','):
                        if '=' in label_pair:
                            k, v = label_pair.split('=', 1)
                            labels[k] = v
                            
                self._complete_window(metric_name, labels, window)
                
            # Return all completed aggregations
            return self.get_aggregated_metrics()
            
    def get_prometheus_format(self) -> str:
        """
        Export aggregated metrics in Prometheus exposition format.
        
        Returns:
            Prometheus formatted metrics string
        """
        with self._lock:
            lines = []
            
            # Group by metric name
            metrics_by_name = defaultdict(list)
            for metric_key, aggregations in self.completed_aggregations.items():
                if aggregations:
                    metric_name = aggregations[-1].metric_name  # Get latest
                    metrics_by_name[metric_name].extend(aggregations)
                    
            # Generate exposition format
            for metric_name, aggregations in metrics_by_name.items():
                # Add metric help if available
                if metric_name in self.metric_descriptions:
                    lines.append(f'# HELP {metric_name} {self.metric_descriptions[metric_name]}')
                    
                # Add metric type
                metric_type = self.metric_types.get(metric_name, 'gauge')
                lines.append(f'# TYPE {metric_name} {metric_type}')
                
                # Add aggregated values
                for agg in aggregations:
                    lines.extend(agg.to_prometheus_format())
                    
                lines.append('')  # Empty line between metrics
                
            return '
'.join(lines)
            
    def register_metric(self, metric_name: str, metric_type: str = 'gauge',
                       description: Optional[str] = None):
        """Register metric metadata."""
        self.metric_types[metric_name] = metric_type
        if description:
            self.metric_descriptions[metric_name] = description
            
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        with self._lock:
            total_windows = sum(len(aggs) for aggs in self.completed_aggregations.values())
            
            return {
                'active_windows': len(self.active_windows),
                'completed_windows': total_windows,
                'unique_metrics': len(self.completed_aggregations),
                'window_size': self.config.window_size,
                'memory_estimate_kb': (total_windows * 0.5) + (len(self.active_windows) * 2)
            }


# Example usage
if __name__ == "__main__":
    import random
    
    # Create aggregator
    config = AggregationConfig(window_size=10)  # 10 second windows for demo
    aggregator = MetricAggregator(config)
    
    # Register metrics
    aggregator.register_metric('http_request_duration', 'histogram', 
                             'HTTP request duration in seconds')
    aggregator.register_metric('memory_usage_bytes', 'gauge',
                             'Memory usage in bytes')
    
    # Simulate metric collection
    print("Collecting metrics for 30 seconds...")
    start_time = time.time()
    
    while time.time() - start_time < 30:
        # HTTP request metrics
        duration = random.uniform(0.1, 2.0)
        aggregator.add_sample(
            'http_request_duration',
            duration,
            {'method': 'GET', 'endpoint': '/api/users'}
        )
        
        # Memory metrics
        memory = 1024 * 1024 * 100 + random.uniform(-1024*1024, 1024*1024)
        aggregator.add_sample(
            'memory_usage_bytes',
            memory,
            {'component': 'api_server'}
        )
        
        time.sleep(0.5)
        
    # Get aggregated results
    print("\nAggregated Metrics:")\n    for metric in aggregator.get_aggregated_metrics():\n        print(f"\n{metric.metric_name} {metric.labels}")\n        print(f"  Window: {datetime.fromtimestamp(metric.window_start).strftime('%H:%M:%S')} - "\n              f"{datetime.fromtimestamp(metric.window_end).strftime('%H:%M:%S')}")\n        print(f"  Count: {metric.count}, Avg: {metric.avg:.3f}")\n        print(f"  Min: {metric.min:.3f}, Max: {metric.max:.3f}")\n        if metric.p95:\n            print(f"  P95: {metric.p95:.3f}")\n\n    # Export Prometheus format\n    print("\nPrometheus Format:")\n    print(aggregator.get_prometheus_format())\n\n    # Show stats\n    print("\nAggregator Stats:")\n    for key, value in aggregator.get_stats().items():\n        print(f"  {key}: {value}")