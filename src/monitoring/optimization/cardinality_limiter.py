"""
Cardinality limiting for Prometheus metrics to prevent metric explosion.

This module implements controls to limit the number of unique label
combinations and prevent unbounded growth of metric cardinality.
"""

import time
import re
from typing import Dict, Set, List, Optional, Tuple, Any
from collections import defaultdict, Counter, OrderedDict
from datetime import datetime, timedelta
import logging
import threading
from enum import Enum

logger = logging.getLogger(__name__)

__all__ = [
    "CardinalityLimiter",
    "CardinalityConfig",
    "EnforcementPolicy",
    "LabelAggregator",
    "MetricCardinality"
]


class EnforcementPolicy(Enum):
    """Cardinality enforcement policies."""
    DROP_NEW = "drop_new"  # Drop new label combinations
    DROP_LEAST_USED = "drop_least_used"  # Drop least frequently used
    AGGREGATE = "aggregate"  # Aggregate to reduce cardinality
    ALERT_ONLY = "alert_only"  # Only alert, don't drop


class CardinalityConfig:
    """Configuration for cardinality limiting."""
    
    def __init__(
        self,
        max_series_per_metric: int = 1000,
        max_total_series: int = 10000,
        enforcement_policy: EnforcementPolicy = EnforcementPolicy.DROP_NEW,
        cleanup_interval: int = 3600,
        track_dropped: bool = True,
        alert_threshold: float = 0.8
    ):
        self.max_series_per_metric = max_series_per_metric
        self.max_total_series = max_total_series
        self.enforcement_policy = enforcement_policy
        self.cleanup_interval = cleanup_interval
        self.track_dropped = track_dropped
        self.alert_threshold = alert_threshold  # Alert when 80% of limit reached


class MetricCardinality:
    """Track cardinality information for a single metric."""
    
    def __init__(self, metric_name: str, max_series: int):
        self.metric_name = metric_name
        self.max_series = max_series
        self.series: OrderedDict[str, int] = OrderedDict()  # series_id -> access_count
        self.last_access: Dict[str, float] = {}
        self.dropped_count: int = 0
        self.creation_times: Dict[str, float] = {}
        
    def add_series(self, series_id: str) -> bool:
        """Add a new series, returns True if added."""
        if series_id in self.series:
            self.series[series_id] += 1
            self.last_access[series_id] = time.time()
            return True
            
        if len(self.series) >= self.max_series:
            return False
            
        self.series[series_id] = 1
        self.last_access[series_id] = time.time()
        self.creation_times[series_id] = time.time()
        return True
        
    def access_series(self, series_id: str):
        """Record access to a series."""
        if series_id in self.series:
            self.series[series_id] += 1
            self.last_access[series_id] = time.time()
            
    def get_least_used(self, count: int = 1) -> List[str]:
        """Get least used series IDs."""
        # Sort by access count, then by last access time
        sorted_series = sorted(
            self.series.items(),
            key=lambda x: (x[1], self.last_access.get(x[0], 0))
        )
        return [s[0] for s in sorted_series[:count]]
        
    def remove_series(self, series_ids: List[str]):
        """Remove series from tracking."""
        for series_id in series_ids:
            self.series.pop(series_id, None)
            self.last_access.pop(series_id, None)
            self.creation_times.pop(series_id, None)
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cardinality statistics."""
        return {
            'current_series': len(self.series),
            'max_series': self.max_series,
            'utilization': len(self.series) / self.max_series,
            'dropped_count': self.dropped_count,
            'total_accesses': sum(self.series.values())
        }


class LabelAggregator:
    """Aggregate labels to reduce cardinality."""
    
    def __init__(self):
        # Common aggregation patterns
        self.patterns = [
            # UUID pattern
            (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), '{uuid}'),
            # Numeric IDs
            (re.compile(r'\b\d{6,}\b'), '{id}'),
            # Session IDs
            (re.compile(r'sess_[a-zA-Z0-9]{16,}'), '{session}'),
            # Timestamps
            (re.compile(r'\b\d{10}\b'), '{timestamp}'),
            # IP addresses
            (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '{ip}'),
        ]
        
    def aggregate_label(self, label_value: str) -> str:
        """Aggregate a label value to reduce cardinality."""
        aggregated = label_value
        
        for pattern, replacement in self.patterns:
            aggregated = pattern.sub(replacement, aggregated)
            
        return aggregated
        
    def aggregate_labels(self, labels: Dict[str, str]) -> Dict[str, str]:
        """Aggregate all labels in a dictionary."""
        return {k: self.aggregate_label(v) for k, v in labels.items()}


class CardinalityLimiter:
    """Main cardinality limiting controller."""
    
    def __init__(self, config: Optional[CardinalityConfig] = None):
        self.config = config or CardinalityConfig()
        self._lock = threading.RLock()
        
        # Metric tracking
        self.metrics: Dict[str, MetricCardinality] = {}
        self.total_series = 0
        
        # Dropped metrics tracking
        self.dropped_series: Counter = Counter()
        self.dropped_by_metric: Dict[str, int] = defaultdict(int)
        
        # Label aggregator
        self.aggregator = LabelAggregator()
        
        # Cleanup state
        self.last_cleanup = time.time()
        
        # Alert callbacks
        self.alert_callbacks: List[callable] = []
        
    def should_accept(self, metric_name: str, labels: Dict[str, str]) -> Tuple[bool, Dict[str, str]]:
        """
        Check if a metric with given labels should be accepted.
        
        Returns:
            Tuple of (should_accept, processed_labels)
        """
        series_id = self._get_series_id(labels)
        
        with self._lock:
            # Initialize metric tracking if needed
            if metric_name not in self.metrics:
                self.metrics[metric_name] = MetricCardinality(
                    metric_name,
                    self.config.max_series_per_metric
                )
                
            metric_card = self.metrics[metric_name]
            
            # Check if series already exists
            if series_id in metric_card.series:
                metric_card.access_series(series_id)
                return True, labels
                
            # Check total cardinality limit
            if self.total_series >= self.config.max_total_series:
                return self._handle_limit_exceeded(metric_name, labels, series_id, 'total')
                
            # Check per-metric cardinality limit
            if len(metric_card.series) >= metric_card.max_series:
                return self._handle_limit_exceeded(metric_name, labels, series_id, 'metric')
                
            # Accept new series
            if metric_card.add_series(series_id):
                self.total_series += 1
                self._check_alert_threshold(metric_name)
                return True, labels
                
            return False, labels
            
    def _get_series_id(self, labels: Dict[str, str]) -> str:
        """Generate unique ID for a label combination."""
        return ','.join(f'{k}={v}' for k, v in sorted(labels.items()))
        
    def _handle_limit_exceeded(self, metric_name: str, labels: Dict[str, str], 
                              series_id: str, limit_type: str) -> Tuple[bool, Dict[str, str]]:
        """Handle cardinality limit exceeded."""
        
        if self.config.enforcement_policy == EnforcementPolicy.ALERT_ONLY:
            logger.warning(f"Cardinality limit exceeded for {metric_name} ({limit_type})")
            return True, labels
            
        elif self.config.enforcement_policy == EnforcementPolicy.DROP_NEW:
            if self.config.track_dropped:
                self.dropped_series[series_id] += 1
                self.dropped_by_metric[metric_name] += 1
                self.metrics[metric_name].dropped_count += 1
            return False, labels
            
        elif self.config.enforcement_policy == EnforcementPolicy.DROP_LEAST_USED:
            # Drop least used series to make room
            metric_card = self.metrics[metric_name]
            to_remove = metric_card.get_least_used(1)
            
            if to_remove:
                metric_card.remove_series(to_remove)
                self.total_series -= len(to_remove)
                
                # Now try to add the new series
                if metric_card.add_series(series_id):
                    self.total_series += 1
                    return True, labels
                    
            return False, labels
            
        elif self.config.enforcement_policy == EnforcementPolicy.AGGREGATE:
            # Try aggregating labels
            aggregated_labels = self.aggregator.aggregate_labels(labels)
            aggregated_series_id = self._get_series_id(aggregated_labels)
            
            # If aggregation reduced cardinality, try again
            if aggregated_series_id != series_id:
                return self.should_accept(metric_name, aggregated_labels)
                
            return False, labels
            
        return False, labels
        
    def _check_alert_threshold(self, metric_name: str):
        """Check if alert threshold is reached."""
        metric_card = self.metrics[metric_name]
        utilization = len(metric_card.series) / metric_card.max_series
        
        if utilization >= self.config.alert_threshold:
            for callback in self.alert_callbacks:
                try:
                    callback(metric_name, utilization)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
                    
    def register_alert_callback(self, callback: callable):
        """Register a callback for cardinality alerts."""
        self.alert_callbacks.append(callback)
        
    def cleanup_old_series(self, max_age_seconds: int = 86400):
        """Remove series not accessed recently."""
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - max_age_seconds
            
            for metric_name, metric_card in self.metrics.items():
                to_remove = []
                
                for series_id, last_access in metric_card.last_access.items():
                    if last_access < cutoff_time:
                        to_remove.append(series_id)
                        
                if to_remove:
                    metric_card.remove_series(to_remove)
                    self.total_series -= len(to_remove)
                    logger.info(f"Cleaned up {len(to_remove)} old series from {metric_name}")
                    
    def get_cardinality_stats(self) -> Dict[str, Any]:
        """Get comprehensive cardinality statistics."""
        with self._lock:
            stats = {
                'total_series': self.total_series,
                'total_metrics': len(self.metrics),
                'max_total_series': self.config.max_total_series,
                'utilization': self.total_series / self.config.max_total_series,
                'dropped_total': sum(self.dropped_series.values()),
                'policy': self.config.enforcement_policy.value
            }
            
            # Per-metric stats
            metric_stats = {}
            for metric_name, metric_card in self.metrics.items():
                metric_stats[metric_name] = metric_card.get_stats()
                
            stats['metrics'] = metric_stats
            
            # Top dropped series
            if self.config.track_dropped:
                stats['top_dropped'] = dict(self.dropped_series.most_common(10))
                
            return stats
            
    def optimize_cardinality(self) -> Dict[str, int]:
        """
        Optimize cardinality by removing low-value series.
        
        Returns:
            Dict of metric_name -> series_removed
        """
        with self._lock:
            removed = {}
            
            for metric_name, metric_card in self.metrics.items():
                # Find series with very low access counts
                low_access_threshold = 5
                to_remove = []
                
                for series_id, access_count in metric_card.series.items():
                    if access_count < low_access_threshold:
                        age = time.time() - metric_card.creation_times.get(series_id, 0)
                        # Only remove if it's been around for a while
                        if age > 3600:  # 1 hour
                            to_remove.append(series_id)
                            
                if to_remove:
                    metric_card.remove_series(to_remove)
                    self.total_series -= len(to_remove)
                    removed[metric_name] = len(to_remove)
                    
            return removed
            
    def reset_metric(self, metric_name: str):
        """Reset cardinality tracking for a specific metric."""
        with self._lock:
            if metric_name in self.metrics:
                series_count = len(self.metrics[metric_name].series)
                del self.metrics[metric_name]
                self.total_series -= series_count
                self.dropped_by_metric.pop(metric_name, None)


# Example usage
if __name__ == "__main__":
    # Create limiter with strict limits for demo
    config = CardinalityConfig(
        max_series_per_metric=10,
        max_total_series=50,
        enforcement_policy=EnforcementPolicy.DROP_LEAST_USED
    )
    limiter = CardinalityLimiter(config)
    
    # Alert callback
    def alert_callback(metric_name: str, utilization: float):
        print(f"ALERT: {metric_name} at {utilization:.1%} capacity!")
        
    limiter.register_alert_callback(alert_callback)
    
    # Simulate metric collection
    import random
    
    endpoints = ['/api/users', '/api/orders', '/api/products', '/api/search']
    users = [f'user_{i}' for i in range(20)]
    
    print("Testing cardinality limiting...")
    
    for i in range(100):
        # HTTP metrics with varying cardinality
        endpoint = random.choice(endpoints)
        user = random.choice(users)
        status = random.choice(['200', '404', '500'])
        
        labels = {
            'endpoint': endpoint,
            'user_id': user,
            'status': status
        }
        
        accepted, processed_labels = limiter.should_accept('http_requests', labels)
        
        if not accepted:
            print(f"Rejected: {labels}")
            
    # Show stats
    print("\nCardinality Statistics:")\n    stats = limiter.get_cardinality_stats()\n    print(f"Total series: {stats['total_series']}/{stats['max_total_series']}")\n    print(f"Dropped: {stats['dropped_total']}")\n\n    print("\nPer-metric stats:")\n    for metric, metric_stats in stats['metrics'].items():\n        print(f"  {metric}: {metric_stats['current_series']}/{metric_stats['max_series']} "\n              f"(dropped: {metric_stats['dropped_count']})")\n\n    # Optimize cardinality\n    print("\nOptimizing cardinality...")\n    removed = limiter.optimize_cardinality()\n    for metric, count in removed.items():\n        print(f"  Removed {count} low-value series from {metric}")