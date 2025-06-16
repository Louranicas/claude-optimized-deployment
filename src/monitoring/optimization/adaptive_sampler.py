"""
Adaptive sampling for monitoring metrics to reduce overhead.

This module implements intelligent sampling that adjusts collection
intervals based on metric stability and system load.
"""

import time
import statistics
from typing import Dict, List, Optional, Tuple
from collections import deque, defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

__all__ = [
    "AdaptiveSampler",
    "SamplingConfig",
    "MetricStability"
]


class SamplingConfig:
    """Configuration for adaptive sampling behavior."""
    
    def __init__(
        self,
        base_interval: int = 30,
        min_interval: int = 10,
        max_interval: int = 300,
        stability_window: int = 10,
        stability_threshold: float = 0.05,
        load_factor_enabled: bool = True
    ):
        self.base_interval = base_interval
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.stability_window = stability_window
        self.stability_threshold = stability_threshold
        self.load_factor_enabled = load_factor_enabled


class MetricStability:
    """Track metric stability over time."""
    
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.values = deque(maxlen=window_size)
        self.timestamps = deque(maxlen=window_size)
        
    def add_value(self, value: float, timestamp: Optional[float] = None):
        """Add a new value to the stability tracker."""
        self.values.append(value)
        self.timestamps.append(timestamp or time.time())
        
    def get_coefficient_of_variation(self) -> Optional[float]:
        """Calculate coefficient of variation (CV) for stability assessment."""
        if len(self.values) < 3:
            return None
            
        mean = statistics.mean(self.values)
        if mean == 0:
            return 0.0
            
        try:
            stdev = statistics.stdev(self.values)
            return stdev / abs(mean)
        except statistics.StatisticsError:
            return None
    
    def get_trend(self) -> str:
        """Determine if metric is trending up, down, or stable."""
        if len(self.values) < 3:
            return "unknown"
            
        # Simple linear regression
        n = len(self.values)
        x = list(range(n))
        y = list(self.values)
        
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
            
        slope = numerator / denominator
        
        # Normalize slope by mean value
        if y_mean != 0:
            normalized_slope = slope / abs(y_mean)
        else:
            normalized_slope = slope
            
        if normalized_slope > 0.01:
            return "increasing"
        elif normalized_slope < -0.01:
            return "decreasing"
        else:
            return "stable"


class AdaptiveSampler:
    """Adaptive sampling controller for monitoring metrics."""
    
    def __init__(self, config: Optional[SamplingConfig] = None):
        self.config = config or SamplingConfig()
        self.metric_stability: Dict[str, MetricStability] = defaultdict(
            lambda: MetricStability(self.config.stability_window)
        )
        self.last_sample_time: Dict[str, float] = {}
        self.current_intervals: Dict[str, int] = {}
        self.sample_counts: Dict[str, int] = defaultdict(int)
        
        # System load tracking
        self.system_load: float = 0.0
        self.last_load_update: float = 0.0
        
    def should_sample(self, metric_name: str, current_value: Optional[float] = None) -> bool:
        """
        Determine if a metric should be sampled now.
        
        Args:
            metric_name: Name of the metric
            current_value: Current value (optional, for stability tracking)
            
        Returns:
            True if metric should be sampled
        """
        now = time.time()
        
        # First sample always collected
        if metric_name not in self.last_sample_time:
            self.last_sample_time[metric_name] = now
            if current_value is not None:
                self.metric_stability[metric_name].add_value(current_value, now)
            return True
            
        # Calculate adaptive interval
        interval = self.get_adaptive_interval(metric_name)
        self.current_intervals[metric_name] = interval
        
        # Check if enough time has passed
        time_since_last = now - self.last_sample_time[metric_name]
        if time_since_last >= interval:
            self.last_sample_time[metric_name] = now
            self.sample_counts[metric_name] += 1
            if current_value is not None:
                self.metric_stability[metric_name].add_value(current_value, now)
            return True
            
        return False
    
    def get_adaptive_interval(self, metric_name: str) -> int:
        """
        Calculate adaptive sampling interval for a metric.
        
        Args:
            metric_name: Name of the metric
            
        Returns:
            Sampling interval in seconds
        """
        base_interval = self.config.base_interval
        
        # Get stability information
        stability = self.metric_stability[metric_name]
        cv = stability.get_coefficient_of_variation()
        trend = stability.get_trend()
        
        # Start with base interval
        interval = base_interval
        
        # Adjust based on stability (CV)
        if cv is not None:
            if cv < self.config.stability_threshold:
                # Very stable metric - increase interval
                interval = min(self.config.max_interval, base_interval * 3)
            elif cv < self.config.stability_threshold * 2:
                # Moderately stable - slight increase
                interval = min(self.config.max_interval, base_interval * 1.5)
            elif cv > self.config.stability_threshold * 4:
                # High variation - decrease interval
                interval = max(self.config.min_interval, base_interval * 0.5)
        
        # Adjust based on trend
        if trend == "increasing" and cv and cv > self.config.stability_threshold:
            # Increasing with variation - monitor more closely
            interval = max(self.config.min_interval, interval * 0.7)
        
        # Apply system load factor if enabled
        if self.config.load_factor_enabled:
            interval = self._apply_load_factor(interval)
            
        return int(interval)
    
    def _apply_load_factor(self, interval: int) -> int:
        """Apply system load factor to interval."""
        # Update system load periodically
        now = time.time()
        if now - self.last_load_update > 60:
            self.system_load = self._get_system_load()
            self.last_load_update = now
            
        # High load = longer intervals to reduce overhead
        if self.system_load > 0.8:
            return min(self.config.max_interval, int(interval * 1.5))
        elif self.system_load > 0.6:
            return min(self.config.max_interval, int(interval * 1.2))
            
        return interval
    
    def _get_system_load(self) -> float:
        """Get current system load (0.0 to 1.0)."""
        try:
            import psutil
            # Combine CPU and memory pressure
            cpu_percent = psutil.cpu_percent(interval=0.1) / 100.0
            memory_percent = psutil.virtual_memory().percent / 100.0
            return (cpu_percent + memory_percent) / 2
        except ImportError:
            return 0.5  # Default to medium load
    
    def update_metric_value(self, metric_name: str, value: float):
        """Update metric value for stability tracking."""
        self.metric_stability[metric_name].add_value(value)
    
    def get_sampling_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics about sampling behavior."""
        stats = {}
        
        for metric_name in self.current_intervals:
            stability = self.metric_stability[metric_name]
            cv = stability.get_coefficient_of_variation()
            
            stats[metric_name] = {
                "current_interval": self.current_intervals.get(metric_name, self.config.base_interval),
                "sample_count": self.sample_counts[metric_name],
                "coefficient_of_variation": cv,
                "trend": stability.get_trend(),
                "last_sample_age": time.time() - self.last_sample_time.get(metric_name, 0)
            }
            
        return stats
    
    def reset_metric(self, metric_name: str):
        """Reset sampling state for a specific metric."""
        if metric_name in self.metric_stability:
            del self.metric_stability[metric_name]
        if metric_name in self.last_sample_time:
            del self.last_sample_time[metric_name]
        if metric_name in self.current_intervals:
            del self.current_intervals[metric_name]
        self.sample_counts[metric_name] = 0


# Example usage and testing
if __name__ == "__main__":
    # Create sampler with custom config
    config = SamplingConfig(
        base_interval=30,
        min_interval=5,
        max_interval=300,
        stability_threshold=0.05
    )
    sampler = AdaptiveSampler(config)
    
    # Simulate metric collection
    import random
    
    # Stable metric
    stable_values = [100 + random.uniform(-1, 1) for _ in range(20)]
    
    # Variable metric
    variable_values = [100 + random.uniform(-20, 20) for _ in range(20)]
    
    # Test stable metric
    print("Testing stable metric:")
    for i, value in enumerate(stable_values):
        if sampler.should_sample("stable_metric", value):
            print(f"  Sample {i}: value={value:.2f}, interval={sampler.current_intervals.get('stable_metric', 30)}s")
        time.sleep(0.1)  # Simulate time passing
    
    print("\nTesting variable metric:")\n    for i, value in enumerate(variable_values):\n        if sampler.should_sample("variable_metric", value):\n            print(f"  Sample {i}: value={value:.2f}, interval={sampler.current_intervals.get('variable_metric', 30)}s")\n        time.sleep(0.1)\n\n    # Print statistics\n    print("\nSampling Statistics:")\n    stats = sampler.get_sampling_stats()\n    for metric, data in stats.items():\n        print(f"\n{metric}:")\n        for key, value in data.items():\n            print(f"  {key}: {value}")