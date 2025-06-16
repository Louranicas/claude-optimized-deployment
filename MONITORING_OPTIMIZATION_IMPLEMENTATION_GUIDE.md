# Monitoring Optimization Implementation Guide

This guide provides step-by-step instructions for implementing the monitoring optimizations to reduce overhead by 60-70% while maintaining observability.

---

## Quick Start

```python
# Example integration
from src.monitoring.optimization.adaptive_sampler import AdaptiveSampler, SamplingConfig
from src.monitoring.optimization.metric_aggregator import MetricAggregator, AggregationConfig
from src.monitoring.optimization.cardinality_limiter import CardinalityLimiter, CardinalityConfig

# Configure optimized monitoring
sampling_config = SamplingConfig(
    base_interval=30,  # 30s instead of 1s
    min_interval=10,
    max_interval=300
)

aggregation_config = AggregationConfig(
    window_size=60,  # 1-minute aggregations
    calculate_percentiles=True
)

cardinality_config = CardinalityConfig(
    max_series_per_metric=1000,
    enforcement_policy=EnforcementPolicy.AGGREGATE
)
```

---

## Phase 1: Quick Wins (Immediate Impact)

### 1.1 Update Memory Monitor Sampling Interval

**File**: `src/monitoring/memory_monitor.py`

```python
# Change line 119 from:
sampling_interval: float = 1.0

# To:
sampling_interval: float = 30.0  # Reduced from 1s to 30s
```

### 1.2 Update Enhanced Memory Metrics

**File**: `src/monitoring/enhanced_memory_metrics.py`

```python
# Change line 252 from:
time.sleep(10)  # Update every 10 seconds

# To:
time.sleep(60)  # Update every 60 seconds
```

### 1.3 Remove Redundant Collectors

Create a unified memory collector to replace duplicate implementations:

```python
# src/monitoring/unified_memory_collector.py
from src.monitoring.optimization.adaptive_sampler import AdaptiveSampler
from src.monitoring.optimization.metric_aggregator import MetricAggregator

class UnifiedMemoryCollector:
    def __init__(self):
        self.sampler = AdaptiveSampler()
        self.aggregator = MetricAggregator()
        
    def collect(self):
        # Consolidate memory collection logic
        if self.sampler.should_sample('memory_usage'):
            snapshot = self._collect_memory_snapshot()
            self.aggregator.add_sample(
                'memory_usage_bytes',
                snapshot.rss,
                {'component': 'system'}
            )
```

---

## Phase 2: Implement Pre-Aggregation

### 2.1 Update Metrics Collector

**File**: `src/monitoring/metrics.py`

Add aggregation to the MetricsCollector class:

```python
# Add to __init__ method
from src.monitoring.optimization.metric_aggregator import MetricAggregator

self.aggregator = MetricAggregator(AggregationConfig(
    window_size=60,
    calculate_percentiles=True
))

# Update record_http_request method
def record_http_request(self, method: str, endpoint: str, status: int, 
                       duration: float, request_size: int = 0, response_size: int = 0):
    # Add to aggregator instead of direct metric
    self.aggregator.add_sample(
        'http_request_duration',
        duration,
        {'method': method, 'endpoint': endpoint}
    )
    
    # Only increment counter for errors or sampled successes
    if status >= 400 or self._should_sample('http_requests', f"{method}:{endpoint}"):
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=str(status)
        ).inc()
```

### 2.2 Implement Aggregated Metrics Export

```python
# Add to get_metrics method
def get_metrics(self) -> bytes:
    # Get aggregated metrics
    aggregated = self.aggregator.get_prometheus_format()
    
    # Combine with existing metrics
    standard_metrics = generate_latest(self.registry)
    
    return standard_metrics + b'\n' + aggregated.encode('utf-8')
```

---

## Phase 3: Adaptive Sampling Integration

### 3.1 Update Memory Monitor with Adaptive Sampling

```python
# src/monitoring/memory_monitor.py
from src.monitoring.optimization.adaptive_sampler import AdaptiveSampler

class MemoryMonitor:
    def __init__(self):
        self.sampler = AdaptiveSampler(SamplingConfig(
            base_interval=30,
            min_interval=10,
            max_interval=300,
            stability_threshold=0.05
        ))
        
    def _monitor_loop(self):
        while self._monitoring:
            # Use adaptive sampling
            if self.sampler.should_sample('memory_usage'):
                snapshot = self._collect_snapshot()
                self.history.append(snapshot)
                self._update_metrics(snapshot)
                
            # Sleep for minimum interval
            time.sleep(self.sampler.config.min_interval)
```

### 3.2 Configure Metric-Specific Sampling

```python
# Metric-specific configurations
METRIC_CONFIGS = {
    'memory_usage_bytes': {
        'base_interval': 30,
        'stability_threshold': 0.02  # Very stable
    },
    'cpu_usage_percent': {
        'base_interval': 15,
        'stability_threshold': 0.1  # More variable
    },
    'http_request_duration': {
        'base_interval': 5,
        'stability_threshold': 0.2  # High variability
    }
}
```

---

## Phase 4: Cardinality Control

### 4.1 Integrate Cardinality Limiter

```python
# src/monitoring/metrics.py
from src.monitoring.optimization.cardinality_limiter import CardinalityLimiter

class MetricsCollector:
    def __init__(self):
        self.limiter = CardinalityLimiter(CardinalityConfig(
            max_series_per_metric=1000,
            max_total_series=10000,
            enforcement_policy=EnforcementPolicy.AGGREGATE
        ))
        
        # Register alert callback
        self.limiter.register_alert_callback(self._cardinality_alert)
        
    def _cardinality_alert(self, metric_name: str, utilization: float):
        logger.warning(f"Metric {metric_name} at {utilization:.1%} cardinality limit")
```

### 4.2 Apply Cardinality Limits

```python
def record_http_request(self, method: str, endpoint: str, status: int, duration: float):
    # Check cardinality before recording
    labels = {'method': method, 'endpoint': endpoint, 'status': str(status)}
    accepted, processed_labels = self.limiter.should_accept('http_requests', labels)
    
    if accepted:
        self.http_requests_total.labels(**processed_labels).inc()
```

---

## Configuration File

Create a central configuration file for monitoring optimization:

```yaml
# config/monitoring_optimization.yaml
sampling:
  memory:
    base_interval: 30
    adaptive: true
    stability_threshold: 0.05
  
  gc:
    interval: 300
    on_demand: true
  
  http:
    success_sample_rate: 0.1
    error_sample_rate: 1.0

aggregation:
  enabled: true
  window_size: 60
  percentiles: [0.5, 0.95, 0.99]
  flush_on_shutdown: true

cardinality:
  max_series_per_metric: 1000
  max_total_series: 10000
  policy: aggregate
  cleanup_interval: 3600
  
  # High-cardinality metrics with specific limits
  limits:
    http_requests: 2000
    ai_requests: 500
    mcp_tool_calls: 1000
```

---

## Testing the Optimizations

### 1. Benchmark Script

```python
# scripts/benchmark_monitoring_overhead.py
import time
import psutil
import gc
from src.monitoring.metrics import get_metrics_collector

def benchmark_monitoring():
    """Benchmark monitoring overhead."""
    collector = get_metrics_collector()
    
    # Baseline
    process = psutil.Process()
    baseline_cpu = process.cpu_percent(interval=1)
    baseline_memory = process.memory_info().rss
    
    # Simulate load
    start_time = time.time()
    for i in range(10000):
        collector.record_http_request(
            method='GET',
            endpoint=f'/api/users/{i % 100}',
            status=200,
            duration=0.1
        )
        
    # Measure overhead
    elapsed = time.time() - start_time
    final_cpu = process.cpu_percent(interval=1)
    final_memory = process.memory_info().rss
    
    print(f"Requests/second: {10000 / elapsed:.2f}")
    print(f"CPU overhead: {final_cpu - baseline_cpu:.2f}%")
    print(f"Memory overhead: {(final_memory - baseline_memory) / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    benchmark_monitoring()
```

### 2. Validation Tests

```python
# tests/test_monitoring_optimization.py
import pytest
from src.monitoring.optimization.adaptive_sampler import AdaptiveSampler
from src.monitoring.optimization.metric_aggregator import MetricAggregator
from src.monitoring.optimization.cardinality_limiter import CardinalityLimiter

def test_adaptive_sampling_reduces_frequency():
    """Test that stable metrics get longer intervals."""
    sampler = AdaptiveSampler()
    
    # Simulate stable metric
    for i in range(10):
        sampler.update_metric_value('stable_metric', 100.0)
        
    interval = sampler.get_adaptive_interval('stable_metric')
    assert interval > sampler.config.base_interval

def test_aggregation_reduces_data_points():
    """Test that aggregation reduces data volume."""
    aggregator = MetricAggregator()
    
    # Add 100 samples
    for i in range(100):
        aggregator.add_sample('test_metric', float(i))
        
    # Should have much fewer aggregated points
    aggregated = aggregator.get_aggregated_metrics()
    assert len(aggregated) < 10

def test_cardinality_limiting():
    """Test cardinality limits are enforced."""
    limiter = CardinalityLimiter(CardinalityConfig(max_series_per_metric=10))
    
    # Try to add 20 unique series
    accepted_count = 0
    for i in range(20):
        accepted, _ = limiter.should_accept('test_metric', {'id': str(i)})
        if accepted:
            accepted_count += 1
            
    assert accepted_count == 10
```

---

## Monitoring Dashboard Updates

Update Grafana dashboards to use aggregated metrics:

```json
{
  "panels": [
    {
      "title": "Memory Usage (Aggregated)",
      "targets": [
        {
          "expr": "memory_usage_bytes_p95{component=\"system\"}",
          "legendFormat": "95th percentile"
        },
        {
          "expr": "memory_usage_bytes_avg{component=\"system\"}",
          "legendFormat": "Average"
        }
      ]
    }
  ]
}
```

---

## Rollback Plan

If issues arise, rollback is straightforward:

1. **Revert sampling intervals** in configuration
2. **Disable aggregation** by setting `aggregation.enabled: false`
3. **Set cardinality policy** to `alert_only`
4. **Restart services** to apply changes

---

## Expected Results After Implementation

### Week 1 (Quick Wins)
- Data points: -69% (from 865,800 to 265,800/day)
- CPU usage: -50% (from 3.6 to 1.8 minutes/day)
- Memory: -40% (from 43MB to 26MB/day)

### Week 2 (Aggregation)
- Data points: -94% (to 50,000/day)
- CPU usage: -75% (to 0.9 minutes/day)
- Memory: -85% (to 6.5MB/day)

### Week 3 (Full Optimization)
- Data points: -96.5% (to 30,000/day)
- CPU usage: -86% (to 0.5 minutes/day)
- Memory: -96% (to 1.5MB/day)

---

## Maintenance

1. **Monthly cardinality review**: Check cardinality stats and adjust limits
2. **Quarterly sampling review**: Analyze sampling effectiveness
3. **Alert on anomalies**: Set up alerts for sudden cardinality spikes

```python
# Maintenance script
from src.monitoring.optimization.cardinality_limiter import get_cardinality_stats

def monthly_review():
    stats = get_cardinality_stats()
    
    # Check for metrics near limits
    for metric, data in stats['metrics'].items():
        if data['utilization'] > 0.9:
            print(f"WARNING: {metric} at {data['utilization']:.1%} capacity")
            
    # Optimize if needed
    removed = limiter.optimize_cardinality()
    print(f"Optimization removed {sum(removed.values())} low-value series")
```

This implementation guide provides a practical path to reducing monitoring overhead while maintaining comprehensive observability.