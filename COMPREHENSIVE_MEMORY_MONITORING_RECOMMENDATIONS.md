# Comprehensive Memory Monitoring and Alerting Recommendations

## Executive Summary

This document provides comprehensive recommendations for proactive memory monitoring and alerting that would have prevented the fatal memory issue encountered. The recommendations focus on early detection, trend analysis, and automated response mechanisms.

## Current State Analysis

### Existing Monitoring Capabilities
- Basic system metrics via psutil
- Prometheus metrics collection for HTTP requests and business operations
- Alert rules for CPU, disk, and basic memory usage (>90% threshold)
- Health checks with memory percentage monitoring
- Grafana dashboards for visualization

### Gaps Identified
1. **Reactive Monitoring**: Current memory alerts only trigger at 90% usage - too late for proactive intervention
2. **Limited Memory Metrics**: Missing heap growth rate, GC performance, memory leak detection
3. **No Trend Analysis**: Lack of memory growth trend monitoring and prediction
4. **Application-Specific Metrics**: Missing Python-specific memory metrics (object counts, reference cycles)
5. **Early Warning Systems**: No graduated alerting for memory pressure

## Enhanced Memory Monitoring Strategy

### 1. Multi-Level Memory Metrics Collection

#### A. System-Level Memory Metrics
```yaml
# Enhanced memory metrics in prometheus.yml
memory_metrics:
  - memory_usage_bytes{type="rss,vms,shared,text,lib,data,dirty"}
  - memory_available_bytes
  - memory_buffers_bytes  
  - memory_cached_bytes
  - memory_swap_used_bytes
  - memory_swap_free_bytes
  - memory_commit_limit_bytes
  - memory_committed_as_bytes
```

#### B. Process-Level Memory Metrics
```yaml
process_memory_metrics:
  - process_memory_rss_bytes
  - process_memory_vms_bytes
  - process_memory_shared_bytes
  - process_memory_text_bytes
  - process_memory_data_bytes
  - process_memory_dirty_bytes
  - process_memory_percent
  - process_memory_growth_rate_bytes_per_second
  - process_memory_peak_rss_bytes
```

#### C. Python-Specific Memory Metrics
```yaml
python_memory_metrics:
  - python_gc_objects_collected_total{generation="0,1,2"}
  - python_gc_objects_uncollectable_total{generation="0,1,2"}
  - python_gc_collections_total{generation="0,1,2"}
  - python_gc_time_seconds_total{generation="0,1,2"}
  - python_memory_objects_total{type="dict,list,tuple,set,function"}
  - python_memory_heap_size_bytes
  - python_memory_heap_free_bytes
  - python_memory_reference_cycles_total
```

#### D. Application-Specific Memory Metrics
```yaml
application_memory_metrics:
  - circle_of_experts_memory_usage_bytes{expert_type}
  - mcp_server_memory_usage_bytes{server_name}
  - database_connection_pool_memory_bytes
  - cache_memory_usage_bytes{cache_type}
  - active_request_memory_bytes
  - websocket_connection_memory_bytes
```

### 2. Enhanced Prometheus Configuration

#### prometheus.yml Enhancements
```yaml
# Add to existing prometheus.yml
scrape_configs:
  # Enhanced application metrics with memory focus
  - job_name: 'claude-api-memory'
    static_configs:
      - targets: ['host.docker.internal:8000']
    metrics_path: '/metrics/memory'
    scrape_interval: 5s  # More frequent for memory metrics
    scrape_timeout: 10s

  # Python process metrics
  - job_name: 'python-process-metrics'
    static_configs:
      - targets: ['host.docker.internal:8000']
    metrics_path: '/metrics/python'
    scrape_interval: 10s

  # GC metrics
  - job_name: 'python-gc-metrics'
    static_configs:
      - targets: ['host.docker.internal:8000']
    metrics_path: '/metrics/gc'
    scrape_interval: 30s

# Enhanced recording rules for memory trends
rule_files:
  - /etc/prometheus/memory_alerts.yml
  - /etc/prometheus/memory_recording_rules.yml
```

### 3. Memory-Specific Alert Rules

#### memory_alerts.yml
```yaml
groups:
  - name: memory_alerts
    interval: 15s
    rules:
      # Early Warning - Memory Pressure
      - alert: MemoryPressureEarly
        expr: memory_usage_bytes{type="percent"} > 70
        for: 5m
        labels:
          severity: low
          team: infrastructure
        annotations:
          summary: "Early memory pressure detected"
          description: "Memory usage is {{ $value }}% for 5 minutes"
          runbook: "https://docs.company.com/runbooks/memory-pressure"

      # Warning - High Memory Usage
      - alert: MemoryUsageHigh
        expr: memory_usage_bytes{type="percent"} > 80
        for: 3m
        labels:
          severity: medium
          team: infrastructure
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ $value }}% for 3 minutes"
          action: "Consider scaling horizontally or investigating memory leaks"

      # Critical - Very High Memory Usage
      - alert: MemoryUsageCritical
        expr: memory_usage_bytes{type="percent"} > 90
        for: 1m
        labels:
          severity: high
          team: infrastructure
        annotations:
          summary: "Critical memory usage"
          description: "Memory usage is {{ $value }}% for 1 minute - immediate action required"
          action: "Scale immediately or restart service to prevent OOM"

      # Fatal - Imminent OOM
      - alert: MemoryUsageFatal
        expr: memory_usage_bytes{type="percent"} > 95
        for: 30s
        labels:
          severity: critical
          team: infrastructure
        annotations:
          summary: "FATAL: Imminent out-of-memory condition"
          description: "Memory usage is {{ $value }}% - OOM likely within minutes"
          action: "IMMEDIATE: Scale or restart service NOW"

      # Memory Growth Rate
      - alert: MemoryGrowthRateHigh
        expr: rate(process_memory_rss_bytes[5m]) > 10485760  # 10MB/5min
        for: 10m
        labels:
          severity: medium
          team: development
        annotations:
          summary: "High memory growth rate detected"
          description: "Memory is growing at {{ $value | humanize }}B/5min"
          action: "Investigate potential memory leak"

      # Memory Growth Rate Critical
      - alert: MemoryGrowthRateCritical
        expr: rate(process_memory_rss_bytes[5m]) > 52428800  # 50MB/5min
        for: 5m
        labels:
          severity: high
          team: development
        annotations:
          summary: "Critical memory growth rate"
          description: "Memory is growing at {{ $value | humanize }}B/5min - potential leak"
          action: "URGENT: Investigate memory leak immediately"

      # GC Performance Alerts
      - alert: GCPerformanceDegraded
        expr: rate(python_gc_time_seconds_total[5m]) > 0.1
        for: 5m
        labels:
          severity: medium
          team: development
        annotations:
          summary: "Garbage collection performance degraded"
          description: "GC is consuming {{ $value | humanizePercentage }} of CPU time"
          action: "Review memory allocation patterns and object lifecycle"

      # Heap Growth Rate
      - alert: HeapGrowthSustained
        expr: increase(python_memory_heap_size_bytes[15m]) > 104857600  # 100MB in 15min
        for: 15m
        labels:
          severity: medium
          team: development
        annotations:
          summary: "Sustained heap growth detected"
          description: "Heap has grown {{ $value | humanize }}B in 15 minutes"
          action: "Monitor for memory leaks and review object retention"

      # Object Count Growth
      - alert: ObjectCountGrowthHigh
        expr: rate(python_memory_objects_total[10m]) > 1000
        for: 10m
        labels:
          severity: medium
          team: development
        annotations:
          summary: "High object creation rate"
          description: "Creating {{ $value }} objects per 10 minutes"
          action: "Review object creation patterns and consider object pooling"

      # Available Memory Low
      - alert: AvailableMemoryLow
        expr: memory_available_bytes < 536870912  # 512MB
        for: 2m
        labels:
          severity: high
          team: infrastructure
        annotations:
          summary: "Available memory critically low"
          description: "Only {{ $value | humanize }}B of memory available"
          action: "Scale immediately or free memory"

      # Swap Usage High
      - alert: SwapUsageHigh
        expr: memory_swap_used_bytes / (memory_swap_used_bytes + memory_swap_free_bytes) * 100 > 50
        for: 5m
        labels:
          severity: medium
          team: infrastructure
        annotations:
          summary: "High swap usage detected"
          description: "Swap usage is {{ $value }}%"
          action: "Consider increasing memory or optimizing memory usage"

      # Memory Fragmentation
      - alert: MemoryFragmentationHigh
        expr: (memory_usage_bytes{type="vms"} - memory_usage_bytes{type="rss"}) / memory_usage_bytes{type="vms"} * 100 > 30
        for: 10m
        labels:
          severity: low
          team: development
        annotations:
          summary: "High memory fragmentation"
          description: "Memory fragmentation is {{ $value }}%"
          action: "Consider memory defragmentation or allocation strategy changes"
```

### 4. Memory Recording Rules

#### memory_recording_rules.yml
```yaml
groups:
  - name: memory_recording_rules
    interval: 30s
    rules:
      # Memory usage trends
      - record: memory:usage_rate_5m
        expr: rate(memory_usage_bytes{type="rss"}[5m])
      
      - record: memory:usage_rate_1h
        expr: rate(memory_usage_bytes{type="rss"}[1h])
      
      - record: memory:usage_rate_24h
        expr: rate(memory_usage_bytes{type="rss"}[24h])

      # Memory efficiency metrics
      - record: memory:efficiency_ratio
        expr: memory_usage_bytes{type="rss"} / memory_usage_bytes{type="vms"}

      # Memory pressure index (0-100)
      - record: memory:pressure_index
        expr: |
          (
            (memory_usage_bytes{type="percent"} * 0.4) +
            (rate(memory_usage_bytes{type="rss"}[5m]) / 1048576 * 0.3) +  # Growth rate factor
            (rate(python_gc_time_seconds_total[5m]) * 100 * 0.2) +        # GC pressure factor
            ((memory_swap_used_bytes / (memory_swap_used_bytes + memory_swap_free_bytes)) * 100 * 0.1)  # Swap factor
          )

      # Predicted memory exhaustion time (in seconds)
      - record: memory:exhaustion_time_seconds
        expr: |
          (memory_available_bytes / rate(memory_usage_bytes{type="rss"}[5m])) 
          and rate(memory_usage_bytes{type="rss"}[5m]) > 0

      # Memory allocation efficiency
      - record: memory:allocation_efficiency
        expr: |
          rate(python_memory_objects_total[5m]) / 
          (rate(memory_usage_bytes{type="rss"}[5m]) / 1024)  # objects per KB allocated
```

### 5. Enhanced Alertmanager Configuration

#### Enhanced alertmanager.yml additions
```yaml
route:
  routes:
    # Memory-specific routing
    - match_re:
        alertname: ^(Memory|Heap|GC|Swap).*
      receiver: memory-alerts
      group_by: ['alertname', 'instance']
      group_wait: 10s
      group_interval: 30s
      repeat_interval: 5m  # More frequent for memory alerts
      continue: true

    # Critical memory alerts get immediate attention
    - match:
        severity: critical
        alertname: MemoryUsageFatal
      receiver: critical-memory-alerts
      group_wait: 0s
      repeat_interval: 1m

receivers:
  - name: memory-alerts
    slack_configs:
      - channel: '#memory-alerts'
        title: '🧠 Memory Alert: {{ .GroupLabels.alertname }}'
        text: |
          Instance: {{ .GroupLabels.instance }}
          {{ range .Alerts }}
          Status: {{ .Status }}
          Description: {{ .Annotations.description }}
          Action: {{ .Annotations.action }}
          Runbook: {{ .Annotations.runbook }}
          {{ end }}
    webhook_configs:
      - url: 'http://host.docker.internal:8000/webhooks/memory-alerts'
        send_resolved: true

  - name: critical-memory-alerts
    pagerduty_configs:
      - service_key: 'MEMORY_PAGERDUTY_KEY'
        description: 'CRITICAL MEMORY: {{ .GroupLabels.alertname }}'
        severity: 'critical'
    slack_configs:
      - channel: '#critical-alerts'
        title: '🚨 CRITICAL MEMORY: {{ .GroupLabels.alertname }}'
        text: |
          ⚠️ IMMEDIATE ACTION REQUIRED ⚠️
          {{ range .Alerts }}{{ .Annotations.description }}{{ end }}
          Action: {{ .Annotations.action }}
```

### 6. Grafana Dashboard Enhancements

#### Memory-Focused Dashboard Panels
```json
{
  "dashboard": {
    "title": "Memory Monitoring - Proactive",
    "panels": [
      {
        "title": "Memory Usage Timeline",
        "type": "graph",
        "targets": [
          {
            "expr": "memory_usage_bytes{type=\"percent\"}",
            "legendFormat": "Memory Usage %"
          },
          {
            "expr": "predict_linear(memory_usage_bytes{type=\"percent\"}[30m], 3600)",
            "legendFormat": "Predicted (1h)"
          }
        ],
        "alert": {
          "conditions": [
            {
              "query": {"queryType": "", "refId": "A"},
              "reducer": {"type": "last", "params": []},
              "evaluator": {"params": [85], "type": "gt"}
            }
          ],
          "executionErrorState": "alerting",
          "for": "5m",
          "frequency": "10s",
          "handler": 1,
          "name": "Memory Usage High",
          "noDataState": "no_data",
          "notifications": []
        }
      },
      {
        "title": "Memory Growth Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(process_memory_rss_bytes[5m])",
            "legendFormat": "Growth Rate (5m)"
          },
          {
            "expr": "rate(process_memory_rss_bytes[1h])",
            "legendFormat": "Growth Rate (1h)"
          }
        ]
      },
      {
        "title": "Memory Pressure Index",
        "type": "singlestat",
        "targets": [
          {
            "expr": "memory:pressure_index",
            "legendFormat": "Pressure Index"
          }
        ],
        "thresholds": "70,85,95",
        "colorBackground": true
      },
      {
        "title": "Predicted Memory Exhaustion",
        "type": "singlestat",
        "targets": [
          {
            "expr": "memory:exhaustion_time_seconds / 3600",
            "legendFormat": "Hours until exhaustion"
          }
        ],
        "thresholds": "24,8,2",
        "colorBackground": true,
        "unit": "h"
      },
      {
        "title": "GC Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(python_gc_time_seconds_total[5m]) * 100",
            "legendFormat": "GC Time %"
          },
          {
            "expr": "rate(python_gc_collections_total[5m])",
            "legendFormat": "GC Collections/sec"
          }
        ]
      },
      {
        "title": "Memory Distribution",
        "type": "piechart",
        "targets": [
          {
            "expr": "memory_usage_bytes{type=\"rss\"}",
            "legendFormat": "RSS"
          },
          {
            "expr": "memory_usage_bytes{type=\"cached\"}",
            "legendFormat": "Cached"
          },
          {
            "expr": "memory_usage_bytes{type=\"available\"}",
            "legendFormat": "Available"
          }
        ]
      }
    ]
  }
}
```

### 7. Application Code Enhancements

#### Enhanced Metrics Collection in metrics.py
```python
# Add to src/monitoring/metrics.py

import gc
import tracemalloc
import resource
from typing import Dict, Any

class EnhancedMemoryMetrics:
    """Enhanced memory metrics collection for proactive monitoring."""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        
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
        
        # Enable tracemalloc for detailed memory tracking
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            
        self._last_memory_check = time.time()
        self._last_memory_value = 0
    
    def update_python_memory_metrics(self):
        """Update Python-specific memory metrics."""
        try:
            # GC statistics
            gc_stats = gc.get_stats()
            for i, stats in enumerate(gc_stats):
                self.python_gc_objects_collected.labels(generation=str(i)).inc(
                    stats.get('collections', 0)
                )
                self.python_gc_objects_uncollectable.labels(generation=str(i)).inc(
                    stats.get('uncollectable', 0)
                )
            
            # Object counts by type
            object_counts = {}
            for obj in gc.get_objects():
                obj_type = type(obj).__name__
                object_counts[obj_type] = object_counts.get(obj_type, 0) + 1
            
            # Only track major object types to avoid label explosion
            major_types = ['dict', 'list', 'tuple', 'set', 'function', 'type', 'module']
            for obj_type in major_types:
                count = object_counts.get(obj_type, 0)
                self.python_memory_objects.labels(type=obj_type).set(count)
            
            # Tracemalloc statistics
            if tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                self.python_memory_heap_size.set(current)
            
            # Process memory information
            usage = resource.getrusage(resource.RUSAGE_SELF)
            self.process_memory_peak_rss.set(usage.ru_maxrss * 1024)  # Convert KB to bytes
            
            # Calculate memory growth rate
            current_time = time.time()
            current_memory = psutil.Process().memory_info().rss
            
            if self._last_memory_value > 0:
                time_diff = current_time - self._last_memory_check
                memory_diff = current_memory - self._last_memory_value
                if time_diff > 0:
                    growth_rate = memory_diff / time_diff
                    self.memory_growth_rate.set(growth_rate)
            
            self._last_memory_check = current_time
            self._last_memory_value = current_memory
            
        except Exception:
            pass  # Don't let metrics collection affect the application
```

### 8. Automated Response System

#### Memory Pressure Response Handler
```python
# Add to src/monitoring/memory_response.py

import asyncio
import logging
from typing import Dict, Any, Optional
from enum import Enum

class MemoryPressureLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"

class MemoryPressureHandler:
    """Automated response to memory pressure alerts."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.response_history: Dict[str, datetime] = {}
        
    async def handle_memory_alert(self, alert: Alert):
        """Handle memory pressure alerts with automated responses."""
        pressure_level = self._determine_pressure_level(alert)
        
        # Prevent rapid repeated responses
        if self._should_skip_response(alert):
            return
            
        self.logger.warning(f"Memory pressure detected: {pressure_level.value}")
        
        try:
            if pressure_level == MemoryPressureLevel.LOW:
                await self._handle_low_pressure()
            elif pressure_level == MemoryPressureLevel.MEDIUM:
                await self._handle_medium_pressure()
            elif pressure_level == MemoryPressureLevel.HIGH:
                await self._handle_high_pressure()
            elif pressure_level == MemoryPressureLevel.CRITICAL:
                await self._handle_critical_pressure()
                
            self.response_history[alert.fingerprint] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Failed to handle memory pressure: {e}")
    
    def _determine_pressure_level(self, alert: Alert) -> MemoryPressureLevel:
        """Determine the memory pressure level from alert."""
        if alert.rule.name == "MemoryUsageFatal":
            return MemoryPressureLevel.CRITICAL
        elif alert.rule.name in ["MemoryUsageCritical", "AvailableMemoryLow"]:
            return MemoryPressureLevel.HIGH
        elif alert.rule.name in ["MemoryUsageHigh", "MemoryGrowthRateCritical"]:
            return MemoryPressureLevel.MEDIUM
        else:
            return MemoryPressureLevel.LOW
    
    def _should_skip_response(self, alert: Alert) -> bool:
        """Check if we should skip response to prevent thrashing."""
        last_response = self.response_history.get(alert.fingerprint)
        if last_response:
            time_since = datetime.now() - last_response
            return time_since < timedelta(minutes=5)  # Minimum 5 minutes between responses
        return False
    
    async def _handle_low_pressure(self):
        """Handle low memory pressure - monitoring and logging."""
        self.logger.info("Low memory pressure - monitoring situation")
        
        # Force garbage collection
        import gc
        collected = gc.collect()
        self.logger.info(f"Garbage collection freed {collected} objects")
        
    async def _handle_medium_pressure(self):
        """Handle medium memory pressure - optimization actions."""
        self.logger.warning("Medium memory pressure - taking optimization actions")
        
        # Force full garbage collection
        import gc
        for generation in range(3):
            collected = gc.collect()
            self.logger.info(f"GC generation {generation}: freed {collected} objects")
        
        # Clear caches if available
        try:
            from ..core.cache import clear_caches
            await clear_caches()
        except:
            pass
            
        # Reduce connection pool sizes temporarily
        try:
            from ..database.connection import reduce_pool_size
            await reduce_pool_size(target_ratio=0.8)
        except:
            pass
    
    async def _handle_high_pressure(self):
        """Handle high memory pressure - aggressive actions."""
        self.logger.error("High memory pressure - taking aggressive actions")
        
        # All medium pressure actions first
        await self._handle_medium_pressure()
        
        # More aggressive cache clearing
        try:
            from ..core.cache import clear_all_caches
            await clear_all_caches()
        except:
            pass
            
        # Reduce Circle of Experts concurrent operations
        try:
            from ..circle_of_experts.core.expert_manager import reduce_concurrency
            await reduce_concurrency(max_concurrent=2)
        except:
            pass
            
        # Close idle connections
        try:
            from ..database.connection import close_idle_connections
            await close_idle_connections(max_idle_time=30)
        except:
            pass
    
    async def _handle_critical_pressure(self):
        """Handle critical memory pressure - emergency actions."""
        self.logger.critical("CRITICAL memory pressure - emergency response")
        
        # All previous actions
        await self._handle_high_pressure()
        
        # Emergency connection pool reduction
        try:
            from ..database.connection import emergency_pool_reduction
            await emergency_pool_reduction()
        except:
            pass
            
        # Pause non-critical operations
        try:
            from ..core.circuit_breaker import emergency_circuit_breaker
            await emergency_circuit_breaker("memory_pressure")
        except:
            pass
            
        # Trigger auto-scaling if available
        try:
            await self._trigger_auto_scaling()
        except:
            pass
    
    async def _trigger_auto_scaling(self):
        """Trigger auto-scaling to add more instances."""
        # This would integrate with your orchestration platform
        # Kubernetes, Docker Swarm, etc.
        self.logger.info("Triggering auto-scaling due to memory pressure")
        
        # Example: Scale Kubernetes deployment
        # kubectl scale deployment claude-deployment-engine --replicas=5
```

### 9. Performance Baseline Establishment

#### Memory Baseline Collection
```python
# Add to src/monitoring/baseline.py

class MemoryBaselineCollector:
    """Collect and maintain memory performance baselines."""
    
    def __init__(self):
        self.baselines: Dict[str, Dict[str, float]] = {}
        
    async def collect_baseline(self, duration_hours: int = 24):
        """Collect memory baseline over specified duration."""
        metrics = []
        
        # Collect metrics every 5 minutes for the duration
        for _ in range(duration_hours * 12):
            metric_snapshot = await self._collect_memory_snapshot()
            metrics.append(metric_snapshot)
            await asyncio.sleep(300)  # 5 minutes
        
        # Calculate baseline statistics
        baseline = self._calculate_baseline_stats(metrics)
        self.baselines['default'] = baseline
        
        return baseline
    
    async def _collect_memory_snapshot(self) -> Dict[str, float]:
        """Collect current memory metrics snapshot."""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'percent': process.memory_percent(),
            'available_mb': psutil.virtual_memory().available / 1024 / 1024,
            'gc_objects': len(gc.get_objects()),
            'open_files': len(process.open_files())
        }
    
    def _calculate_baseline_stats(self, metrics: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        """Calculate baseline statistics from collected metrics."""
        baseline = {}
        
        for metric_name in metrics[0].keys():
            values = [m[metric_name] for m in metrics]
            baseline[metric_name] = {
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'std_dev': statistics.stdev(values),
                'min': min(values),
                'max': max(values),
                'p95': statistics.quantiles(values, n=20)[18],  # 95th percentile
                'p99': statistics.quantiles(values, n=100)[98]   # 99th percentile
            }
        
        return baseline
```

### 10. Log-Based Memory Pattern Monitoring

#### Memory Pattern Detection
```python
# Add to src/monitoring/log_patterns.py

import re
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class MemoryPattern:
    pattern_type: str
    description: str
    severity: str
    count: int
    first_seen: datetime
    last_seen: datetime

class MemoryLogAnalyzer:
    """Analyze logs for memory-related patterns and anomalies."""
    
    def __init__(self):
        self.patterns = {
            'oom_killer': re.compile(r'Out of memory: Kill process'),
            'malloc_fail': re.compile(r'malloc.*failed|Memory allocation failed'),
            'gc_pressure': re.compile(r'gc: \d+ ms'),
            'memory_warning': re.compile(r'memory.*warning|low memory'),
            'swap_thrashing': re.compile(r'swap.*thrashing|excessive swapping')
        }
        
        self.detected_patterns: Dict[str, MemoryPattern] = {}
    
    def analyze_log_line(self, log_line: str, timestamp: datetime = None):
        """Analyze a single log line for memory patterns."""
        timestamp = timestamp or datetime.now()
        
        for pattern_name, pattern_regex in self.patterns.items():
            if pattern_regex.search(log_line):
                self._record_pattern_match(pattern_name, log_line, timestamp)
    
    def _record_pattern_match(self, pattern_name: str, log_line: str, timestamp: datetime):
        """Record a pattern match."""
        if pattern_name in self.detected_patterns:
            pattern = self.detected_patterns[pattern_name]
            pattern.count += 1
            pattern.last_seen = timestamp
        else:
            self.detected_patterns[pattern_name] = MemoryPattern(
                pattern_type=pattern_name,
                description=self._get_pattern_description(pattern_name),
                severity=self._get_pattern_severity(pattern_name),
                count=1,
                first_seen=timestamp,
                last_seen=timestamp
            )
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        descriptions = {
            'oom_killer': 'Out of memory killer activated',
            'malloc_fail': 'Memory allocation failures',
            'gc_pressure': 'High garbage collection pressure', 
            'memory_warning': 'Memory warnings in logs',
            'swap_thrashing': 'Swap thrashing detected'
        }
        return descriptions.get(pattern_name, 'Unknown pattern')
    
    def _get_pattern_severity(self, pattern_name: str) -> str:
        severities = {
            'oom_killer': 'critical',
            'malloc_fail': 'high',
            'gc_pressure': 'medium',
            'memory_warning': 'low',
            'swap_thrashing': 'high'
        }
        return severities.get(pattern_name, 'medium')
    
    def get_recent_patterns(self, hours: int = 1) -> List[MemoryPattern]:
        """Get patterns detected in the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            pattern for pattern in self.detected_patterns.values()
            if pattern.last_seen >= cutoff
        ]
```

## Implementation Priorities

### Phase 1: Critical Foundation (Week 1)
1. Deploy enhanced memory alert rules with multi-level thresholds
2. Implement memory growth rate monitoring
3. Set up automated memory pressure response system
4. Configure critical memory alerts with PagerDuty integration

### Phase 2: Comprehensive Monitoring (Week 2)
1. Deploy Python-specific memory metrics
2. Implement GC performance monitoring
3. Set up memory baseline collection
4. Deploy enhanced Grafana dashboards

### Phase 3: Advanced Analysis (Week 3)
1. Implement log-based memory pattern detection
2. Deploy predictive memory exhaustion alerts
3. Set up automated scaling triggers
4. Implement memory efficiency reporting

### Phase 4: Optimization (Week 4)
1. Fine-tune alert thresholds based on baseline data
2. Implement advanced memory pressure responses
3. Deploy memory leak detection automation
4. Set up memory performance trend analysis

## Success Metrics

### Immediate (1 month)
- Memory alerts trigger 15+ minutes before OOM conditions
- Zero unexpected OOM kills
- Memory growth rate alerts catch leaks within 30 minutes
- Automated responses reduce memory pressure in 80% of cases

### Long-term (3 months)
- Predictive alerts prevent 95% of memory issues
- Memory efficiency improves by 20%
- Incident response time reduced by 75%
- Zero memory-related downtime

## Conclusion

This comprehensive memory monitoring strategy provides multiple layers of protection against memory-related failures. The graduated alerting system ensures early intervention, while automated responses provide immediate relief during memory pressure events.

The key to preventing the fatal memory issue would have been the combination of:
1. **Early Warning**: 70% threshold alerts would have provided 15+ minutes notice
2. **Growth Rate Monitoring**: Rapid memory growth would have been detected immediately
3. **Automated Response**: Memory pressure handlers would have taken corrective action
4. **Predictive Analytics**: Trend analysis would have predicted exhaustion time

Regular baseline collection and pattern analysis ensure the monitoring system adapts to application behavior over time, providing increasingly accurate and actionable alerts.