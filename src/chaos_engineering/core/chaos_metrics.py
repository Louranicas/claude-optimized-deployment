"""
Chaos Engineering Metrics Collection and Analysis
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import statistics
import logging

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of chaos engineering metrics."""
    # Experiment lifecycle
    EXPERIMENT_CREATED = "experiment_created"
    EXPERIMENT_STARTED = "experiment_started"
    EXPERIMENT_COMPLETED = "experiment_completed"
    EXPERIMENT_FAILED = "experiment_failed"
    EXPERIMENT_CANCELLED = "experiment_cancelled"
    
    # Scenario events
    SCENARIO_STARTED = "scenario_started"
    SCENARIO_COMPLETED = "scenario_completed"
    SCENARIO_FAILED = "scenario_failed"
    
    # System metrics
    SYSTEM_DEGRADATION_DETECTED = "system_degradation_detected"
    SYSTEM_RECOVERY_DETECTED = "system_recovery_detected"
    COMPONENT_FAILURE = "component_failure"
    COMPONENT_RECOVERY = "component_recovery"
    
    # Performance metrics
    RESPONSE_TIME = "response_time"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    AVAILABILITY = "availability"
    
    # Resilience metrics
    MTTR = "mean_time_to_recovery"
    MTBF = "mean_time_between_failures"
    RESILIENCE_SCORE = "resilience_score"


@dataclass
class MetricPoint:
    """A single metric data point."""
    timestamp: datetime
    metric_type: MetricType
    experiment_id: str
    scenario_id: Optional[str] = None
    value: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetricSummary:
    """Summary statistics for a metric."""
    metric_type: MetricType
    count: int
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    mean: Optional[float] = None
    median: Optional[float] = None
    std_dev: Optional[float] = None
    percentiles: Dict[int, float] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ChaosMetrics:
    """
    Chaos engineering metrics collection and analysis system.
    """
    
    def __init__(self, retention_hours: int = 168):  # 7 days default
        self.retention_hours = retention_hours
        self.metrics: deque = deque()
        self.metric_indices: Dict[MetricType, List[MetricPoint]] = defaultdict(list)
        self.experiment_metrics: Dict[str, List[MetricPoint]] = defaultdict(list)
        self._last_cleanup = time.time()
        
    def record(self, 
               metric_type: MetricType,
               experiment_id: str,
               value: Any = None,
               scenario_id: Optional[str] = None,
               metadata: Optional[Dict[str, Any]] = None,
               tags: Optional[Dict[str, str]] = None):
        """
        Record a metric point.
        
        Args:
            metric_type: Type of metric
            experiment_id: ID of the experiment
            value: Metric value
            scenario_id: Optional scenario ID
            metadata: Additional metadata
            tags: Tags for grouping/filtering
        """
        point = MetricPoint(
            timestamp=datetime.now(),
            metric_type=metric_type,
            experiment_id=experiment_id,
            scenario_id=scenario_id,
            value=value,
            metadata=metadata or {},
            tags=tags or {}
        )
        
        # Store metric point
        self.metrics.append(point)
        self.metric_indices[metric_type].append(point)
        self.experiment_metrics[experiment_id].append(point)
        
        # Periodic cleanup
        if time.time() - self._last_cleanup > 3600:  # Cleanup every hour
            self._cleanup_old_metrics()
    
    def _cleanup_old_metrics(self):
        """Remove metrics older than retention period."""
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        
        # Clean main metrics deque
        while self.metrics and self.metrics[0].timestamp < cutoff_time:
            old_point = self.metrics.popleft()
            
            # Remove from indices
            self.metric_indices[old_point.metric_type] = [
                p for p in self.metric_indices[old_point.metric_type]
                if p.timestamp >= cutoff_time
            ]
            
            self.experiment_metrics[old_point.experiment_id] = [
                p for p in self.experiment_metrics[old_point.experiment_id]
                if p.timestamp >= cutoff_time
            ]
        
        # Clean empty experiment entries
        empty_experiments = [
            exp_id for exp_id, points in self.experiment_metrics.items()
            if not points
        ]
        for exp_id in empty_experiments:
            del self.experiment_metrics[exp_id]
        
        self._last_cleanup = time.time()
        logger.debug(f"Cleaned up metrics older than {cutoff_time}")
    
    def get_metric_summary(self, 
                          metric_type: MetricType,
                          experiment_id: Optional[str] = None,
                          time_range: Optional[timedelta] = None) -> MetricSummary:
        """
        Get summary statistics for a metric type.
        
        Args:
            metric_type: Type of metric to summarize
            experiment_id: Optional experiment filter
            time_range: Optional time range filter
            
        Returns:
            MetricSummary: Summary statistics
        """
        # Get relevant metrics
        if experiment_id:
            metrics = [
                p for p in self.experiment_metrics.get(experiment_id, [])
                if p.metric_type == metric_type
            ]
        else:
            metrics = self.metric_indices[metric_type]
        
        # Apply time range filter
        if time_range:
            cutoff_time = datetime.now() - time_range
            metrics = [p for p in metrics if p.timestamp >= cutoff_time]
        
        summary = MetricSummary(
            metric_type=metric_type,
            count=len(metrics)
        )
        
        if not metrics:
            return summary
        
        # Calculate time bounds
        summary.first_seen = min(p.timestamp for p in metrics)
        summary.last_seen = max(p.timestamp for p in metrics)
        
        # Calculate numerical statistics for numeric values
        numeric_values = []
        for point in metrics:
            if isinstance(point.value, (int, float)):
                numeric_values.append(float(point.value))
        
        if numeric_values:
            summary.min_value = min(numeric_values)
            summary.max_value = max(numeric_values)
            summary.mean = statistics.mean(numeric_values)
            summary.median = statistics.median(numeric_values)
            
            if len(numeric_values) > 1:
                summary.std_dev = statistics.stdev(numeric_values)
            
            # Calculate percentiles
            if len(numeric_values) >= 4:
                sorted_values = sorted(numeric_values)
                summary.percentiles = {
                    25: statistics.quantiles(sorted_values, n=4)[0],
                    50: summary.median,
                    75: statistics.quantiles(sorted_values, n=4)[2],
                    90: statistics.quantiles(sorted_values, n=10)[8],
                    95: statistics.quantiles(sorted_values, n=20)[18],
                    99: statistics.quantiles(sorted_values, n=100)[98]
                }
        
        return summary
    
    def get_experiment_timeline(self, experiment_id: str) -> List[Dict[str, Any]]:
        """
        Get a timeline of events for an experiment.
        
        Args:
            experiment_id: ID of the experiment
            
        Returns:
            List of timeline events
        """
        metrics = sorted(
            self.experiment_metrics.get(experiment_id, []),
            key=lambda p: p.timestamp
        )
        
        timeline = []
        for point in metrics:
            event = {
                'timestamp': point.timestamp.isoformat(),
                'metric_type': point.metric_type.value,
                'value': point.value,
                'scenario_id': point.scenario_id,
                'metadata': point.metadata,
                'tags': point.tags
            }
            timeline.append(event)
        
        return timeline
    
    def calculate_resilience_metrics(self, 
                                   experiment_id: Optional[str] = None,
                                   time_range: Optional[timedelta] = None) -> Dict[str, float]:
        """
        Calculate key resilience metrics.
        
        Args:
            experiment_id: Optional experiment filter
            time_range: Optional time range filter
            
        Returns:
            Dict containing resilience metrics
        """
        # Get relevant metrics
        if experiment_id:
            all_metrics = self.experiment_metrics.get(experiment_id, [])
        else:
            all_metrics = list(self.metrics)
        
        # Apply time range filter
        if time_range:
            cutoff_time = datetime.now() - time_range
            all_metrics = [p for p in all_metrics if p.timestamp >= cutoff_time]
        
        # Calculate MTTR (Mean Time To Recovery)
        recovery_times = []
        failure_start = None
        
        for point in sorted(all_metrics, key=lambda p: p.timestamp):
            if point.metric_type == MetricType.SYSTEM_DEGRADATION_DETECTED:
                failure_start = point.timestamp
            elif point.metric_type == MetricType.SYSTEM_RECOVERY_DETECTED and failure_start:
                recovery_time = (point.timestamp - failure_start).total_seconds()
                recovery_times.append(recovery_time)
                failure_start = None
        
        mttr = statistics.mean(recovery_times) if recovery_times else 0
        
        # Calculate MTBF (Mean Time Between Failures)
        failure_times = [
            p.timestamp for p in all_metrics
            if p.metric_type == MetricType.SYSTEM_DEGRADATION_DETECTED
        ]
        
        if len(failure_times) > 1:
            intervals = []
            for i in range(1, len(failure_times)):
                interval = (failure_times[i] - failure_times[i-1]).total_seconds()
                intervals.append(interval)
            mtbf = statistics.mean(intervals)
        else:
            mtbf = 0
        
        # Calculate availability
        total_time = 0
        downtime = 0
        failure_start = None
        
        if all_metrics:
            sorted_metrics = sorted(all_metrics, key=lambda p: p.timestamp)
            total_time = (sorted_metrics[-1].timestamp - sorted_metrics[0].timestamp).total_seconds()
            
            for point in sorted_metrics:
                if point.metric_type == MetricType.SYSTEM_DEGRADATION_DETECTED:
                    failure_start = point.timestamp
                elif point.metric_type == MetricType.SYSTEM_RECOVERY_DETECTED and failure_start:
                    downtime += (point.timestamp - failure_start).total_seconds()
                    failure_start = None
        
        availability = ((total_time - downtime) / total_time * 100) if total_time > 0 else 100
        
        # Calculate error rate
        error_points = [
            p for p in all_metrics
            if p.metric_type == MetricType.ERROR_RATE and isinstance(p.value, (int, float))
        ]
        avg_error_rate = statistics.mean([p.value for p in error_points]) if error_points else 0
        
        # Calculate resilience score (composite metric)
        # Scale: 0-100, where 100 is perfectly resilient
        resilience_score = 0
        
        if availability > 0:
            availability_score = min(availability, 100) * 0.4  # 40% weight
            resilience_score += availability_score
        
        if mttr > 0:
            # Lower MTTR is better, normalize to 0-30 range
            mttr_score = max(0, 30 - (mttr / 60))  # 30 points for recovery under 1 minute
            resilience_score += mttr_score
        
        if avg_error_rate < 0.05:  # Less than 5% error rate
            error_score = 30 * (1 - min(avg_error_rate, 0.05) / 0.05)  # 30% weight
            resilience_score += error_score
        
        return {
            'mttr_seconds': mttr,
            'mtbf_seconds': mtbf,
            'availability_percent': availability,
            'average_error_rate': avg_error_rate,
            'resilience_score': min(resilience_score, 100),
            'recovery_events': len(recovery_times),
            'failure_events': len(failure_times)
        }
    
    def get_trend_analysis(self, 
                          metric_type: MetricType,
                          experiment_id: Optional[str] = None,
                          window_size: int = 10) -> Dict[str, Any]:
        """
        Analyze trends in metric values over time.
        
        Args:
            metric_type: Type of metric to analyze
            experiment_id: Optional experiment filter
            window_size: Size of the moving window for trend analysis
            
        Returns:
            Dict containing trend analysis
        """
        # Get relevant metrics
        if experiment_id:
            metrics = [
                p for p in self.experiment_metrics.get(experiment_id, [])
                if p.metric_type == metric_type
            ]
        else:
            metrics = self.metric_indices[metric_type]
        
        # Sort by timestamp
        metrics = sorted(metrics, key=lambda p: p.timestamp)
        
        # Extract numeric values
        values = []
        timestamps = []
        for point in metrics:
            if isinstance(point.value, (int, float)):
                values.append(float(point.value))
                timestamps.append(point.timestamp)
        
        if len(values) < window_size:
            return {
                'trend': 'insufficient_data',
                'data_points': len(values),
                'required_points': window_size
            }
        
        # Calculate moving averages
        moving_averages = []
        for i in range(window_size - 1, len(values)):
            window = values[i - window_size + 1:i + 1]
            moving_averages.append(statistics.mean(window))
        
        # Determine trend direction
        if len(moving_averages) >= 2:
            first_half = moving_averages[:len(moving_averages)//2]
            second_half = moving_averages[len(moving_averages)//2:]
            
            first_avg = statistics.mean(first_half)
            second_avg = statistics.mean(second_half)
            
            if second_avg > first_avg * 1.05:  # 5% increase threshold
                trend = 'increasing'
            elif second_avg < first_avg * 0.95:  # 5% decrease threshold
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'stable'
        
        # Calculate trend strength (slope)
        if len(moving_averages) >= 2:
            x_values = list(range(len(moving_averages)))
            
            # Simple linear regression slope
            n = len(moving_averages)
            sum_x = sum(x_values)
            sum_y = sum(moving_averages)
            sum_xy = sum(x * y for x, y in zip(x_values, moving_averages))
            sum_x_squared = sum(x * x for x in x_values)
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x)
            trend_strength = abs(slope)
        else:
            trend_strength = 0
        
        return {
            'trend': trend,
            'trend_strength': trend_strength,
            'data_points': len(values),
            'moving_average_window': window_size,
            'latest_value': values[-1] if values else None,
            'average_value': statistics.mean(values) if values else None,
            'value_range': (min(values), max(values)) if values else None,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def export_metrics(self, 
                      experiment_id: Optional[str] = None,
                      metric_types: Optional[List[MetricType]] = None,
                      format_type: str = 'json') -> str:
        """
        Export metrics in various formats.
        
        Args:
            experiment_id: Optional experiment filter
            metric_types: Optional metric type filter
            format_type: Export format ('json', 'csv')
            
        Returns:
            str: Exported metrics data
        """
        # Get relevant metrics
        if experiment_id:
            metrics = self.experiment_metrics.get(experiment_id, [])
        else:
            metrics = list(self.metrics)
        
        # Apply metric type filter
        if metric_types:
            metrics = [p for p in metrics if p.metric_type in metric_types]
        
        if format_type == 'json':
            import json
            
            export_data = []
            for point in metrics:
                export_data.append({
                    'timestamp': point.timestamp.isoformat(),
                    'metric_type': point.metric_type.value,
                    'experiment_id': point.experiment_id,
                    'scenario_id': point.scenario_id,
                    'value': point.value,
                    'metadata': point.metadata,
                    'tags': point.tags
                })
            
            return json.dumps(export_data, indent=2)
        
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'timestamp', 'metric_type', 'experiment_id', 'scenario_id',
                'value', 'metadata', 'tags'
            ])
            
            # Write data
            for point in metrics:
                writer.writerow([
                    point.timestamp.isoformat(),
                    point.metric_type.value,
                    point.experiment_id,
                    point.scenario_id or '',
                    point.value or '',
                    str(point.metadata),
                    str(point.tags)
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
    
    def get_metrics_dashboard_data(self) -> Dict[str, Any]:
        """
        Get data formatted for a metrics dashboard.
        
        Returns:
            Dict containing dashboard data
        """
        dashboard_data = {
            'summary': {
                'total_metrics': len(self.metrics),
                'active_experiments': len(self.experiment_metrics),
                'metric_types': len(self.metric_indices),
                'retention_hours': self.retention_hours,
                'last_updated': datetime.now().isoformat()
            },
            'recent_activity': [],
            'resilience_metrics': self.calculate_resilience_metrics(
                time_range=timedelta(hours=24)
            ),
            'metric_summaries': {}
        }
        
        # Recent activity (last 50 metrics)
        recent_metrics = sorted(
            list(self.metrics)[-50:], 
            key=lambda p: p.timestamp, 
            reverse=True
        )
        
        for point in recent_metrics:
            dashboard_data['recent_activity'].append({
                'timestamp': point.timestamp.isoformat(),
                'type': point.metric_type.value,
                'experiment': point.experiment_id,
                'value': point.value
            })
        
        # Metric summaries for key metrics
        key_metrics = [
            MetricType.RESPONSE_TIME,
            MetricType.ERROR_RATE,
            MetricType.AVAILABILITY,
            MetricType.RESILIENCE_SCORE
        ]
        
        for metric_type in key_metrics:
            if self.metric_indices[metric_type]:
                summary = self.get_metric_summary(
                    metric_type, 
                    time_range=timedelta(hours=24)
                )
                dashboard_data['metric_summaries'][metric_type.value] = {
                    'count': summary.count,
                    'mean': summary.mean,
                    'min': summary.min_value,
                    'max': summary.max_value,
                    'latest': self.metric_indices[metric_type][-1].value if self.metric_indices[metric_type] else None
                }
        
        return dashboard_data