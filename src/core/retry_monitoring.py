"""
Comprehensive retry monitoring and metrics collection.

This module provides:
- Real-time retry metrics collection
- Prometheus metrics integration
- Health checks and alerting
- Performance analysis and reporting
- Dashboard data preparation
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

try:
    from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class RetryEvent:
    """Single retry event record."""
    timestamp: datetime
    service_name: str
    service_type: str
    function_name: str
    attempt: int
    success: bool
    duration: float
    error_type: Optional[str] = None
    delay: Optional[float] = None
    circuit_breaker_state: Optional[str] = None
    budget_tokens: Optional[float] = None
    idempotency_hit: bool = False


@dataclass
class ServiceHealthStatus:
    """Health status for a service."""
    service_name: str
    is_healthy: bool
    success_rate: float
    failure_rate: float
    avg_response_time: float
    circuit_breaker_state: str
    retry_budget_remaining: float
    last_success: Optional[datetime]
    last_failure: Optional[datetime]
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class RetryAnalysis:
    """Analysis results for retry patterns."""
    total_attempts: int
    success_rate: float
    avg_attempts_to_success: float
    most_common_errors: List[tuple]
    retry_distribution: Dict[int, int]
    delay_effectiveness: Dict[str, float]
    circuit_breaker_activations: int
    budget_rejections: int
    time_period: str
    recommendations: List[str]


class PrometheusRetryMetrics:
    """Prometheus metrics for retry operations."""
    
    def __init__(self):
        """Initialize Prometheus metrics."""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available")
            return
        
        # Counters
        self.retry_attempts_total = Counter(
            'retry_attempts_total',
            'Total number of retry attempts',
            ['service_name', 'service_type', 'function_name', 'attempt']
        )
        
        self.retry_successes_total = Counter(
            'retry_successes_total',
            'Total number of successful retries',
            ['service_name', 'service_type', 'function_name', 'attempt']
        )
        
        self.retry_failures_total = Counter(
            'retry_failures_total',
            'Total number of failed retries',
            ['service_name', 'service_type', 'function_name', 'error_type']
        )
        
        self.circuit_breaker_state_changes = Counter(
            'circuit_breaker_state_changes_total',
            'Circuit breaker state changes',
            ['service_name', 'service_type', 'from_state', 'to_state']
        )
        
        self.budget_rejections_total = Counter(
            'retry_budget_rejections_total',
            'Total number of retry budget rejections',
            ['service_name', 'service_type']
        )
        
        self.idempotency_hits_total = Counter(
            'retry_idempotency_hits_total',
            'Total number of idempotency cache hits',
            ['service_name', 'service_type', 'function_name']
        )
        
        # Histograms
        self.retry_duration = Histogram(
            'retry_operation_duration_seconds',
            'Duration of retry operations',
            ['service_name', 'service_type', 'function_name'],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
        )
        
        self.retry_delay = Histogram(
            'retry_delay_seconds',
            'Delay between retry attempts',
            ['service_name', 'service_type', 'strategy'],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
        )
        
        # Gauges
        self.active_retries = Gauge(
            'retry_active_operations',
            'Number of currently active retry operations',
            ['service_name', 'service_type']
        )
        
        self.circuit_breaker_state = Gauge(
            'circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['service_name', 'service_type']
        )
        
        self.retry_budget_tokens = Gauge(
            'retry_budget_tokens_remaining',
            'Remaining tokens in retry budget',
            ['service_name', 'service_type']
        )
        
        self.service_health_score = Gauge(
            'service_health_score',
            'Service health score (0-1)',
            ['service_name', 'service_type']
        )
        
        # Info
        self.retry_config_info = Info(
            'retry_config',
            'Retry configuration information',
            ['service_name', 'service_type']
        )
    
    def record_retry_attempt(self, event: RetryEvent):
        """Record a retry attempt."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        labels = {
            'service_name': event.service_name,
            'service_type': event.service_type,
            'function_name': event.function_name,
            'attempt': str(event.attempt)
        }
        
        self.retry_attempts_total.labels(**labels).inc()
        
        if event.success:
            self.retry_successes_total.labels(**labels).inc()
        else:
            error_labels = {
                'service_name': event.service_name,
                'service_type': event.service_type,
                'function_name': event.function_name,
                'error_type': event.error_type or 'unknown'
            }
            self.retry_failures_total.labels(**error_labels).inc()
        
        # Record duration
        duration_labels = {
            'service_name': event.service_name,
            'service_type': event.service_type,
            'function_name': event.function_name
        }
        self.retry_duration.labels(**duration_labels).observe(event.duration)
        
        # Record delay if available
        if event.delay is not None:
            delay_labels = {
                'service_name': event.service_name,
                'service_type': event.service_type,
                'strategy': 'unknown'  # Could be enhanced to track strategy
            }
            self.retry_delay.labels(**delay_labels).observe(event.delay)
        
        # Record idempotency hit
        if event.idempotency_hit:
            idem_labels = {
                'service_name': event.service_name,
                'service_type': event.service_type,
                'function_name': event.function_name
            }
            self.idempotency_hits_total.labels(**idem_labels).inc()


class RetryMonitor:
    """Comprehensive retry monitoring system."""
    
    def __init__(self, max_events: int = 10000):
        """Initialize retry monitor."""
        self.max_events = max_events
        self.events: deque[RetryEvent] = deque(maxlen=max_events)
        self.service_stats: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.prometheus_metrics: Optional[PrometheusRetryMetrics] = None
        self.active_operations: Set[str] = set()
        self._lock = asyncio.Lock()
        
        # Health check thresholds
        self.health_thresholds = {
            'min_success_rate': 0.95,
            'max_avg_response_time': 5.0,
            'max_failure_rate': 0.05,
            'circuit_breaker_timeout': 300  # 5 minutes
        }
        
        if PROMETHEUS_AVAILABLE:
            self.prometheus_metrics = PrometheusRetryMetrics()
        
        logger.info("Retry monitor initialized")
    
    async def record_event(self, event: RetryEvent):
        """Record a retry event."""
        async with self._lock:
            self.events.append(event)
            await self._update_service_stats(event)
        
        # Record in Prometheus if available
        if self.prometheus_metrics:
            self.prometheus_metrics.record_retry_attempt(event)
        
        logger.debug(
            f"Recorded retry event: {event.service_name} attempt {event.attempt} "
            f"{'success' if event.success else 'failure'}"
        )
    
    async def _update_service_stats(self, event: RetryEvent):
        """Update service statistics."""
        service_key = f"{event.service_name}:{event.service_type}"
        
        if service_key not in self.service_stats:
            self.service_stats[service_key] = {
                'total_attempts': 0,
                'successful_attempts': 0,
                'failed_attempts': 0,
                'total_duration': 0.0,
                'error_counts': defaultdict(int),
                'attempt_distribution': defaultdict(int),
                'last_success': None,
                'last_failure': None,
                'circuit_breaker_activations': 0,
                'budget_rejections': 0,
                'idempotency_hits': 0
            }
        
        stats = self.service_stats[service_key]
        stats['total_attempts'] += 1
        stats['total_duration'] += event.duration
        stats['attempt_distribution'][event.attempt] += 1
        
        if event.success:
            stats['successful_attempts'] += 1
            stats['last_success'] = event.timestamp
        else:
            stats['failed_attempts'] += 1
            stats['last_failure'] = event.timestamp
            if event.error_type:
                stats['error_counts'][event.error_type] += 1
        
        if event.idempotency_hit:
            stats['idempotency_hits'] += 1
    
    async def start_operation(self, operation_id: str, service_name: str, service_type: str):
        """Mark the start of a retry operation."""
        async with self._lock:
            self.active_operations.add(operation_id)
        
        if self.prometheus_metrics:
            self.prometheus_metrics.active_retries.labels(
                service_name=service_name,
                service_type=service_type
            ).inc()
    
    async def end_operation(self, operation_id: str, service_name: str, service_type: str):
        """Mark the end of a retry operation."""
        async with self._lock:
            self.active_operations.discard(operation_id)
        
        if self.prometheus_metrics:
            self.prometheus_metrics.active_retries.labels(
                service_name=service_name,
                service_type=service_type
            ).dec()
    
    async def get_service_health(self, service_name: str, service_type: str) -> ServiceHealthStatus:
        """Get health status for a service."""
        service_key = f"{service_name}:{service_type}"
        
        async with self._lock:
            stats = self.service_stats.get(service_key, {})
        
        if not stats:
            return ServiceHealthStatus(
                service_name=service_name,
                is_healthy=True,
                success_rate=1.0,
                failure_rate=0.0,
                avg_response_time=0.0,
                circuit_breaker_state="closed",
                retry_budget_remaining=1.0,
                last_success=None,
                last_failure=None,
                issues=["No data available"],
                recommendations=["Monitor service after first operations"]
            )
        
        total_attempts = stats['total_attempts']
        successful_attempts = stats['successful_attempts']
        failed_attempts = stats['failed_attempts']
        
        success_rate = successful_attempts / total_attempts if total_attempts > 0 else 1.0
        failure_rate = failed_attempts / total_attempts if total_attempts > 0 else 0.0
        avg_response_time = stats['total_duration'] / total_attempts if total_attempts > 0 else 0.0
        
        # Determine health
        is_healthy = (
            success_rate >= self.health_thresholds['min_success_rate'] and
            failure_rate <= self.health_thresholds['max_failure_rate'] and
            avg_response_time <= self.health_thresholds['max_avg_response_time']
        )
        
        # Generate issues and recommendations
        issues = []
        recommendations = []
        
        if success_rate < self.health_thresholds['min_success_rate']:
            issues.append(f"Low success rate: {success_rate:.2%}")
            recommendations.append("Check service configuration and dependencies")
        
        if failure_rate > self.health_thresholds['max_failure_rate']:
            issues.append(f"High failure rate: {failure_rate:.2%}")
            recommendations.append("Investigate common error patterns")
        
        if avg_response_time > self.health_thresholds['max_avg_response_time']:
            issues.append(f"Slow response time: {avg_response_time:.2f}s")
            recommendations.append("Optimize service performance or increase timeouts")
        
        return ServiceHealthStatus(
            service_name=service_name,
            is_healthy=is_healthy,
            success_rate=success_rate,
            failure_rate=failure_rate,
            avg_response_time=avg_response_time,
            circuit_breaker_state="unknown",  # Would need integration with circuit breaker
            retry_budget_remaining=1.0,  # Would need integration with budget
            last_success=stats.get('last_success'),
            last_failure=stats.get('last_failure'),
            issues=issues,
            recommendations=recommendations
        )
    
    async def get_all_service_health(self) -> Dict[str, ServiceHealthStatus]:
        """Get health status for all services."""
        health_statuses = {}
        
        async with self._lock:
            service_keys = list(self.service_stats.keys())
        
        for service_key in service_keys:
            service_name, service_type = service_key.split(':', 1)
            health_statuses[service_key] = await self.get_service_health(
                service_name, service_type
            )
        
        return health_statuses
    
    async def analyze_retry_patterns(
        self,
        service_name: Optional[str] = None,
        time_window: timedelta = timedelta(hours=1)
    ) -> RetryAnalysis:
        """Analyze retry patterns for insights."""
        cutoff_time = datetime.now() - time_window
        
        # Filter events
        relevant_events = [
            event for event in self.events
            if event.timestamp >= cutoff_time and
            (service_name is None or event.service_name == service_name)
        ]
        
        if not relevant_events:
            return RetryAnalysis(
                total_attempts=0,
                success_rate=1.0,
                avg_attempts_to_success=0.0,
                most_common_errors=[],
                retry_distribution={},
                delay_effectiveness={},
                circuit_breaker_activations=0,
                budget_rejections=0,
                time_period=str(time_window),
                recommendations=["No data available for analysis"]
            )
        
        # Calculate metrics
        total_attempts = len(relevant_events)
        successful_attempts = sum(1 for event in relevant_events if event.success)
        success_rate = successful_attempts / total_attempts
        
        # Error analysis
        error_counts = defaultdict(int)
        for event in relevant_events:
            if not event.success and event.error_type:
                error_counts[event.error_type] += 1
        
        most_common_errors = sorted(
            error_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Retry distribution
        retry_distribution = defaultdict(int)
        for event in relevant_events:
            retry_distribution[event.attempt] += 1
        
        # Calculate average attempts to success
        success_events = [event for event in relevant_events if event.success]
        avg_attempts_to_success = (
            sum(event.attempt for event in success_events) / len(success_events)
            if success_events else 0.0
        )
        
        # Generate recommendations
        recommendations = []
        
        if success_rate < 0.9:
            recommendations.append("Consider reviewing retry policy - low success rate")
        
        if avg_attempts_to_success > 2:
            recommendations.append("High average attempts to success - optimize initial operation")
        
        if retry_distribution.get(1, 0) / total_attempts < 0.7:
            recommendations.append("Many operations require retries - check service stability")
        
        return RetryAnalysis(
            total_attempts=total_attempts,
            success_rate=success_rate,
            avg_attempts_to_success=avg_attempts_to_success,
            most_common_errors=most_common_errors,
            retry_distribution=dict(retry_distribution),
            delay_effectiveness={},  # Could be enhanced with delay analysis
            circuit_breaker_activations=0,  # Would need circuit breaker integration
            budget_rejections=0,  # Would need budget integration
            time_period=str(time_window),
            recommendations=recommendations
        )
    
    async def export_metrics(self, filepath: str):
        """Export all metrics to JSON file."""
        async with self._lock:
            stats_copy = dict(self.service_stats)
            events_data = [
                {
                    'timestamp': event.timestamp.isoformat(),
                    'service_name': event.service_name,
                    'service_type': event.service_type,
                    'function_name': event.function_name,
                    'attempt': event.attempt,
                    'success': event.success,
                    'duration': event.duration,
                    'error_type': event.error_type,
                    'delay': event.delay,
                    'idempotency_hit': event.idempotency_hit
                }
                for event in list(self.events)
            ]
        
        # Get system metrics if available
        system_metrics = {}
        if PSUTIL_AVAILABLE:
            try:
                system_metrics = {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent if hasattr(psutil, 'disk_usage') else None
                }
            except Exception as e:
                logger.warning(f"Failed to collect system metrics: {e}")
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'service_stats': stats_copy,
            'events': events_data,
            'active_operations': len(self.active_operations),
            'system_metrics': system_metrics,
            'health_thresholds': self.health_thresholds
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            logger.info(f"Exported retry metrics to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export metrics to {filepath}: {e}")
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data formatted for monitoring dashboards."""
        # Get recent events (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_events = [
            event for event in self.events
            if event.timestamp >= one_hour_ago
        ]
        
        # Calculate summary statistics
        total_attempts = len(recent_events)
        successful_attempts = sum(1 for event in recent_events if event.success)
        success_rate = successful_attempts / total_attempts if total_attempts > 0 else 1.0
        
        # Service breakdown
        service_breakdown = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        for event in recent_events:
            key = f"{event.service_name}:{event.service_type}"
            service_breakdown[key]['attempts'] += 1
            if event.success:
                service_breakdown[key]['successes'] += 1
        
        # Error analysis
        error_counts = defaultdict(int)
        for event in recent_events:
            if not event.success and event.error_type:
                error_counts[event.error_type] += 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_attempts_last_hour': total_attempts,
                'success_rate_last_hour': success_rate,
                'active_operations': len(self.active_operations),
                'services_monitored': len(self.service_stats)
            },
            'service_breakdown': dict(service_breakdown),
            'top_errors': dict(sorted(
                error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'retry_distribution': {
                str(i): len([e for e in recent_events if e.attempt == i])
                for i in range(1, 6)
            }
        }


# Global monitor instance
_retry_monitor = RetryMonitor()


def get_retry_monitor() -> RetryMonitor:
    """Get the global retry monitor instance."""
    return _retry_monitor


async def record_retry_event(
    service_name: str,
    service_type: str,
    function_name: str,
    attempt: int,
    success: bool,
    duration: float,
    error_type: Optional[str] = None,
    delay: Optional[float] = None,
    idempotency_hit: bool = False
):
    """Record a retry event using the global monitor."""
    event = RetryEvent(
        timestamp=datetime.now(),
        service_name=service_name,
        service_type=service_type,
        function_name=function_name,
        attempt=attempt,
        success=success,
        duration=duration,
        error_type=error_type,
        delay=delay,
        idempotency_hit=idempotency_hit
    )
    
    await _retry_monitor.record_event(event)


def start_prometheus_server(port: int = 8000):
    """Start Prometheus metrics server."""
    if PROMETHEUS_AVAILABLE:
        try:
            start_http_server(port)
            logger.info(f"Started Prometheus metrics server on port {port}")
        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")
    else:
        logger.warning("Prometheus client not available")


# Export public API
__all__ = [
    'RetryEvent',
    'ServiceHealthStatus',
    'RetryAnalysis',
    'RetryMonitor',
    'PrometheusRetryMetrics',
    'get_retry_monitor',
    'record_retry_event',
    'start_prometheus_server',
]