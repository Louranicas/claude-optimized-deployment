"""
Circuit breaker metrics collection and monitoring integration.

Provides Prometheus metrics for circuit breaker states and health monitoring.
"""

import time
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

try:
    from prometheus_client import Counter, Gauge, Histogram, Info
    PROMETHEUS_AVAILABLE = True
except ImportError:
    # Mock Prometheus classes if not available
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)


class CircuitBreakerPrometheusMetrics:
    """
    Prometheus metrics collector for circuit breakers.
    
    Collects and exposes circuit breaker metrics for monitoring and alerting.
    """
    
    def __init__(self, registry=None):
        """Initialize Prometheus metrics."""
        self.registry = registry
        
        # Circuit breaker state gauge
        self.circuit_state = Gauge(
            'circuit_breaker_state',
            'Current state of circuit breaker (0=closed, 1=open, 2=half_open)',
            ['name', 'service_type'],
            registry=registry
        )
        
        # Request counters
        self.total_requests = Counter(
            'circuit_breaker_requests_total',
            'Total number of requests through circuit breaker',
            ['name', 'service_type', 'result'],
            registry=registry
        )
        
        # Failure counters
        self.failures = Counter(
            'circuit_breaker_failures_total',
            'Total number of failures tracked by circuit breaker',
            ['name', 'service_type', 'failure_type'],
            registry=registry
        )
        
        # State transition counter
        self.state_transitions = Counter(
            'circuit_breaker_state_transitions_total',
            'Total number of state transitions',
            ['name', 'service_type', 'from_state', 'to_state'],
            registry=registry
        )
        
        # Response time histogram
        self.response_time = Histogram(
            'circuit_breaker_response_time_seconds',
            'Response time of requests through circuit breaker',
            ['name', 'service_type'],
            registry=registry
        )
        
        # Fallback activation counter
        self.fallback_activations = Counter(
            'circuit_breaker_fallback_activations_total',
            'Total number of fallback activations',
            ['name', 'service_type'],
            registry=registry
        )
        
        # Circuit breaker configuration info
        self.config_info = Info(
            'circuit_breaker_config',
            'Circuit breaker configuration',
            ['name', 'service_type'],
            registry=registry
        )
        
        # Health score gauge
        self.health_score = Gauge(
            'circuit_breaker_health_score',
            'Health score of the circuit breaker (0.0 to 1.0)',
            ['name', 'service_type'],
            registry=registry
        )
        
        logger.info(f"Circuit breaker Prometheus metrics initialized (available: {PROMETHEUS_AVAILABLE})")
    
    def record_request(self, breaker_name: str, service_type: str, result: str):
        """Record a request through the circuit breaker."""
        if PROMETHEUS_AVAILABLE:
            self.total_requests.labels(
                name=breaker_name,
                service_type=service_type,
                result=result
            ).inc()
    
    def record_failure(self, breaker_name: str, service_type: str, failure_type: str):
        """Record a failure in the circuit breaker."""
        if PROMETHEUS_AVAILABLE:
            self.failures.labels(
                name=breaker_name,
                service_type=service_type,
                failure_type=failure_type
            ).inc()
    
    def record_state_transition(
        self, 
        breaker_name: str, 
        service_type: str, 
        from_state: str, 
        to_state: str
    ):
        """Record a state transition."""
        if PROMETHEUS_AVAILABLE:
            self.state_transitions.labels(
                name=breaker_name,
                service_type=service_type,
                from_state=from_state,
                to_state=to_state
            ).inc()
    
    def set_circuit_state(self, breaker_name: str, service_type: str, state: str):
        """Set the current circuit breaker state."""
        if PROMETHEUS_AVAILABLE:
            state_value = {
                'closed': 0,
                'open': 1,
                'half_open': 2
            }.get(state, -1)
            
            self.circuit_state.labels(
                name=breaker_name,
                service_type=service_type
            ).set(state_value)
    
    def record_response_time(self, breaker_name: str, service_type: str, duration: float):
        """Record response time for a request."""
        if PROMETHEUS_AVAILABLE:
            self.response_time.labels(
                name=breaker_name,
                service_type=service_type
            ).observe(duration)
    
    def record_fallback_activation(self, breaker_name: str, service_type: str):
        """Record a fallback activation."""
        if PROMETHEUS_AVAILABLE:
            self.fallback_activations.labels(
                name=breaker_name,
                service_type=service_type
            ).inc()
    
    def set_config_info(self, breaker_name: str, service_type: str, config: Dict[str, Any]):
        """Set circuit breaker configuration info."""
        if PROMETHEUS_AVAILABLE:
            self.config_info.labels(
                name=breaker_name,
                service_type=service_type
            ).info({
                'failure_threshold': str(config.get('failure_threshold', 0)),
                'timeout': str(config.get('timeout', 0)),
                'failure_rate_threshold': str(config.get('failure_rate_threshold', 0)),
                'minimum_calls': str(config.get('minimum_calls', 0))
            })
    
    def set_health_score(self, breaker_name: str, service_type: str, score: float):
        """Set health score for the circuit breaker."""
        if PROMETHEUS_AVAILABLE:
            self.health_score.labels(
                name=breaker_name,
                service_type=service_type
            ).set(score)
    
    def get_dashboard_config(self) -> Dict[str, Any]:
        """Generate Grafana dashboard configuration for circuit breakers."""
        return {
            "dashboard": {
                "id": None,
                "title": "Circuit Breaker Monitoring",
                "tags": ["circuit-breaker", "reliability", "monitoring"],
                "timezone": "browser",
                "refresh": "30s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "Circuit Breaker States",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "circuit_breaker_state",
                                "legendFormat": "{{name}} - {{service_type}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "mappings": [
                                    {"options": {"0": {"text": "CLOSED", "color": "green"}}},
                                    {"options": {"1": {"text": "OPEN", "color": "red"}}},
                                    {"options": {"2": {"text": "HALF_OPEN", "color": "yellow"}}}
                                ]
                            }
                        }
                    },
                    {
                        "id": 2,
                        "title": "Request Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(circuit_breaker_requests_total[5m])",
                                "legendFormat": "{{name}} - {{result}}"
                            }
                        ]
                    },
                    {
                        "id": 3,
                        "title": "Failure Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(circuit_breaker_failures_total[5m])",
                                "legendFormat": "{{name}} - {{failure_type}}"
                            }
                        ]
                    },
                    {
                        "id": 4,
                        "title": "Response Time Distribution",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(circuit_breaker_response_time_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            },
                            {
                                "expr": "histogram_quantile(0.50, rate(circuit_breaker_response_time_seconds_bucket[5m]))",
                                "legendFormat": "50th percentile"
                            }
                        ]
                    },
                    {
                        "id": 5,
                        "title": "Health Scores",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "circuit_breaker_health_score",
                                "legendFormat": "{{name}} - {{service_type}}"
                            }
                        ]
                    },
                    {
                        "id": 6,
                        "title": "State Transitions",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(circuit_breaker_state_transitions_total[5m])",
                                "legendFormat": "{{name}}: {{from_state}} -> {{to_state}}"
                            }
                        ]
                    }
                ]
            }
        }


# Global metrics instance
_metrics_instance: Optional[CircuitBreakerPrometheusMetrics] = None


def get_circuit_breaker_metrics(registry=None) -> CircuitBreakerPrometheusMetrics:
    """Get or create the global circuit breaker metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = CircuitBreakerPrometheusMetrics(registry)
    return _metrics_instance


def reset_metrics():
    """Reset global metrics instance (mainly for testing)."""
    global _metrics_instance
    _metrics_instance = None