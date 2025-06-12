"""
Comprehensive monitoring and metrics module for the Claude-Optimized Deployment Engine.

This module provides:
- Prometheus metrics collection
- Health check endpoints
- Distributed tracing with OpenTelemetry
- Alert definitions and rules
- SLA tracking and reporting
- API endpoints for monitoring
"""

from .metrics import (
    MetricsCollector,
    get_metrics_collector,
    record_request,
    record_error,
    record_business_metric,
    metrics_decorator,
)
from .health import (
    HealthChecker,
    HealthStatus,
    HealthCheckResult,
    get_health_checker,
    register_health_check,
    health_check,
)
from .tracing import (
    TracingManager,
    get_tracer,
    trace_span,
    trace_async,
    init_tracing,
)
from .alerts import (
    AlertManager,
    AlertRule,
    AlertSeverity,
    get_alert_manager,
    register_alert_handler,
    log_alert_handler,
    slack_alert_handler,
)
from .sla import (
    SLATracker,
    SLAObjective,
    SLAType,
    get_sla_tracker,
    check_sla_compliance,
    add_sla_objective,
    get_sla_report,
)
from .api import (
    monitoring_router,
    health_check_middleware,
)

__all__ = [
    # Metrics
    "MetricsCollector",
    "get_metrics_collector",
    "record_request",
    "record_error",
    "record_business_metric",
    "metrics_decorator",
    # Health
    "HealthChecker",
    "HealthStatus",
    "HealthCheckResult",
    "get_health_checker",
    "register_health_check",
    "health_check",
    # Tracing
    "TracingManager",
    "get_tracer",
    "trace_span",
    "trace_async",
    "init_tracing",
    # Alerts
    "AlertManager",
    "AlertRule",
    "AlertSeverity",
    "get_alert_manager",
    "register_alert_handler",
    "log_alert_handler",
    "slack_alert_handler",
    # SLA
    "SLATracker",
    "SLAObjective",
    "SLAType",
    "get_sla_tracker",
    "check_sla_compliance",
    "add_sla_objective",
    "get_sla_report",
    # API
    "monitoring_router",
    "health_check_middleware",
]