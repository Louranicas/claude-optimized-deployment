"""
Comprehensive monitoring and metrics module for the Claude-Optimized Deployment Engine.

This module provides:
- Prometheus metrics collection
- Health check endpoints
- Distributed tracing with OpenTelemetry
- Alert definitions and rules
- SLA tracking and reporting
- SLI/SLO tracking with error budget management
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
    get_comprehensive_sla_status,
)
from .sla_alerting import (
    SLAAlertManager,
    SLAAlert,
    AlertingRule,
    get_sla_alert_manager,
)
from .sla_history import (
    SLAHistoryTracker,
    SLATrend,
    get_sla_history_tracker,
)
from .sla_dashboard import (
    SLADashboardAPI,
    get_sla_dashboard_api,
)
from .error_budget import (
    ErrorBudgetTracker,
    ErrorBudgetStatus,
    get_error_budget_tracker,
)
from .prometheus_client import (
    PrometheusClient,
    get_prometheus_client,
)
from .sla_tests import (
    run_sla_validation,
)
from .api import (
    monitoring_router,
    health_check_middleware,
)
from .sli_slo_tracking import (
    SLOTrackingSystem,
    SLICollector,
    SLOCalculator,
    ErrorBudgetManager,
    SLOAlertManager,
    SLOReporter,
    SLOGovernance,
    SLIComplianceDashboard,
    SLIType,
    SLOStatus,
    TimeWindow,
    AlertSeverity,
    SLIDefinition,
    SLOTarget,
    ErrorBudgetPolicy,
    SLOCompliance,
)
from .slo_integration import (
    PrometheusIntegration,
    GrafanaIntegration,
    SlackIntegration,
    DeploymentIntegration,
    IncidentManagementIntegration,
    SLOIntegrationOrchestrator,
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
    # SLA Core
    "SLATracker",
    "SLAObjective",
    "SLAType",
    "get_sla_tracker",
    "check_sla_compliance",
    "add_sla_objective",
    "get_sla_report",
    "get_comprehensive_sla_status",
    # SLA Alerting
    "SLAAlertManager",
    "SLAAlert",
    "AlertingRule",
    "get_sla_alert_manager",
    # SLA History
    "SLAHistoryTracker",
    "SLATrend", 
    "get_sla_history_tracker",
    # SLA Dashboard
    "SLADashboardAPI",
    "get_sla_dashboard_api",
    # Error Budget
    "ErrorBudgetTracker",
    "ErrorBudgetStatus",
    "get_error_budget_tracker",
    # Prometheus Client
    "PrometheusClient",
    "get_prometheus_client",
    # SLA Testing
    "run_sla_validation",
    # API
    "monitoring_router",
    "health_check_middleware",
    # SLI/SLO Tracking
    "SLOTrackingSystem",
    "SLICollector",
    "SLOCalculator",
    "ErrorBudgetManager",
    "SLOAlertManager",
    "SLOReporter",
    "SLOGovernance",
    "SLIComplianceDashboard",
    "SLIType",
    "SLOStatus",
    "TimeWindow",
    "AlertSeverity",
    "SLIDefinition",
    "SLOTarget",
    "ErrorBudgetPolicy",
    "SLOCompliance",
    # SLO Integrations
    "PrometheusIntegration",
    "GrafanaIntegration",
    "SlackIntegration",
    "DeploymentIntegration",
    "IncidentManagementIntegration",
    "SLOIntegrationOrchestrator",
]