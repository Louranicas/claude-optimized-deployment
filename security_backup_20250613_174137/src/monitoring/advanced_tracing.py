"""
Advanced OpenTelemetry tracing components for comprehensive observability.

This module provides enhanced tracing capabilities including:
- Custom sampling strategies
- Multi-exporter support with failover
- Performance analysis and SLI/SLO tracking
- Business metrics integration
- Trace correlation across services
"""

import os
import uuid
import time
import json
import logging
from typing import Dict, Optional, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

from opentelemetry import trace, context
from opentelemetry.trace import Status, StatusCode, SpanKind, Link
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.sampling import (
    Sampler, SamplingResult, Decision
)
from opentelemetry.util.types import Attributes

logger = logging.getLogger(__name__)


@dataclass
class BusinessMetrics:
    """Business-specific metrics for tracing."""
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    operation_type: Optional[str] = None
    business_value: Optional[float] = None
    customer_tier: Optional[str] = None
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_span_attributes(self) -> Dict[str, Any]:
        """Convert to span attributes."""
        attrs = {}
        
        if self.user_id:
            attrs["user.id"] = self.user_id
        if self.tenant_id:
            attrs["tenant.id"] = self.tenant_id
        if self.request_id:
            attrs["request.id"] = self.request_id
        if self.operation_type:
            attrs["operation.type"] = self.operation_type
        if self.business_value is not None:
            attrs["business.value"] = self.business_value
        if self.customer_tier:
            attrs["user.tier"] = self.customer_tier
        
        # Add feature flags
        for flag, enabled in self.feature_flags.items():
            attrs[f"feature.{flag}"] = enabled
        
        # Add custom attributes
        for key, value in self.custom_attributes.items():
            if not key.startswith("custom."):
                key = f"custom.{key}"
            attrs[key] = value
        
        return attrs


@dataclass 
class PerformanceMetrics:
    """Performance-specific metrics for tracing."""
    sli_name: str
    slo_threshold: float
    actual_value: float
    is_critical: bool = False
    percentile: Optional[float] = None
    baseline_value: Optional[float] = None
    
    @property
    def slo_compliance(self) -> bool:
        """Check if performance meets SLO."""
        return self.actual_value <= self.slo_threshold
    
    @property
    def slo_breach_severity(self) -> str:
        """Calculate SLO breach severity."""
        if self.slo_compliance:
            return "none"
        
        breach_ratio = self.actual_value / self.slo_threshold
        if breach_ratio <= 1.5:
            return "minor"
        elif breach_ratio <= 2.0:
            return "major"
        else:
            return "critical"
    
    def to_span_attributes(self) -> Dict[str, Any]:
        """Convert to span attributes."""
        return {
            "sli.name": self.sli_name,
            "slo.threshold": self.slo_threshold,
            "sli.value": self.actual_value,
            "slo.compliant": self.slo_compliance,
            "slo.breach_severity": self.slo_breach_severity,
            "performance.is_critical": self.is_critical,
        }


class CustomSampler(Sampler):
    """Advanced custom sampler with business logic."""
    
    def __init__(
        self,
        base_rate: float = 0.1,
        error_rate: float = 1.0,
        slow_request_rate: float = 1.0,
        critical_user_rate: float = 1.0,
        slow_threshold_ms: float = 1000.0,
    ):
        self.base_rate = base_rate
        self.error_rate = error_rate
        self.slow_request_rate = slow_request_rate
        self.critical_user_rate = critical_user_rate
        self.slow_threshold_ms = slow_threshold_ms
    
    def should_sample(
        self,
        parent_context: Optional[context.Context],
        trace_id: int,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Attributes = None,
        links: Optional[List[Link]] = None,
        trace_state: Optional[str] = None,
    ) -> SamplingResult:
        """Implement intelligent sampling logic."""
        
        attributes = attributes or {}
        
        # Always sample errors
        if attributes.get("error", False) or "error" in name.lower():
            return SamplingResult(
                decision=Decision.RECORD_AND_SAMPLE,
                attributes={"sampling.reason": "error_sampling"},
            )
        
        # Always sample critical users
        if attributes.get("user.tier") == "premium" or attributes.get("user.critical"):
            return SamplingResult(
                decision=Decision.RECORD_AND_SAMPLE,
                attributes={"sampling.reason": "critical_user_sampling"},
            )
        
        # Always sample slow requests
        duration_ms = attributes.get("duration_ms", 0)
        if duration_ms > self.slow_threshold_ms:
            return SamplingResult(
                decision=Decision.RECORD_AND_SAMPLE,
                attributes={"sampling.reason": "slow_request_sampling"},
            )
        
        # Sample based on trace ID for consistent sampling
        if (trace_id % 10000) < (self.base_rate * 10000):
            return SamplingResult(
                decision=Decision.RECORD_AND_SAMPLE,
                attributes={"sampling.reason": "base_rate_sampling"},
            )
        
        return SamplingResult(decision=Decision.NOT_RECORD)
    
    def get_description(self) -> str:
        return f"CustomSampler(base_rate={self.base_rate})"


class MultiExporter(SpanExporter):
    """Multi-exporter with failover support."""
    
    def __init__(self, exporters: List[Tuple[str, SpanExporter]], max_retries: int = 3):
        self.exporters = exporters
        self.max_retries = max_retries
        self.export_stats = defaultdict(lambda: {"success": 0, "failure": 0})
        self.logger = logging.getLogger(__name__)
    
    def export(self, spans: List[ReadableSpan]) -> SpanExportResult:
        """Export spans to multiple backends with failover."""
        results = []
        
        for name, exporter in self.exporters:
            try:
                result = exporter.export(spans)
                results.append((name, result))
                
                if result == SpanExportResult.SUCCESS:
                    self.export_stats[name]["success"] += len(spans)
                else:
                    self.export_stats[name]["failure"] += len(spans)
                    
            except Exception as e:
                self.logger.error(f"Export to {name} failed: {e}")
                self.export_stats[name]["failure"] += len(spans)
                results.append((name, SpanExportResult.FAILURE))
        
        # Return success if at least one exporter succeeded
        if any(result == SpanExportResult.SUCCESS for _, result in results):
            return SpanExportResult.SUCCESS
        
        return SpanExportResult.FAILURE
    
    def shutdown(self) -> None:
        """Shutdown all exporters."""
        for name, exporter in self.exporters:
            try:
                exporter.shutdown()
            except Exception as e:
                self.logger.error(f"Failed to shutdown exporter {name}: {e}")
    
    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush all exporters."""
        results = []
        for name, exporter in self.exporters:
            try:
                result = exporter.force_flush(timeout_millis)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to flush exporter {name}: {e}")
                results.append(False)
        
        return any(results)
    
    def get_export_stats(self) -> Dict[str, Dict[str, int]]:
        """Get export statistics."""
        return dict(self.export_stats)


class TraceAnalyzer:
    """Analyze traces for performance and business insights."""
    
    def __init__(self):
        self.performance_data = defaultdict(list)
        self.error_data = defaultdict(list)
        self.business_data = defaultdict(list)
        self.slo_violations = []
        self.logger = logging.getLogger(__name__)
    
    def analyze_span(self, span: trace.Span):
        """Analyze a single span for insights."""
        if not span.is_recording():
            return
        
        span_context = span.get_span_context()
        attributes = getattr(span, 'attributes', {})
        
        # Extract performance metrics
        duration_ms = attributes.get("duration_ms")
        if duration_ms:
            operation = attributes.get("operation.name", span.name)
            self.performance_data[operation].append(duration_ms)
            
            # Check SLO violations
            slo_threshold = attributes.get("slo.threshold_ms")
            if slo_threshold and duration_ms > slo_threshold:
                self.slo_violations.append({
                    "trace_id": format(span_context.trace_id, "032x"),
                    "span_id": format(span_context.span_id, "016x"),
                    "operation": operation,
                    "duration_ms": duration_ms,
                    "slo_threshold_ms": slo_threshold,
                    "breach_ratio": duration_ms / slo_threshold,
                    "timestamp": datetime.utcnow().isoformat(),
                })
        
        # Extract error data
        if attributes.get("error", False):
            error_type = attributes.get("error.type", "unknown")
            self.error_data[error_type].append({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x"),
                "error_message": attributes.get("error.message", ""),
                "timestamp": datetime.utcnow().isoformat(),
            })
        
        # Extract business metrics
        user_id = attributes.get("user.id")
        if user_id:
            self.business_data["user_activity"].append({
                "user_id": user_id,
                "operation": attributes.get("operation.name", span.name),
                "tenant_id": attributes.get("tenant.id"),
                "customer_tier": attributes.get("user.tier"),
                "timestamp": datetime.utcnow().isoformat(),
            })
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance analysis summary."""
        summary = {}
        
        for operation, durations in self.performance_data.items():
            if durations:
                durations.sort()
                n = len(durations)
                
                summary[operation] = {
                    "count": n,
                    "avg_ms": sum(durations) / n,
                    "min_ms": durations[0],
                    "max_ms": durations[-1],
                    "p50_ms": durations[n // 2],
                    "p95_ms": durations[int(n * 0.95)] if n > 20 else durations[-1],
                    "p99_ms": durations[int(n * 0.99)] if n > 100 else durations[-1],
                }
        
        return summary
    
    def get_slo_violations(self) -> List[Dict[str, Any]]:
        """Get SLO violations."""
        return self.slo_violations.copy()
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error analysis summary."""
        return {
            error_type: {
                "count": len(errors),
                "recent_errors": errors[-5:] if len(errors) > 5 else errors,
            }
            for error_type, errors in self.error_data.items()
        }


class PerformanceTracker:
    """Track performance metrics and SLI/SLO compliance."""
    
    def __init__(self):
        self.slis = {}
        self.slos = {}
        self.measurements = defaultdict(list)
        self.logger = logging.getLogger(__name__)
    
    def define_sli(self, name: str, description: str, measurement_type: str = "latency"):
        """Define a Service Level Indicator."""
        self.slis[name] = {
            "description": description,
            "type": measurement_type,
            "created_at": datetime.utcnow().isoformat(),
        }
    
    def define_slo(self, sli_name: str, threshold: float, target_percentage: float = 95.0):
        """Define a Service Level Objective."""
        if sli_name not in self.slis:
            raise ValueError(f"SLI {sli_name} not defined")
        
        self.slos[sli_name] = {
            "threshold": threshold,
            "target_percentage": target_percentage,
            "created_at": datetime.utcnow().isoformat(),
        }
    
    def record_measurement(self, sli_name: str, value: float, attributes: Optional[Dict] = None):
        """Record a measurement for an SLI."""
        measurement = {
            "value": value,
            "timestamp": datetime.utcnow().isoformat(),
            "attributes": attributes or {},
        }
        
        self.measurements[sli_name].append(measurement)
        
        # Check SLO compliance
        if sli_name in self.slos:
            slo = self.slos[sli_name]
            if value > slo["threshold"]:
                self.logger.warning(
                    f"SLO violation for {sli_name}: {value} > {slo['threshold']}"
                )
    
    def get_slo_compliance(self, sli_name: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """Calculate SLO compliance over a time window."""
        if sli_name not in self.slos:
            return {"error": f"SLO not defined for {sli_name}"}
        
        slo = self.slos[sli_name]
        measurements = self.measurements[sli_name]
        
        # Filter measurements by time window
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        recent_measurements = [
            m for m in measurements
            if datetime.fromisoformat(m["timestamp"]) >= cutoff_time
        ]
        
        if not recent_measurements:
            return {"error": "No measurements in time window"}
        
        # Calculate compliance
        compliant_count = sum(
            1 for m in recent_measurements
            if m["value"] <= slo["threshold"]
        )
        
        total_count = len(recent_measurements)
        compliance_percentage = (compliant_count / total_count) * 100
        
        return {
            "sli_name": sli_name,
            "slo_threshold": slo["threshold"],
            "target_percentage": slo["target_percentage"],
            "actual_percentage": compliance_percentage,
            "compliant": compliance_percentage >= slo["target_percentage"],
            "total_measurements": total_count,
            "compliant_measurements": compliant_count,
            "time_window_hours": time_window_hours,
        }


# Global correlation ID storage
_correlation_context = context.create_key("correlation_id")


def create_correlation_id() -> str:
    """Create a new correlation ID."""
    return str(uuid.uuid4())


def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID from context."""
    return context.get_value(_correlation_context)


def set_correlation_id(correlation_id: str) -> context.Token:
    """Set correlation ID in context."""
    return context.attach(context.set_value(_correlation_context, correlation_id))


class AlertManager:
    """Manage trace-based alerts."""
    
    def __init__(self):
        self.alert_rules = []
        self.alert_history = []
        self.logger = logging.getLogger(__name__)
    
    def add_alert_rule(
        self,
        name: str,
        condition: str,
        threshold: float,
        severity: str = "warning",
        description: str = "",
    ):
        """Add a new alert rule."""
        rule = {
            "name": name,
            "condition": condition,
            "threshold": threshold,
            "severity": severity,
            "description": description,
            "created_at": datetime.utcnow().isoformat(),
            "enabled": True,
        }
        self.alert_rules.append(rule)
    
    def evaluate_alerts(self, performance_summary: Dict[str, Any]):
        """Evaluate alert rules against performance data."""
        alerts = []
        
        for rule in self.alert_rules:
            if not rule["enabled"]:
                continue
            
            try:
                if self._evaluate_condition(rule, performance_summary):
                    alert = {
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "threshold": rule["threshold"],
                        "timestamp": datetime.utcnow().isoformat(),
                        "performance_data": performance_summary,
                    }
                    alerts.append(alert)
                    self.alert_history.append(alert)
                    self.logger.warning(f"Alert triggered: {rule['name']}")
            
            except Exception as e:
                self.logger.error(f"Error evaluating alert rule {rule['name']}: {e}")
        
        return alerts
    
    def _evaluate_condition(self, rule: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Evaluate a single alert condition."""
        condition = rule["condition"]
        threshold = rule["threshold"]
        
        if condition == "avg_latency_ms":
            for operation_data in data.values():
                if operation_data.get("avg_ms", 0) > threshold:
                    return True
        
        elif condition == "p95_latency_ms":
            for operation_data in data.values():
                if operation_data.get("p95_ms", 0) > threshold:
                    return True
        
        elif condition == "error_rate":
            # This would need error data from the analyzer
            pass
        
        return False
    
    def get_active_alerts(self, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """Get alerts from the specified time window."""
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        return [
            alert for alert in self.alert_history
            if datetime.fromisoformat(alert["timestamp"]) >= cutoff_time
        ]