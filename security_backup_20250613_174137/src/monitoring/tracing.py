"""
Comprehensive OpenTelemetry distributed tracing implementation.

Provides:
- Advanced span creation and management with business context
- Cross-service context propagation with correlation IDs
- Intelligent trace sampling strategies
- Multi-exporter support (Jaeger, Zipkin, OTLP) with failover
- Automatic instrumentation for web frameworks and databases
- Performance trace analysis and SLI/SLO tracking
- Trace-based alerting and monitoring
- Custom business metrics and attributes
"""

import os
import functools
import asyncio
import uuid
import time
import json
from typing import Dict, Optional, Any, Callable, Union, List, Tuple
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import logging

from opentelemetry import trace, context, baggage
from opentelemetry.trace import Status, StatusCode, SpanKind, Link
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.trace import TracerProvider, SpanProcessor, ReadableSpan
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)

__all__ = [
    "TracingManager",
    "AdvancedTracingManager",
    "TraceAnalyzer",
    "CustomSampler",
    "MultiExporter",
    "get_tracer",
    "init_tracing",
    "trace_span",
    "trace_async",
    "trace_performance",
    "inject_trace_context",
    "extract_trace_context",
    "add_span_event",
    "set_span_attribute",
    "set_span_status",
    "record_span_exception",
    "create_correlation_id",
    "get_correlation_id",
    "trace_with_correlation",
    "BusinessMetrics",
    "PerformanceTracker",
]
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.zipkin.json import ZipkinExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.sdk.trace.sampling import (
    TraceIdRatioBased,
    ALWAYS_ON,
    ALWAYS_OFF,
    ParentBased,
    Sampler,
    SamplingResult,
    Decision,
)
from opentelemetry.util.types import Attributes

from src.core.error_handler import (
    handle_errors, async_handle_errors, log_error,
    ServiceUnavailableError, ExternalServiceError, ConfigurationError
)

# Import advanced tracing components
from .advanced_tracing import (
    BusinessMetrics, PerformanceMetrics, CustomSampler, MultiExporter,
    TraceAnalyzer, PerformanceTracker, AlertManager,
    create_correlation_id, get_correlation_id, set_correlation_id
)


class TracingManager:
    """Manages distributed tracing for the application."""
    
    def __init__(
        self,
        service_name: str = "claude-deployment-engine",
        environment: Optional[str] = None,
        sample_rate: float = 1.0,
        exporter_type: str = "jaeger",
        endpoint: Optional[str] = None,
    ):
        self.service_name = service_name
        self.environment = environment or os.getenv("ENVIRONMENT", "development")
        self.sample_rate = sample_rate
        
        # Set up resource
        self.resource = Resource.create({
            "service.name": service_name,
            "service.version": os.getenv("APP_VERSION", "unknown"),
            "deployment.environment": self.environment,
            "telemetry.sdk.language": "python",
            "host.name": os.getenv("HOSTNAME", "unknown"),
        })
        
        # Set up tracer provider
        self.tracer_provider = TracerProvider(
            resource=self.resource,
            sampler=self._create_sampler(sample_rate),
        )
        
        # Set up exporter
        self.exporter = self._create_exporter(exporter_type, endpoint)
        self.span_processor = BatchSpanProcessor(self.exporter)
        self.tracer_provider.add_span_processor(self.span_processor)
        
        # Set as global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        
        # Get tracer
        self.tracer = trace.get_tracer(
            instrumenting_module_name=__name__,
            tracer_provider=self.tracer_provider,
        )
        
        # Auto-instrument common libraries
        self._setup_auto_instrumentation()
    
    def _create_sampler(self, sample_rate: float):
        """Create appropriate sampler based on rate."""
        if sample_rate >= 1.0:
            return ALWAYS_ON
        elif sample_rate <= 0.0:
            return ALWAYS_OFF
        else:
            return ParentBased(root=TraceIdRatioBased(sample_rate))
    
    def _create_exporter(self, exporter_type: str, endpoint: Optional[str]) -> SpanExporter:
        """Create span exporter based on type."""
        if exporter_type == "console":
            return ConsoleSpanExporter()
        elif exporter_type == "jaeger":
            endpoint = endpoint or os.getenv("JAEGER_ENDPOINT", "localhost:6831")
            host, port = endpoint.split(":")
            return JaegerExporter(
                agent_host_name=host,
                agent_port=int(port),
                udp_split_oversized_batches=True,
            )
        elif exporter_type == "zipkin":
            endpoint = endpoint or os.getenv("ZIPKIN_ENDPOINT", "http://localhost:9411/api/v2/spans")
            return ZipkinExporter(endpoint=endpoint)
        elif exporter_type == "otlp":
            endpoint = endpoint or os.getenv("OTLP_ENDPOINT", "localhost:4317")
            return OTLPSpanExporter(
                endpoint=endpoint,
                insecure=True,  # Use secure=False for development
            )
        elif exporter_type == "multi":
            # Create multiple exporters with failover
            exporters = []
            
            # Add Jaeger
            jaeger_endpoint = os.getenv("JAEGER_ENDPOINT", "localhost:6831")
            if jaeger_endpoint:
                try:
                    host, port = jaeger_endpoint.split(":")
                    jaeger_exporter = JaegerExporter(
                        agent_host_name=host,
                        agent_port=int(port),
                        udp_split_oversized_batches=True,
                    )
                    exporters.append(("jaeger", jaeger_exporter))
                except Exception as e:
                    logger.warning(f"Failed to create Jaeger exporter: {e}")
            
            # Add Zipkin
            zipkin_endpoint = os.getenv("ZIPKIN_ENDPOINT")
            if zipkin_endpoint:
                try:
                    zipkin_exporter = ZipkinExporter(endpoint=zipkin_endpoint)
                    exporters.append(("zipkin", zipkin_exporter))
                except Exception as e:
                    logger.warning(f"Failed to create Zipkin exporter: {e}")
            
            # Add OTLP
            otlp_endpoint = os.getenv("OTLP_ENDPOINT")
            if otlp_endpoint:
                try:
                    otlp_exporter = OTLPSpanExporter(
                        endpoint=otlp_endpoint,
                        insecure=True,
                    )
                    exporters.append(("otlp", otlp_exporter))
                except Exception as e:
                    logger.warning(f"Failed to create OTLP exporter: {e}")
            
            if exporters:
                return MultiExporter(exporters)
            else:
                logger.warning("No exporters configured, falling back to console")
                return ConsoleSpanExporter()
        else:
            # Default to console
            return ConsoleSpanExporter()
    
    def _setup_auto_instrumentation(self):
        """Set up automatic instrumentation for common libraries."""
        try:
            # HTTP clients
            RequestsInstrumentor().instrument()
            AioHttpClientInstrumentor().instrument()
            
            # Web frameworks (will only instrument if installed)
            try:
                FastAPIInstrumentor().instrument()
            except ImportError as e:
                logger.debug(f"FastAPI instrumentation not available: {e}")
            except Exception as e:
                logger.warning(f"Failed to instrument FastAPI: {e}")
            
            # Databases
            try:
                SQLAlchemyInstrumentor().instrument()
            except ImportError as e:
                logger.debug(f"SQLAlchemy instrumentation not available: {e}")
            except Exception as e:
                logger.warning(f"Failed to instrument SQLAlchemy: {e}")
            
            try:
                RedisInstrumentor().instrument()
            except ImportError as e:
                logger.debug(f"Redis instrumentation not available: {e}")
            except Exception as e:
                logger.warning(f"Failed to instrument Redis: {e}")
            
            try:
                Psycopg2Instrumentor().instrument()
            except ImportError as e:
                logger.debug(f"Psycopg2 instrumentation not available: {e}")
            except Exception as e:
                logger.warning(f"Failed to instrument Psycopg2: {e}")
        except Exception:
            # Silently fail auto-instrumentation
            pass
    
    def get_tracer(self, name: Optional[str] = None) -> trace.Tracer:
        """Get a tracer instance."""
        if name:
            return trace.get_tracer(name, tracer_provider=self.tracer_provider)
        return self.tracer
    
    @contextmanager
    def span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        """Create a span context manager."""
        with self.tracer.start_as_current_span(
            name,
            kind=kind,
            attributes=attributes or {},
        ) as span:
            try:
                yield span
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
    
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> trace.Span:
        """Start a new span."""
        return self.tracer.start_span(
            name,
            kind=kind,
            attributes=attributes or {},
        )
    
    def inject_context(self, carrier: Dict[str, str]):
        """Inject trace context into carrier for propagation."""
        inject(carrier)
    
    def extract_context(self, carrier: Dict[str, str]):
        """Extract trace context from carrier."""
        return extract(carrier)
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to the current span."""
        span = trace.get_current_span()
        if span:
            span.add_event(name, attributes=attributes or {})
    
    def set_attribute(self, key: str, value: Any):
        """Set an attribute on the current span."""
        span = trace.get_current_span()
        if span:
            span.set_attribute(key, value)
    
    def set_status(self, status: Union[Status, StatusCode], description: Optional[str] = None):
        """Set status on the current span."""
        span = trace.get_current_span()
        if span:
            if isinstance(status, StatusCode):
                status = Status(status, description or "")
            span.set_status(status)
    
    def record_exception(self, exception: Exception, escaped: bool = True):
        """Record an exception on the current span."""
        span = trace.get_current_span()
        if span:
            span.record_exception(exception, escaped=escaped)
    
    def shutdown(self):
        """Shutdown the tracing system."""
        self.tracer_provider.shutdown()


class AdvancedTracingManager(TracingManager):
    """Advanced tracing manager with comprehensive observability features."""
    
    def __init__(
        self,
        service_name: str = "claude-deployment-engine",
        environment: Optional[str] = None,
        sample_rate: float = 0.1,
        exporter_type: str = "multi",
        endpoint: Optional[str] = None,
        enable_custom_sampling: bool = True,
        enable_performance_tracking: bool = True,
        enable_alerting: bool = True,
    ):
        # Initialize performance tracker and analyzer
        self.performance_tracker = PerformanceTracker() if enable_performance_tracking else None
        self.trace_analyzer = TraceAnalyzer()
        self.alert_manager = AlertManager() if enable_alerting else None
        
        # Set up custom sampler if enabled
        if enable_custom_sampling:
            custom_sampler = CustomSampler(
                base_rate=sample_rate,
                error_rate=1.0,
                slow_request_rate=1.0,
                critical_user_rate=1.0,
                slow_threshold_ms=float(os.getenv("TRACE_SLOW_THRESHOLD_MS", "1000")),
            )
            # Override the sample_rate parameter for parent class
            sample_rate = 1.0  # Let custom sampler handle sampling
        
        # Initialize parent with custom sampler
        super().__init__(
            service_name=service_name,
            environment=environment,
            sample_rate=sample_rate,
            exporter_type=exporter_type,
            endpoint=endpoint,
        )
        
        # Replace sampler if custom sampling is enabled
        if enable_custom_sampling:
            self.tracer_provider._sampler = custom_sampler
        
        # Set up default SLIs and SLOs
        self._setup_default_slos()
        
        # Set up default alert rules
        self._setup_default_alerts()
    
    def _setup_default_slos(self):
        """Set up default SLI/SLO definitions."""
        if not self.performance_tracker:
            return
        
        # Define common SLIs
        self.performance_tracker.define_sli(
            "api_latency", 
            "API request latency in milliseconds", 
            "latency"
        )
        self.performance_tracker.define_sli(
            "database_latency", 
            "Database query latency in milliseconds", 
            "latency"
        )
        self.performance_tracker.define_sli(
            "external_service_latency", 
            "External service call latency in milliseconds", 
            "latency"
        )
        
        # Define SLOs
        self.performance_tracker.define_slo("api_latency", 500.0, 95.0)  # 95% < 500ms
        self.performance_tracker.define_slo("database_latency", 100.0, 99.0)  # 99% < 100ms
        self.performance_tracker.define_slo("external_service_latency", 2000.0, 90.0)  # 90% < 2s
    
    def _setup_default_alerts(self):
        """Set up default alert rules."""
        if not self.alert_manager:
            return
        
        # High latency alerts
        self.alert_manager.add_alert_rule(
            "high_avg_latency",
            "avg_latency_ms",
            1000.0,
            "warning",
            "Average latency exceeded 1 second"
        )
        
        self.alert_manager.add_alert_rule(
            "critical_p95_latency",
            "p95_latency_ms",
            2000.0,
            "critical",
            "95th percentile latency exceeded 2 seconds"
        )
    
    @contextmanager
    def enhanced_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        business_metrics: Optional[BusinessMetrics] = None,
        performance_metrics: Optional[PerformanceMetrics] = None,
        auto_record_performance: bool = True,
    ):
        """Create an enhanced span with business and performance context."""
        
        # Prepare span attributes
        attributes = {}
        
        # Add business metrics
        if business_metrics:
            attributes.update(business_metrics.to_span_attributes())
        
        # Add performance metrics
        if performance_metrics:
            attributes.update(performance_metrics.to_span_attributes())
        
        # Add correlation ID
        correlation_id = get_correlation_id()
        if correlation_id:
            attributes["correlation.id"] = correlation_id
        
        # Record start time for performance tracking
        start_time = time.time()
        
        with self.tracer.start_as_current_span(
            name,
            kind=kind,
            attributes=attributes,
        ) as span:
            try:
                yield span
                
                # Record performance data
                if auto_record_performance:
                    duration_ms = (time.time() - start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)
                    
                    # Record to performance tracker
                    if self.performance_tracker:
                        operation_type = business_metrics.operation_type if business_metrics else "general"
                        if operation_type == "api":
                            self.performance_tracker.record_measurement("api_latency", duration_ms)
                        elif operation_type == "database":
                            self.performance_tracker.record_measurement("database_latency", duration_ms)
                        elif operation_type == "external":
                            self.performance_tracker.record_measurement("external_service_latency", duration_ms)
                
                span.set_status(Status(StatusCode.OK))
                
            except Exception as e:
                # Record error information
                span.set_attribute("error", True)
                span.set_attribute("error.type", type(e).__name__)
                span.set_attribute("error.message", str(e))
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                
                # Analyze span for insights
                self.trace_analyzer.analyze_span(span)
                
                raise
            finally:
                # Always analyze span
                self.trace_analyzer.analyze_span(span)
    
    def create_business_span(
        self,
        name: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        **kwargs
    ):
        """Create a span with business context."""
        business_metrics = BusinessMetrics(
            user_id=user_id,
            tenant_id=tenant_id,
            operation_type=operation_type,
            request_id=get_correlation_id(),
            **kwargs
        )
        
        return self.enhanced_span(
            name,
            business_metrics=business_metrics,
        )
    
    def create_performance_span(
        self,
        name: str,
        sli_name: str,
        slo_threshold: float,
        **kwargs
    ):
        """Create a span with performance tracking."""
        performance_metrics = PerformanceMetrics(
            sli_name=sli_name,
            slo_threshold=slo_threshold,
            actual_value=0.0,  # Will be set during execution
            **kwargs
        )
        
        return self.enhanced_span(
            name,
            performance_metrics=performance_metrics,
        )
    
    def get_performance_insights(self) -> Dict[str, Any]:
        """Get comprehensive performance insights."""
        insights = {
            "performance_summary": self.trace_analyzer.get_performance_summary(),
            "error_summary": self.trace_analyzer.get_error_summary(),
            "slo_violations": self.trace_analyzer.get_slo_violations(),
        }
        
        # Add SLO compliance data
        if self.performance_tracker:
            slo_compliance = {}
            for sli_name in ["api_latency", "database_latency", "external_service_latency"]:
                try:
                    compliance = self.performance_tracker.get_slo_compliance(sli_name)
                    slo_compliance[sli_name] = compliance
                except Exception as e:
                    logger.warning(f"Failed to get SLO compliance for {sli_name}: {e}")
            
            insights["slo_compliance"] = slo_compliance
        
        # Add active alerts
        if self.alert_manager:
            active_alerts = self.alert_manager.get_active_alerts()
            insights["active_alerts"] = active_alerts
            
            # Evaluate new alerts
            performance_summary = insights["performance_summary"]
            new_alerts = self.alert_manager.evaluate_alerts(performance_summary)
            insights["new_alerts"] = new_alerts
        
        return insights
    
    def export_traces_analysis(self, filepath: str):
        """Export trace analysis to file."""
        insights = self.get_performance_insights()
        
        with open(filepath, 'w') as f:
            json.dump(insights, f, indent=2, default=str)
        
        logger.info(f"Trace analysis exported to {filepath}")
    
    def get_trace_health_status(self) -> Dict[str, Any]:
        """Get overall trace health status."""
        insights = self.get_performance_insights()
        
        # Calculate health scores
        health_score = 100.0
        issues = []
        
        # Check SLO compliance
        slo_compliance = insights.get("slo_compliance", {})
        for sli_name, compliance in slo_compliance.items():
            if isinstance(compliance, dict) and not compliance.get("compliant", True):
                health_score -= 20
                issues.append(f"SLO violation: {sli_name}")
        
        # Check for active alerts
        active_alerts = insights.get("active_alerts", [])
        critical_alerts = [a for a in active_alerts if a.get("severity") == "critical"]
        warning_alerts = [a for a in active_alerts if a.get("severity") == "warning"]
        
        health_score -= len(critical_alerts) * 15
        health_score -= len(warning_alerts) * 5
        
        # Determine status
        if health_score >= 90:
            status = "healthy"
        elif health_score >= 70:
            status = "warning"
        else:
            status = "critical"
        
        return {
            "status": status,
            "health_score": max(0, health_score),
            "issues": issues,
            "active_alerts_count": len(active_alerts),
            "critical_alerts_count": len(critical_alerts),
            "timestamp": datetime.utcnow().isoformat(),
        }


# Global tracing manager instance
_tracing_manager: Optional[TracingManager] = None


def get_tracer(name: Optional[str] = None) -> trace.Tracer:
    """Get a tracer instance."""
    global _tracing_manager
    if _tracing_manager is None:
        _tracing_manager = TracingManager()
    return _tracing_manager.get_tracer(name)


def init_tracing(
    service_name: str = "claude-deployment-engine",
    environment: Optional[str] = None,
    sample_rate: float = 1.0,
    exporter_type: str = "jaeger",
    endpoint: Optional[str] = None,
    use_advanced: bool = True,
    config_file: Optional[str] = None,
) -> Union[TracingManager, AdvancedTracingManager]:
    """Initialize the global tracing manager."""
    global _tracing_manager
    
    if use_advanced:
        _tracing_manager = AdvancedTracingManager(
            service_name=service_name,
            environment=environment,
            sample_rate=sample_rate,
            exporter_type=exporter_type,
            endpoint=endpoint,
        )
    else:
        _tracing_manager = TracingManager(
            service_name=service_name,
            environment=environment,
            sample_rate=sample_rate,
            exporter_type=exporter_type,
            endpoint=endpoint,
        )
    
    # Load configuration if provided
    if config_file:
        try:
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Apply configuration to tracing manager
            _apply_config(_tracing_manager, config)
            logger.info(f"Applied tracing configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Failed to load tracing config from {config_file}: {e}")
    
    return _tracing_manager


def _apply_config(tracing_manager, config: Dict[str, Any]):
    """Apply configuration to tracing manager."""
    if not isinstance(tracing_manager, AdvancedTracingManager):
        return
    
    tracing_config = config.get("tracing", {})
    
    # Apply SLO configuration
    slos_config = tracing_config.get("slos", {})
    if tracing_manager.performance_tracker:
        for sli_name, slo_config in slos_config.items():
            try:
                # Define SLI
                tracing_manager.performance_tracker.define_sli(
                    sli_name,
                    slo_config.get("description", ""),
                    slo_config.get("measurement_type", "latency")
                )
                
                # Define SLO
                if "threshold_ms" in slo_config:
                    threshold = slo_config["threshold_ms"]
                elif "threshold" in slo_config:
                    threshold = slo_config["threshold"]
                else:
                    continue
                
                tracing_manager.performance_tracker.define_slo(
                    sli_name,
                    threshold,
                    slo_config.get("target_percentage", 95.0)
                )
            except Exception as e:
                logger.warning(f"Failed to configure SLO {sli_name}: {e}")
    
    # Apply alert configuration
    alerts_config = tracing_config.get("alerts", {})
    if alerts_config.get("enabled") and tracing_manager.alert_manager:
        for rule in alerts_config.get("rules", []):
            try:
                tracing_manager.alert_manager.add_alert_rule(
                    rule["name"],
                    rule["condition"],
                    rule["threshold"],
                    rule.get("severity", "warning"),
                    rule.get("description", "")
                )
            except Exception as e:
                logger.warning(f"Failed to configure alert rule {rule.get('name')}: {e}")


def init_comprehensive_tracing(
    app=None,
    engine=None,
    config_file: Optional[str] = None,
    **kwargs
) -> AdvancedTracingManager:
    """Initialize comprehensive tracing with auto-instrumentation."""
    from .enhanced_instrumentation import setup_enhanced_instrumentation
    
    # Default config file path
    if config_file is None:
        config_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config", "tracing_config.yaml"
        )
    
    # Load configuration
    config = {}
    if os.path.exists(config_file):
        try:
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")
    
    tracing_config = config.get("tracing", {})
    service_config = tracing_config.get("service", {})
    sampling_config = tracing_config.get("sampling", {})
    exporters_config = tracing_config.get("exporters", {})
    
    # Initialize advanced tracing manager
    tracing_manager = AdvancedTracingManager(
        service_name=service_config.get("name", "claude-deployment-engine"),
        environment=service_config.get("environment", os.getenv("ENVIRONMENT", "development")),
        sample_rate=sampling_config.get("base_rate", 0.1),
        exporter_type=exporters_config.get("primary", "multi"),
        **kwargs
    )
    
    # Apply full configuration
    _apply_config(tracing_manager, config)
    
    # Set up enhanced instrumentation
    instrumentation_config = tracing_config.get("instrumentation", {})
    if instrumentation_config.get("auto_instrument", {}).get("enabled", True):
        custom_attributes = instrumentation_config.get("custom_attributes", {})
        performance_thresholds = instrumentation_config.get("performance_thresholds", {})
        
        setup_enhanced_instrumentation(
            app=app,
            engine=engine,
            custom_attributes=custom_attributes,
            performance_thresholds=performance_thresholds,
        )
    
    # Set as global manager
    global _tracing_manager
    _tracing_manager = tracing_manager
    
    logger.info("Comprehensive tracing initialization completed")
    return tracing_manager


# Decorators for tracing
def trace_span(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
):
    """Decorator to trace a function execution."""
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(
                span_name,
                kind=kind,
                attributes=attributes or {},
            ) as span:
                try:
                    # Add function arguments as span attributes
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                    
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        return wrapper
    return decorator


def trace_async(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None,
):
    """Decorator to trace an async function execution."""
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(
                span_name,
                kind=kind,
                attributes=attributes or {},
            ) as span:
                try:
                    # Add function arguments as span attributes
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                    
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        return wrapper
    return decorator


# Context propagation helpers
def inject_trace_context(headers: Dict[str, str]):
    """Inject trace context into HTTP headers."""
    inject(headers)


def extract_trace_context(headers: Dict[str, str]):
    """Extract trace context from HTTP headers."""
    return extract(headers)


# Span helpers
def add_span_event(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Add an event to the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.add_event(name, attributes=attributes or {})


def set_span_attribute(key: str, value: Any):
    """Set an attribute on the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_attribute(key, value)


def set_span_status(code: StatusCode, description: Optional[str] = None):
    """Set status on the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_status(Status(code, description or ""))


def record_span_exception(exception: Exception, escaped: bool = True):
    """Record an exception on the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.record_exception(exception, escaped=escaped)


# Enhanced decorators with business and performance context
def trace_performance(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    sli_name: Optional[str] = None,
    slo_threshold: Optional[float] = None,
    operation_type: str = "general",
    auto_correlation: bool = True,
):
    """Decorator to trace function with performance metrics."""
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create correlation ID if auto_correlation is enabled
            correlation_token = None
            if auto_correlation and not get_correlation_id():
                correlation_id = create_correlation_id()
                correlation_token = set_correlation_id(correlation_id)
            
            try:
                business_metrics = BusinessMetrics(
                    operation_type=operation_type,
                    request_id=get_correlation_id(),
                )
                
                performance_metrics = None
                if sli_name and slo_threshold:
                    performance_metrics = PerformanceMetrics(
                        sli_name=sli_name,
                        slo_threshold=slo_threshold,
                        actual_value=0.0,
                    )
                
                # Get advanced tracing manager if available
                global _tracing_manager
                if isinstance(_tracing_manager, AdvancedTracingManager):
                    with _tracing_manager.enhanced_span(
                        span_name,
                        kind=kind,
                        business_metrics=business_metrics,
                        performance_metrics=performance_metrics,
                    ) as span:
                        result = func(*args, **kwargs)
                        return result
                else:
                    # Fallback to basic tracing
                    tracer = get_tracer()
                    with tracer.start_as_current_span(span_name, kind=kind) as span:
                        span.set_attribute("function.name", func.__name__)
                        span.set_attribute("function.module", func.__module__)
                        span.set_attribute("operation.type", operation_type)
                        
                        if get_correlation_id():
                            span.set_attribute("correlation.id", get_correlation_id())
                        
                        result = func(*args, **kwargs)
                        span.set_status(Status(StatusCode.OK))
                        return result
            
            except Exception as e:
                logger.error(f"Error in traced function {span_name}: {e}")
                raise
            
            finally:
                if correlation_token:
                    context.detach(correlation_token)
        
        return wrapper
    return decorator


def trace_with_correlation(
    correlation_id: Optional[str] = None,
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    business_context: Optional[Dict[str, Any]] = None,
):
    """Decorator to trace function with correlation ID."""
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Use provided correlation ID or create new one
            corr_id = correlation_id or create_correlation_id()
            correlation_token = set_correlation_id(corr_id)
            
            try:
                business_metrics = BusinessMetrics(
                    request_id=corr_id,
                    custom_attributes=business_context or {},
                )
                
                # Get advanced tracing manager if available
                global _tracing_manager
                if isinstance(_tracing_manager, AdvancedTracingManager):
                    with _tracing_manager.enhanced_span(
                        span_name,
                        kind=kind,
                        business_metrics=business_metrics,
                    ) as span:
                        result = func(*args, **kwargs)
                        return result
                else:
                    # Fallback to basic tracing
                    tracer = get_tracer()
                    with tracer.start_as_current_span(span_name, kind=kind) as span:
                        span.set_attribute("function.name", func.__name__)
                        span.set_attribute("function.module", func.__module__)
                        span.set_attribute("correlation.id", corr_id)
                        
                        if business_context:
                            for key, value in business_context.items():
                                span.set_attribute(f"business.{key}", value)
                        
                        result = func(*args, **kwargs)
                        span.set_status(Status(StatusCode.OK))
                        return result
            
            except Exception as e:
                logger.error(f"Error in correlated traced function {span_name}: {e}")
                raise
            
            finally:
                context.detach(correlation_token)
        
        return wrapper
    return decorator


@asynccontextmanager
async def async_enhanced_span(
    name: str,
    kind: SpanKind = SpanKind.INTERNAL,
    business_metrics: Optional[BusinessMetrics] = None,
    performance_metrics: Optional[PerformanceMetrics] = None,
):
    """Async context manager for enhanced spans."""
    global _tracing_manager
    
    if isinstance(_tracing_manager, AdvancedTracingManager):
        with _tracing_manager.enhanced_span(
            name,
            kind=kind,
            business_metrics=business_metrics,
            performance_metrics=performance_metrics,
        ) as span:
            yield span
    else:
        # Fallback to basic span
        tracer = get_tracer()
        with tracer.start_as_current_span(name, kind=kind) as span:
            yield span


def get_trace_context_headers() -> Dict[str, str]:
    """Get trace context as HTTP headers for service-to-service calls."""
    headers = {}
    inject(headers)
    
    # Add correlation ID if available
    correlation_id = get_correlation_id()
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    
    return headers


def extract_trace_context_from_headers(headers: Dict[str, str]) -> Optional[context.Context]:
    """Extract trace context from HTTP headers."""
    # Extract OpenTelemetry context
    otel_context = extract(headers)
    
    # Extract correlation ID
    correlation_id = headers.get("X-Correlation-ID")
    if correlation_id:
        correlation_token = set_correlation_id(correlation_id)
        # Note: In a real implementation, you'd want to manage this token properly
    
    return otel_context


def create_trace_link(trace_id: str, span_id: str) -> Link:
    """Create a trace link for connecting related spans."""
    from opentelemetry.trace import TraceFlags
    
    # Convert string IDs to integers
    trace_id_int = int(trace_id, 16) if isinstance(trace_id, str) else trace_id
    span_id_int = int(span_id, 16) if isinstance(span_id, str) else span_id
    
    # Create span context
    span_context = trace.SpanContext(
        trace_id=trace_id_int,
        span_id=span_id_int,
        is_remote=True,
        trace_flags=TraceFlags.SAMPLED,
    )
    
    return Link(context=span_context)


def get_current_trace_info() -> Dict[str, str]:
    """Get current trace information."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span_context = span.get_span_context()
        return {
            "trace_id": format(span_context.trace_id, "032x"),
            "span_id": format(span_context.span_id, "016x"),
            "correlation_id": get_correlation_id() or "",
        }
    
    return {
        "trace_id": "",
        "span_id": "",
        "correlation_id": get_correlation_id() or "",
    }