"""
Distributed tracing with OpenTelemetry for comprehensive request tracking.

Provides:
- Span creation and management
- Context propagation
- Trace sampling
- Integration with Jaeger/Zipkin
"""

import os
import functools
import asyncio
from typing import Dict, Optional, Any, Callable, Union
from contextlib import contextmanager
from datetime import datetime

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.trace import TracerProvider, SpanProcessor
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
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
        elif exporter_type == "otlp":
            endpoint = endpoint or os.getenv("OTLP_ENDPOINT", "localhost:4317")
            return OTLPSpanExporter(
                endpoint=endpoint,
                insecure=True,  # Use secure=False for development
            )
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
            except:
                pass
            
            # Databases
            try:
                SQLAlchemyInstrumentor().instrument()
            except:
                pass
            
            try:
                RedisInstrumentor().instrument()
            except:
                pass
            
            try:
                Psycopg2Instrumentor().instrument()
            except:
                pass
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
) -> TracingManager:
    """Initialize the global tracing manager."""
    global _tracing_manager
    _tracing_manager = TracingManager(
        service_name=service_name,
        environment=environment,
        sample_rate=sample_rate,
        exporter_type=exporter_type,
        endpoint=endpoint,
    )
    return _tracing_manager


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