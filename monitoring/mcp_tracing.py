#!/usr/bin/env python3
"""
MCP Server Distributed Tracing System
Implements OpenTelemetry integration for distributed tracing with request correlation,
span creation, and trace analysis for MCP servers.
"""

import asyncio
import json
import logging
import time
import uuid
import contextvars
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import httpx
import structlog

# OpenTelemetry imports
from opentelemetry import trace, context, baggage
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.asyncio import AsyncioInstrumentor
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.trace import TracerProvider, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION
from opentelemetry.trace import Status, StatusCode, Span
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

class SpanKind(Enum):
    """Types of spans for MCP operations"""
    CLIENT = "client"
    SERVER = "server"
    PRODUCER = "producer"
    CONSUMER = "consumer"
    INTERNAL = "internal"

@dataclass
class TraceContext:
    """Context information for a trace"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    baggage: Dict[str, str]
    start_time: datetime
    service_name: str
    operation_name: str

@dataclass
class SpanMetrics:
    """Metrics collected for a span"""
    duration_ms: float
    success: bool
    error_count: int
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]]
    links: List[Dict[str, Any]]

class MCPTracer:
    """Distributed tracing system for MCP servers"""
    
    def __init__(self, config_path: str = None):
        self.logger = structlog.get_logger("mcp_tracer")
        self.config = self._load_config(config_path)
        self.tracer_provider = None
        self.tracer = None
        self.active_spans: Dict[str, Span] = {}
        self.span_metrics: Dict[str, SpanMetrics] = {}
        self._setup_tracing()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load tracing configuration"""
        default_config = {
            "service_name": "mcp-servers",
            "service_version": "1.0.0",
            "environment": "production",
            "tracing": {
                "enabled": True,
                "sample_rate": 1.0,
                "max_span_attributes": 128,
                "max_events_per_span": 128,
                "max_links_per_span": 128,
                "span_timeout_seconds": 300
            },
            "exporters": {
                "jaeger": {
                    "enabled": True,
                    "agent_host_name": "localhost",
                    "agent_port": 14268,
                    "collector_endpoint": "http://localhost:14268/api/traces"
                },
                "otlp": {
                    "enabled": False,
                    "endpoint": "http://localhost:4317",
                    "headers": {},
                    "insecure": True
                },
                "console": {
                    "enabled": True
                }
            },
            "instrumentation": {
                "httpx": True,
                "asyncio": True,
                "auto_instrument": True
            },
            "baggage": {
                "default_baggage": {
                    "environment": "production",
                    "service.name": "mcp-servers"
                }
            },
            "correlation": {
                "header_name": "X-Trace-Id",
                "correlation_id_header": "X-Correlation-Id",
                "user_id_header": "X-User-Id",
                "session_id_header": "X-Session-Id"
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.warning("Failed to load config file, using defaults", error=str(e))
                
        return default_config

    def _setup_tracing(self):
        """Setup OpenTelemetry tracing"""
        if not self.config["tracing"]["enabled"]:
            self.logger.info("Tracing disabled")
            return
            
        try:
            # Create resource
            resource = Resource.create({
                SERVICE_NAME: self.config["service_name"],
                SERVICE_VERSION: self.config["service_version"],
                "environment": self.config["environment"]
            })
            
            # Create tracer provider
            self.tracer_provider = TracerProvider(
                resource=resource,
                sampler=trace.TraceIdRatioBasedSampler(
                    rate=self.config["tracing"]["sample_rate"]
                )
            )
            
            # Setup exporters
            self._setup_exporters()
            
            # Set global tracer provider
            trace.set_tracer_provider(self.tracer_provider)
            
            # Get tracer
            self.tracer = trace.get_tracer(
                __name__,
                version=self.config["service_version"]
            )
            
            # Setup instrumentation
            self._setup_instrumentation()
            
            self.logger.info("Tracing initialized successfully")
            
        except Exception as e:
            self.logger.error("Failed to setup tracing", error=str(e))

    def _setup_exporters(self):
        """Setup trace exporters"""
        exporters_config = self.config["exporters"]
        
        # Jaeger exporter
        if exporters_config["jaeger"]["enabled"]:
            try:
                jaeger_exporter = JaegerExporter(
                    agent_host_name=exporters_config["jaeger"]["agent_host_name"],
                    agent_port=exporters_config["jaeger"]["agent_port"],
                    collector_endpoint=exporters_config["jaeger"]["collector_endpoint"]
                )
                span_processor = BatchSpanProcessor(jaeger_exporter)
                self.tracer_provider.add_span_processor(span_processor)
                self.logger.info("Jaeger exporter configured")
            except Exception as e:
                self.logger.error("Failed to setup Jaeger exporter", error=str(e))
        
        # OTLP exporter
        if exporters_config["otlp"]["enabled"]:
            try:
                otlp_exporter = OTLPSpanExporter(
                    endpoint=exporters_config["otlp"]["endpoint"],
                    headers=exporters_config["otlp"]["headers"],
                    insecure=exporters_config["otlp"]["insecure"]
                )
                span_processor = BatchSpanProcessor(otlp_exporter)
                self.tracer_provider.add_span_processor(span_processor)
                self.logger.info("OTLP exporter configured")
            except Exception as e:
                self.logger.error("Failed to setup OTLP exporter", error=str(e))
        
        # Console exporter (for debugging)
        if exporters_config["console"]["enabled"]:
            try:
                console_exporter = ConsoleSpanExporter()
                span_processor = BatchSpanProcessor(console_exporter)
                self.tracer_provider.add_span_processor(span_processor)
                self.logger.info("Console exporter configured")
            except Exception as e:
                self.logger.error("Failed to setup Console exporter", error=str(e))

    def _setup_instrumentation(self):
        """Setup automatic instrumentation"""
        instrumentation_config = self.config["instrumentation"]
        
        try:
            # HTTP client instrumentation
            if instrumentation_config["httpx"]:
                HTTPXClientInstrumentor().instrument()
                self.logger.info("HTTPX instrumentation enabled")
            
            # Asyncio instrumentation
            if instrumentation_config["asyncio"]:
                AsyncioInstrumentor().instrument()
                self.logger.info("Asyncio instrumentation enabled")
                
        except Exception as e:
            self.logger.error("Failed to setup instrumentation", error=str(e))

    def create_span(
        self, 
        operation_name: str,
        span_kind: SpanKind = SpanKind.INTERNAL,
        parent_context: Optional[context.Context] = None,
        attributes: Optional[Dict[str, Any]] = None,
        server_name: Optional[str] = None
    ) -> Span:
        """Create a new span"""
        if not self.tracer:
            return trace.INVALID_SPAN
            
        # Determine span kind
        otel_span_kind = {
            SpanKind.CLIENT: trace.SpanKind.CLIENT,
            SpanKind.SERVER: trace.SpanKind.SERVER,
            SpanKind.PRODUCER: trace.SpanKind.PRODUCER,
            SpanKind.CONSUMER: trace.SpanKind.CONSUMER,
            SpanKind.INTERNAL: trace.SpanKind.INTERNAL
        }.get(span_kind, trace.SpanKind.INTERNAL)
        
        # Create span with context
        ctx = parent_context or context.get_current()
        span = self.tracer.start_span(
            name=operation_name,
            kind=otel_span_kind,
            context=ctx
        )
        
        # Set standard attributes
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        
        # Set server-specific attributes
        if server_name:
            span.set_attribute("mcp.server.name", server_name)
        
        # Set service attributes
        span.set_attribute("service.name", self.config["service_name"])
        span.set_attribute("service.version", self.config["service_version"])
        span.set_attribute("environment", self.config["environment"])
        
        # Store span for tracking
        span_id = str(uuid.uuid4())
        self.active_spans[span_id] = span
        
        # Initialize metrics
        self.span_metrics[span_id] = SpanMetrics(
            duration_ms=0,
            success=True,
            error_count=0,
            attributes=attributes or {},
            events=[],
            links=[]
        )
        
        return span

    def start_mcp_request_span(
        self,
        method: str,
        server_name: str,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Span:
        """Start a span for an MCP request"""
        
        # Extract context from headers if provided
        parent_context = None
        if headers:
            parent_context = extract(headers)
        
        # Create operation name
        operation_name = f"mcp.{server_name}.{method}"
        
        # Create span
        span = self.create_span(
            operation_name=operation_name,
            span_kind=SpanKind.SERVER,
            parent_context=parent_context,
            server_name=server_name
        )
        
        # Set MCP-specific attributes
        span.set_attribute("mcp.method", method)
        span.set_attribute("mcp.server.name", server_name)
        span.set_attribute("mcp.request.id", request_id or str(uuid.uuid4()))
        
        if user_id:
            span.set_attribute("user.id", user_id)
        if session_id:
            span.set_attribute("session.id", session_id)
        
        # Set baggage for correlation
        baggage_data = self.config["baggage"]["default_baggage"].copy()
        baggage_data.update({
            "mcp.server": server_name,
            "mcp.method": method
        })
        
        if user_id:
            baggage_data["user.id"] = user_id
        if session_id:
            baggage_data["session.id"] = session_id
            
        # Set baggage in context
        ctx = baggage.set_baggage_items(baggage_data)
        
        return span

    def start_tool_execution_span(
        self,
        tool_name: str,
        server_name: str,
        parent_span: Optional[Span] = None,
        tool_args: Optional[Dict[str, Any]] = None
    ) -> Span:
        """Start a span for tool execution"""
        
        operation_name = f"mcp.tool.{tool_name}"
        
        # Get parent context
        parent_context = None
        if parent_span:
            parent_context = trace.set_span_in_context(parent_span)
        
        span = self.create_span(
            operation_name=operation_name,
            span_kind=SpanKind.INTERNAL,
            parent_context=parent_context,
            server_name=server_name
        )
        
        # Set tool-specific attributes
        span.set_attribute("mcp.tool.name", tool_name)
        span.set_attribute("mcp.server.name", server_name)
        span.set_attribute("mcp.operation.type", "tool_execution")
        
        if tool_args:
            # Store non-sensitive tool arguments
            safe_args = self._sanitize_tool_args(tool_args)
            for key, value in safe_args.items():
                span.set_attribute(f"mcp.tool.arg.{key}", str(value)[:100])  # Limit length
        
        return span

    def start_dependency_span(
        self,
        dependency_name: str,
        operation: str,
        server_name: str,
        parent_span: Optional[Span] = None,
        endpoint: Optional[str] = None
    ) -> Span:
        """Start a span for dependency calls"""
        
        operation_name = f"mcp.dependency.{dependency_name}.{operation}"
        
        parent_context = None
        if parent_span:
            parent_context = trace.set_span_in_context(parent_span)
        
        span = self.create_span(
            operation_name=operation_name,
            span_kind=SpanKind.CLIENT,
            parent_context=parent_context,
            server_name=server_name
        )
        
        # Set dependency-specific attributes
        span.set_attribute("mcp.dependency.name", dependency_name)
        span.set_attribute("mcp.dependency.operation", operation)
        span.set_attribute("mcp.server.name", server_name)
        
        if endpoint:
            span.set_attribute("mcp.dependency.endpoint", endpoint)
        
        return span

    def add_span_event(
        self,
        span: Span,
        event_name: str,
        attributes: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        """Add an event to a span"""
        if span == trace.INVALID_SPAN:
            return
            
        event_attributes = attributes or {}
        event_timestamp = timestamp or datetime.utcnow()
        
        span.add_event(
            name=event_name,
            attributes=event_attributes,
            timestamp=int(event_timestamp.timestamp() * 1_000_000_000)  # nanoseconds
        )
        
        # Track in metrics
        span_id = self._get_span_id(span)
        if span_id and span_id in self.span_metrics:
            self.span_metrics[span_id].events.append({
                "name": event_name,
                "attributes": event_attributes,
                "timestamp": event_timestamp.isoformat()
            })

    def add_span_error(
        self,
        span: Span,
        error: Exception,
        error_type: Optional[str] = None,
        stack_trace: Optional[str] = None
    ):
        """Add error information to a span"""
        if span == trace.INVALID_SPAN:
            return
            
        # Set span status to error
        span.set_status(Status(StatusCode.ERROR, str(error)))
        
        # Add error attributes
        span.set_attribute("error", True)
        span.set_attribute("error.type", error_type or type(error).__name__)
        span.set_attribute("error.message", str(error))
        
        if stack_trace:
            span.set_attribute("error.stack", stack_trace[:1000])  # Limit size
        
        # Add error event
        self.add_span_event(
            span,
            "exception",
            {
                "exception.type": type(error).__name__,
                "exception.message": str(error),
                "exception.escaped": False
            }
        )
        
        # Track in metrics
        span_id = self._get_span_id(span)
        if span_id and span_id in self.span_metrics:
            self.span_metrics[span_id].success = False
            self.span_metrics[span_id].error_count += 1

    def finish_span(
        self,
        span: Span,
        success: bool = True,
        result_attributes: Optional[Dict[str, Any]] = None
    ):
        """Finish a span with result information"""
        if span == trace.INVALID_SPAN:
            return
            
        # Set final attributes
        if result_attributes:
            for key, value in result_attributes.items():
                span.set_attribute(key, value)
        
        # Set status
        if success:
            span.set_status(Status(StatusCode.OK))
        else:
            span.set_status(Status(StatusCode.ERROR))
        
        # End the span
        span.end()
        
        # Update metrics
        span_id = self._get_span_id(span)
        if span_id:
            if span_id in self.span_metrics:
                metrics = self.span_metrics[span_id]
                metrics.success = success
                # Calculate duration (would need start time tracking)
            
            # Remove from active spans
            if span_id in self.active_spans:
                del self.active_spans[span_id]

    def create_trace_headers(self, span: Optional[Span] = None) -> Dict[str, str]:
        """Create headers for trace propagation"""
        headers = {}
        
        if span and span != trace.INVALID_SPAN:
            # Get current context with span
            ctx = trace.set_span_in_context(span)
        else:
            ctx = context.get_current()
        
        # Inject context into headers
        propagator = TraceContextTextMapPropagator()
        propagator.inject(headers, context=ctx)
        
        # Add correlation headers
        correlation_config = self.config["correlation"]
        
        # Add trace ID header
        trace_id = self._extract_trace_id(ctx)
        if trace_id:
            headers[correlation_config["header_name"]] = trace_id
        
        # Add correlation ID
        correlation_id = baggage.get_baggage("correlation.id") or str(uuid.uuid4())
        headers[correlation_config["correlation_id_header"]] = correlation_id
        
        return headers

    def extract_context_from_headers(self, headers: Dict[str, str]) -> context.Context:
        """Extract trace context from headers"""
        propagator = TraceContextTextMapPropagator()
        return propagator.extract(headers)

    def get_current_trace_id(self) -> Optional[str]:
        """Get current trace ID"""
        current_span = trace.get_current_span()
        if current_span != trace.INVALID_SPAN:
            return f"{current_span.get_span_context().trace_id:032x}"
        return None

    def get_current_span_id(self) -> Optional[str]:
        """Get current span ID"""
        current_span = trace.get_current_span()
        if current_span != trace.INVALID_SPAN:
            return f"{current_span.get_span_context().span_id:016x}"
        return None

    def get_trace_metrics(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """Get trace metrics for analysis"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # This would typically query your tracing backend
        # For now, return metrics from in-memory data
        active_traces = len(self.active_spans)
        total_spans = len(self.span_metrics)
        
        successful_spans = len([
            m for m in self.span_metrics.values() 
            if m.success
        ])
        
        error_spans = total_spans - successful_spans
        
        avg_duration = 0
        if self.span_metrics:
            durations = [m.duration_ms for m in self.span_metrics.values()]
            avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            "time_window_minutes": time_window_minutes,
            "active_traces": active_traces,
            "total_spans": total_spans,
            "successful_spans": successful_spans,
            "error_spans": error_spans,
            "success_rate": (successful_spans / total_spans) if total_spans > 0 else 0,
            "average_duration_ms": avg_duration,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _sanitize_tool_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from tool arguments"""
        sensitive_keys = {
            'password', 'token', 'key', 'secret', 'auth', 'credential',
            'api_key', 'private_key', 'access_token', 'refresh_token'
        }
        
        sanitized = {}
        for key, value in args.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 100:
                sanitized[key] = value[:100] + "..."
            else:
                sanitized[key] = value
        
        return sanitized

    def _get_span_id(self, span: Span) -> Optional[str]:
        """Get internal span ID for tracking"""
        # This would need to be implemented based on how spans are tracked
        for span_id, tracked_span in self.active_spans.items():
            if tracked_span == span:
                return span_id
        return None

    def _extract_trace_id(self, ctx: context.Context) -> Optional[str]:
        """Extract trace ID from context"""
        span = trace.get_current_span(ctx)
        if span != trace.INVALID_SPAN:
            return f"{span.get_span_context().trace_id:032x}"
        return None

    # Context manager support
    def trace_operation(
        self,
        operation_name: str,
        span_kind: SpanKind = SpanKind.INTERNAL,
        server_name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """Context manager for tracing operations"""
        return TracingContext(self, operation_name, span_kind, server_name, attributes)

class TracingContext:
    """Context manager for automatic span lifecycle management"""
    
    def __init__(
        self,
        tracer: MCPTracer,
        operation_name: str,
        span_kind: SpanKind,
        server_name: Optional[str],
        attributes: Optional[Dict[str, Any]]
    ):
        self.tracer = tracer
        self.operation_name = operation_name
        self.span_kind = span_kind
        self.server_name = server_name
        self.attributes = attributes
        self.span: Optional[Span] = None
        self.start_time: Optional[float] = None

    def __enter__(self) -> Span:
        self.start_time = time.time()
        self.span = self.tracer.create_span(
            operation_name=self.operation_name,
            span_kind=self.span_kind,
            server_name=self.server_name,
            attributes=self.attributes
        )
        return self.span

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.span:
            success = exc_type is None
            
            if exc_type:
                self.tracer.add_span_error(self.span, exc_val)
            
            # Add duration
            if self.start_time:
                duration = (time.time() - self.start_time) * 1000
                self.span.set_attribute("duration_ms", duration)
            
            self.tracer.finish_span(self.span, success=success)

# Decorators for automatic tracing
def trace_mcp_method(
    method_name: Optional[str] = None,
    server_name: Optional[str] = None,
    span_kind: SpanKind = SpanKind.SERVER
):
    """Decorator to automatically trace MCP methods"""
    def decorator(func: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            tracer = get_global_tracer()
            if not tracer:
                return await func(*args, **kwargs)
            
            operation = method_name or f"{func.__module__}.{func.__name__}"
            
            with tracer.trace_operation(operation, span_kind, server_name) as span:
                # Add function arguments as attributes (sanitized)
                if kwargs:
                    safe_kwargs = tracer._sanitize_tool_args(kwargs)
                    for key, value in safe_kwargs.items():
                        span.set_attribute(f"arg.{key}", str(value)[:100])
                
                result = await func(*args, **kwargs)
                
                # Add result information
                if result is not None:
                    span.set_attribute("result.type", type(result).__name__)
                    if hasattr(result, '__len__'):
                        span.set_attribute("result.size", len(result))
                
                return result
        
        def sync_wrapper(*args, **kwargs):
            tracer = get_global_tracer()
            if not tracer:
                return func(*args, **kwargs)
            
            operation = method_name or f"{func.__module__}.{func.__name__}"
            
            with tracer.trace_operation(operation, span_kind, server_name) as span:
                # Add function arguments as attributes (sanitized)
                if kwargs:
                    safe_kwargs = tracer._sanitize_tool_args(kwargs)
                    for key, value in safe_kwargs.items():
                        span.set_attribute(f"arg.{key}", str(value)[:100])
                
                result = func(*args, **kwargs)
                
                # Add result information
                if result is not None:
                    span.set_attribute("result.type", type(result).__name__)
                    if hasattr(result, '__len__'):
                        span.set_attribute("result.size", len(result))
                
                return result
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# Global tracer instance
_global_tracer: Optional[MCPTracer] = None

def init_global_tracer(config_path: str = None) -> MCPTracer:
    """Initialize global tracer instance"""
    global _global_tracer
    _global_tracer = MCPTracer(config_path)
    return _global_tracer

def get_global_tracer() -> Optional[MCPTracer]:
    """Get global tracer instance"""
    return _global_tracer

# Example usage and CLI
async def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Server Tracing System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--demo", action="store_true", help="Run demonstration")
    parser.add_argument("--metrics", action="store_true", help="Show trace metrics")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize tracer
    tracer = init_global_tracer(args.config)
    
    if args.demo:
        # Demonstrate tracing functionality
        print("Running tracing demonstration...")
        
        # Create a root span
        with tracer.trace_operation("demo_operation", SpanKind.SERVER, "demo-server") as root_span:
            tracer.add_span_event(root_span, "demo_started")
            
            # Simulate tool execution
            with tracer.trace_operation("tool_execution", SpanKind.INTERNAL, "demo-server") as tool_span:
                tracer.add_span_event(tool_span, "tool_started", {"tool_name": "example_tool"})
                await asyncio.sleep(0.1)  # Simulate work
                tracer.add_span_event(tool_span, "tool_completed")
            
            # Simulate dependency call
            with tracer.trace_operation("dependency_call", SpanKind.CLIENT, "demo-server") as dep_span:
                tracer.add_span_event(dep_span, "request_sent", {"endpoint": "https://api.example.com"})
                await asyncio.sleep(0.05)  # Simulate network call
                tracer.add_span_event(dep_span, "response_received", {"status_code": 200})
            
            tracer.add_span_event(root_span, "demo_completed")
        
        print("Demonstration completed. Check your tracing backend for traces.")
    
    if args.metrics:
        metrics = tracer.get_trace_metrics()
        print("Trace Metrics:")
        print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    asyncio.run(main())