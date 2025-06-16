"""
Enhanced automatic instrumentation with custom attributes and business context.

This module provides advanced auto-instrumentation capabilities for:
- FastAPI with request/response context
- SQLAlchemy with query performance tracking
- Redis with operation profiling
- HTTP clients with correlation propagation
"""

import os
import logging
import time
from typing import Dict, Any, Optional, Callable
from functools import wraps

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor

from .advanced_tracing import (
    BusinessMetrics, PerformanceMetrics, 
    get_correlation_id, set_correlation_id, create_correlation_id
)

logger = logging.getLogger(__name__)


class EnhancedInstrumentation:
    """Enhanced auto-instrumentation with custom attributes."""
    
    def __init__(self):
        self.instrumented = set()
        self.custom_attributes = {}
        self.performance_thresholds = {
            "api_slow_threshold_ms": float(os.getenv("API_SLOW_THRESHOLD_MS", "1000")),
            "db_slow_threshold_ms": float(os.getenv("DB_SLOW_THRESHOLD_MS", "100")),
            "redis_slow_threshold_ms": float(os.getenv("REDIS_SLOW_THRESHOLD_MS", "50")),
            "http_slow_threshold_ms": float(os.getenv("HTTP_SLOW_THRESHOLD_MS", "2000")),
        }
    
    def instrument_fastapi(self, app, **kwargs):
        """Instrument FastAPI with enhanced attributes."""
        if "fastapi" in self.instrumented:
            return
        
        def request_hook(span: trace.Span, scope: dict):
            """Add custom attributes to FastAPI spans."""
            if span and span.is_recording():
                # Add correlation ID
                correlation_id = get_correlation_id()
                if not correlation_id:
                    correlation_id = create_correlation_id()
                    set_correlation_id(correlation_id)
                
                span.set_attribute("correlation.id", correlation_id)
                span.set_attribute("operation.type", "api")
                
                # Add request context
                headers = scope.get("headers", [])
                for name, value in headers:
                    name_str = name.decode("utf-8")
                    value_str = value.decode("utf-8")
                    
                    # Add important headers
                    if name_str.lower() in ["user-agent", "x-forwarded-for", "x-real-ip"]:
                        span.set_attribute(f"http.request.header.{name_str}", value_str)
                    
                    # Add business context headers
                    if name_str.lower().startswith("x-tenant-"):
                        span.set_attribute(f"tenant.{name_str[9:]}", value_str)
                    elif name_str.lower().startswith("x-user-"):
                        span.set_attribute(f"user.{name_str[7:]}", value_str)
                
                # Add route information
                route = scope.get("route")
                if route:
                    span.set_attribute("http.route", route.path if hasattr(route, 'path') else str(route))
        
        def response_hook(span: trace.Span, scope: dict, response):
            """Add response attributes to FastAPI spans."""
            if span and span.is_recording():
                # Calculate request duration
                if hasattr(span, '_start_time'):
                    duration_ms = (time.time() - span._start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)
                    
                    # Check if request is slow
                    if duration_ms > self.performance_thresholds["api_slow_threshold_ms"]:
                        span.set_attribute("performance.slow", True)
                        span.set_attribute("slo.threshold_ms", self.performance_thresholds["api_slow_threshold_ms"])
                
                # Add response size if available
                if hasattr(response, 'headers'):
                    content_length = response.headers.get('content-length')
                    if content_length:
                        span.set_attribute("http.response.size", int(content_length))
        
        # Store start time in span
        original_start_span = trace.get_tracer_provider().get_tracer(__name__).start_span
        def enhanced_start_span(*args, **kwargs):
            span = original_start_span(*args, **kwargs)
            if span:
                span._start_time = time.time()
            return span
        
        try:
            FastAPIInstrumentor().instrument_app(
                app,
                request_hook=request_hook,
                response_hook=response_hook,
                **kwargs
            )
            self.instrumented.add("fastapi")
            logger.info("Enhanced FastAPI instrumentation enabled")
        except Exception as e:
            logger.error(f"Failed to instrument FastAPI: {e}")
    
    def instrument_sqlalchemy(self, engine=None, **kwargs):
        """Instrument SQLAlchemy with query performance tracking."""
        if "sqlalchemy" in self.instrumented:
            return
        
        def query_hook(span: trace.Span, conn, cursor, statement, parameters, context, executemany):
            """Add custom attributes to SQLAlchemy spans."""
            if span and span.is_recording():
                span.set_attribute("operation.type", "database")
                span.set_attribute("correlation.id", get_correlation_id() or "")
                
                # Add query context
                if statement:
                    # Determine query type
                    query_type = statement.strip().split()[0].upper()
                    span.set_attribute("db.operation", query_type)
                    
                    # Add table information (basic extraction)
                    if "FROM" in statement.upper():
                        try:
                            from_part = statement.upper().split("FROM")[1].split()[0]
                            span.set_attribute("db.table", from_part.strip())
                        except:
                            pass
                    
                    # Mark complex queries
                    if any(keyword in statement.upper() for keyword in ["JOIN", "SUBQUERY", "UNION"]):
                        span.set_attribute("db.query.complex", True)
                
                # Add connection info
                if hasattr(conn, 'engine'):
                    span.set_attribute("db.system", str(conn.engine.dialect.name))
        
        def result_hook(span: trace.Span, conn, cursor, statement, parameters, context, executemany):
            """Add result attributes to SQLAlchemy spans."""
            if span and span.is_recording():
                # Add row count if available
                if hasattr(cursor, 'rowcount') and cursor.rowcount >= 0:
                    span.set_attribute("db.rows_affected", cursor.rowcount)
                
                # Calculate query duration and check performance
                if hasattr(span, '_start_time'):
                    duration_ms = (time.time() - span._start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)
                    
                    if duration_ms > self.performance_thresholds["db_slow_threshold_ms"]:
                        span.set_attribute("performance.slow", True)
                        span.set_attribute("slo.threshold_ms", self.performance_thresholds["db_slow_threshold_ms"])
        
        try:
            SQLAlchemyInstrumentor().instrument(
                engine=engine,
                request_hook=query_hook,
                response_hook=result_hook,
                **kwargs
            )
            self.instrumented.add("sqlalchemy")
            logger.info("Enhanced SQLAlchemy instrumentation enabled")
        except Exception as e:
            logger.error(f"Failed to instrument SQLAlchemy: {e}")
    
    def instrument_redis(self, **kwargs):
        """Instrument Redis with operation profiling."""
        if "redis" in self.instrumented:
            return
        
        def redis_hook(span: trace.Span, instance, request):
            """Add custom attributes to Redis spans."""
            if span and span.is_recording():
                span.set_attribute("operation.type", "cache")
                span.set_attribute("correlation.id", get_correlation_id() or "")
                
                # Add Redis-specific context
                if hasattr(request, 'command'):
                    command = request.command
                    span.set_attribute("redis.command", command)
                    
                    # Categorize commands
                    read_commands = {"GET", "MGET", "HGET", "HGETALL", "LRANGE", "SMEMBERS"}
                    write_commands = {"SET", "MSET", "HSET", "LPUSH", "RPUSH", "SADD"}
                    
                    if command in read_commands:
                        span.set_attribute("redis.operation_type", "read")
                    elif command in write_commands:
                        span.set_attribute("redis.operation_type", "write")
                    else:
                        span.set_attribute("redis.operation_type", "other")
                
                # Add key information (limited for privacy)
                if hasattr(request, 'keys') and request.keys:
                    span.set_attribute("redis.key_count", len(request.keys))
                    # Add first key pattern (anonymized)
                    first_key = str(request.keys[0])
                    if ":" in first_key:
                        pattern = first_key.split(":")[0] + ":*"
                        span.set_attribute("redis.key_pattern", pattern)
        
        def redis_response_hook(span: trace.Span, instance, response):
            """Add response attributes to Redis spans."""
            if span and span.is_recording():
                # Calculate operation duration
                if hasattr(span, '_start_time'):
                    duration_ms = (time.time() - span._start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)
                    
                    if duration_ms > self.performance_thresholds["redis_slow_threshold_ms"]:
                        span.set_attribute("performance.slow", True)
                        span.set_attribute("slo.threshold_ms", self.performance_thresholds["redis_slow_threshold_ms"])
        
        try:
            RedisInstrumentor().instrument(
                request_hook=redis_hook,
                response_hook=redis_response_hook,
                **kwargs
            )
            self.instrumented.add("redis")
            logger.info("Enhanced Redis instrumentation enabled")
        except Exception as e:
            logger.error(f"Failed to instrument Redis: {e}")
    
    def instrument_http_clients(self, **kwargs):
        """Instrument HTTP clients with correlation propagation."""
        if "http_clients" in self.instrumented:
            return
        
        def request_hook(span: trace.Span, request):
            """Add custom attributes to HTTP client spans."""
            if span and span.is_recording():
                span.set_attribute("operation.type", "external")
                span.set_attribute("correlation.id", get_correlation_id() or "")
                
                # Add request context
                if hasattr(request, 'url'):
                    url = str(request.url)
                    span.set_attribute("http.url.full", url)
                    
                    # Extract service name from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        span.set_attribute("service.name", parsed.hostname)
                        span.set_attribute("service.port", parsed.port or 80)
                    except:
                        pass
                
                # Add important headers
                if hasattr(request, 'headers'):
                    for header_name in ['content-type', 'authorization', 'x-api-key']:
                        if header_name in request.headers:
                            if header_name == 'authorization':
                                span.set_attribute(f"http.request.header.{header_name}", "[REDACTED]")
                            else:
                                span.set_attribute(f"http.request.header.{header_name}", request.headers[header_name])
        
        def response_hook(span: trace.Span, request, response):
            """Add response attributes to HTTP client spans."""
            if span and span.is_recording():
                # Calculate request duration
                if hasattr(span, '_start_time'):
                    duration_ms = (time.time() - span._start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)
                    
                    if duration_ms > self.performance_thresholds["http_slow_threshold_ms"]:
                        span.set_attribute("performance.slow", True)
                        span.set_attribute("slo.threshold_ms", self.performance_thresholds["http_slow_threshold_ms"])
                
                # Add response context
                if hasattr(response, 'status_code'):
                    span.set_attribute("http.response.status_code", response.status_code)
                    
                    # Mark errors
                    if response.status_code >= 400:
                        span.set_attribute("error", True)
                        span.set_attribute("error.type", f"HTTP_{response.status_code}")
                        span.set_status(Status(StatusCode.ERROR, f"HTTP {response.status_code}"))
                
                # Add response size
                if hasattr(response, 'headers'):
                    content_length = response.headers.get('content-length')
                    if content_length:
                        span.set_attribute("http.response.size", int(content_length))
        
        try:
            # Instrument requests library
            RequestsInstrumentor().instrument(
                request_hook=request_hook,
                response_hook=response_hook,
                **kwargs
            )
            
            # Instrument aiohttp client
            AioHttpClientInstrumentor().instrument(
                request_hook=request_hook,
                response_hook=response_hook,
                **kwargs
            )
            
            self.instrumented.add("http_clients")
            logger.info("Enhanced HTTP client instrumentation enabled")
        except Exception as e:
            logger.error(f"Failed to instrument HTTP clients: {e}")
    
    def instrument_psycopg2(self, **kwargs):
        """Instrument PostgreSQL with performance tracking."""
        if "psycopg2" in self.instrumented:
            return
        
        def pg_hook(span: trace.Span, conn, cursor, statement, parameters, context, executemany):
            """Add custom attributes to PostgreSQL spans."""
            if span and span.is_recording():
                span.set_attribute("operation.type", "database")
                span.set_attribute("correlation.id", get_correlation_id() or "")
                span.set_attribute("db.system", "postgresql")
                
                # Add PostgreSQL-specific context
                if statement:
                    # Detect query patterns
                    statement_upper = statement.upper()
                    if "EXPLAIN" in statement_upper:
                        span.set_attribute("db.query.explained", True)
                    if "ANALYZE" in statement_upper:
                        span.set_attribute("db.query.analyzed", True)
                    if statement_upper.count("JOIN") > 2:
                        span.set_attribute("db.query.complex_joins", True)
        
        try:
            Psycopg2Instrumentor().instrument(
                request_hook=pg_hook,
                **kwargs
            )
            self.instrumented.add("psycopg2")
            logger.info("Enhanced PostgreSQL instrumentation enabled")
        except Exception as e:
            logger.error(f"Failed to instrument PostgreSQL: {e}")
    
    def instrument_all(self, app=None, engine=None, **kwargs):
        """Instrument all available libraries."""
        logger.info("Starting enhanced auto-instrumentation...")
        
        if app:
            self.instrument_fastapi(app)
        
        if engine:
            self.instrument_sqlalchemy(engine)
        
        self.instrument_redis()
        self.instrument_http_clients()
        self.instrument_psycopg2()
        
        logger.info(f"Enhanced instrumentation completed. Instrumented: {', '.join(self.instrumented)}")
    
    def get_instrumentation_status(self) -> Dict[str, Any]:
        """Get current instrumentation status."""
        return {
            "instrumented_libraries": list(self.instrumented),
            "performance_thresholds": self.performance_thresholds,
            "custom_attributes": self.custom_attributes,
        }
    
    def update_performance_thresholds(self, thresholds: Dict[str, float]):
        """Update performance thresholds."""
        self.performance_thresholds.update(thresholds)
        logger.info(f"Updated performance thresholds: {thresholds}")
    
    def add_custom_attributes(self, attributes: Dict[str, Any]):
        """Add custom attributes to all spans."""
        self.custom_attributes.update(attributes)
        logger.info(f"Added custom attributes: {attributes}")


# Global instrumentation instance
_instrumentation = EnhancedInstrumentation()


def get_instrumentation() -> EnhancedInstrumentation:
    """Get the global instrumentation instance."""
    return _instrumentation


def setup_enhanced_instrumentation(
    app=None,
    engine=None,
    custom_attributes: Optional[Dict[str, Any]] = None,
    performance_thresholds: Optional[Dict[str, float]] = None,
    **kwargs
):
    """Set up enhanced auto-instrumentation."""
    global _instrumentation
    
    if custom_attributes:
        _instrumentation.add_custom_attributes(custom_attributes)
    
    if performance_thresholds:
        _instrumentation.update_performance_thresholds(performance_thresholds)
    
    _instrumentation.instrument_all(app=app, engine=engine, **kwargs)
    
    return _instrumentation