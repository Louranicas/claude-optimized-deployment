"""
Prometheus metrics collection for comprehensive monitoring.

Provides metrics for:
- API response times
- Error rates
- Resource usage
- Business metrics
- SLA tracking
"""

import os
import time
import psutil
import functools
from typing import Dict, Optional, Callable, Any, Union
from contextlib import contextmanager
from datetime import datetime, timedelta

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Summary,
    Info,
    generate_latest,
    CollectorRegistry,
    CONTENT_TYPE_LATEST,
)
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily


class MetricsCollector:
    """Centralized metrics collector for the application."""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        
        # HTTP metrics
        self.http_requests_total = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.http_request_duration_seconds = Histogram(
            'http_request_duration_seconds',
            'HTTP request latency',
            ['method', 'endpoint'],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry
        )
        
        self.http_request_size_bytes = Summary(
            'http_request_size_bytes',
            'HTTP request size',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.http_response_size_bytes = Summary(
            'http_response_size_bytes',
            'HTTP response size',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        # Error metrics
        self.errors_total = Counter(
            'errors_total',
            'Total errors',
            ['error_type', 'component'],
            registry=self.registry
        )
        
        self.unhandled_exceptions_total = Counter(
            'unhandled_exceptions_total',
            'Total unhandled exceptions',
            ['exception_type'],
            registry=self.registry
        )
        
        # Resource metrics
        self.cpu_usage_percent = Gauge(
            'cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage_bytes = Gauge(
            'memory_usage_bytes',
            'Memory usage in bytes',
            ['type'],  # rss, vms, available, percent
            registry=self.registry
        )
        
        self.disk_usage_bytes = Gauge(
            'disk_usage_bytes',
            'Disk usage in bytes',
            ['path', 'type'],  # total, used, free
            registry=self.registry
        )
        
        self.open_file_descriptors = Gauge(
            'open_file_descriptors',
            'Number of open file descriptors',
            registry=self.registry
        )
        
        # Business metrics
        self.business_operations_total = Counter(
            'business_operations_total',
            'Total business operations',
            ['operation', 'status'],
            registry=self.registry
        )
        
        self.business_operation_duration_seconds = Histogram(
            'business_operation_duration_seconds',
            'Business operation duration',
            ['operation'],
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
            registry=self.registry
        )
        
        self.active_users = Gauge(
            'active_users',
            'Number of active users',
            registry=self.registry
        )
        
        self.queue_size = Gauge(
            'queue_size',
            'Size of various queues',
            ['queue_name'],
            registry=self.registry
        )
        
        # SLA metrics
        self.sla_compliance_percent = Gauge(
            'sla_compliance_percent',
            'SLA compliance percentage',
            ['sla_type'],
            registry=self.registry
        )
        
        self.availability_percent = Gauge(
            'availability_percent',
            'Service availability percentage',
            ['service'],
            registry=self.registry
        )
        
        # AI/ML specific metrics
        self.ai_requests_total = Counter(
            'ai_requests_total',
            'Total AI model requests',
            ['model', 'provider', 'status'],
            registry=self.registry
        )
        
        self.ai_request_duration_seconds = Histogram(
            'ai_request_duration_seconds',
            'AI request duration',
            ['model', 'provider'],
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
            registry=self.registry
        )
        
        self.ai_tokens_used = Counter(
            'ai_tokens_used',
            'Total AI tokens used',
            ['model', 'provider', 'type'],  # type: input/output
            registry=self.registry
        )
        
        self.ai_cost_dollars = Counter(
            'ai_cost_dollars',
            'Total AI cost in dollars',
            ['model', 'provider'],
            registry=self.registry
        )
        
        # MCP specific metrics
        self.mcp_tool_calls_total = Counter(
            'mcp_tool_calls_total',
            'Total MCP tool calls',
            ['server', 'tool', 'status'],
            registry=self.registry
        )
        
        self.mcp_tool_duration_seconds = Histogram(
            'mcp_tool_duration_seconds',
            'MCP tool execution duration',
            ['server', 'tool'],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry
        )
        
        # Application info
        self.app_info = Info(
            'app_info',
            'Application information',
            registry=self.registry
        )
        self.app_info.info({
            'version': os.getenv('APP_VERSION', 'unknown'),
            'environment': os.getenv('ENVIRONMENT', 'development'),
            'python_version': os.sys.version.split()[0],
        })
        
        # Initialize resource metrics
        self._update_resource_metrics()
    
    def _update_resource_metrics(self):
        """Update resource usage metrics."""
        try:
            # CPU usage
            self.cpu_usage_percent.set(psutil.cpu_percent(interval=0.1))
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage_bytes.labels(type='rss').set(memory.used)
            self.memory_usage_bytes.labels(type='available').set(memory.available)
            self.memory_usage_bytes.labels(type='percent').set(memory.percent)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.disk_usage_bytes.labels(path='/', type='total').set(disk.total)
            self.disk_usage_bytes.labels(path='/', type='used').set(disk.used)
            self.disk_usage_bytes.labels(path='/', type='free').set(disk.free)
            
            # File descriptors
            process = psutil.Process()
            self.open_file_descriptors.set(len(process.open_files()))
        except Exception:
            pass  # Silently fail resource metric updates
    
    @contextmanager
    def time_operation(self, operation: str, labels: Optional[Dict[str, str]] = None):
        """Context manager to time operations."""
        start_time = time.time()
        labels = labels or {}
        
        try:
            yield
            status = 'success'
        except Exception:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.business_operations_total.labels(
                operation=operation,
                status=status
            ).inc()
            self.business_operation_duration_seconds.labels(
                operation=operation
            ).observe(duration)
    
    def record_http_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        duration: float,
        request_size: int = 0,
        response_size: int = 0
    ):
        """Record HTTP request metrics."""
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=str(status)
        ).inc()
        
        self.http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        if request_size > 0:
            self.http_request_size_bytes.labels(
                method=method,
                endpoint=endpoint
            ).observe(request_size)
        
        if response_size > 0:
            self.http_response_size_bytes.labels(
                method=method,
                endpoint=endpoint
            ).observe(response_size)
    
    def record_error(self, error_type: str, component: str):
        """Record error metrics."""
        self.errors_total.labels(
            error_type=error_type,
            component=component
        ).inc()
    
    def record_exception(self, exception: Exception):
        """Record unhandled exception."""
        self.unhandled_exceptions_total.labels(
            exception_type=type(exception).__name__
        ).inc()
    
    def record_ai_request(
        self,
        model: str,
        provider: str,
        status: str,
        duration: float,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost: float = 0
    ):
        """Record AI/ML request metrics."""
        self.ai_requests_total.labels(
            model=model,
            provider=provider,
            status=status
        ).inc()
        
        self.ai_request_duration_seconds.labels(
            model=model,
            provider=provider
        ).observe(duration)
        
        if input_tokens > 0:
            self.ai_tokens_used.labels(
                model=model,
                provider=provider,
                type='input'
            ).inc(input_tokens)
        
        if output_tokens > 0:
            self.ai_tokens_used.labels(
                model=model,
                provider=provider,
                type='output'
            ).inc(output_tokens)
        
        if cost > 0:
            self.ai_cost_dollars.labels(
                model=model,
                provider=provider
            ).inc(cost)
    
    def record_mcp_tool_call(
        self,
        server: str,
        tool: str,
        status: str,
        duration: float
    ):
        """Record MCP tool call metrics."""
        self.mcp_tool_calls_total.labels(
            server=server,
            tool=tool,
            status=status
        ).inc()
        
        self.mcp_tool_duration_seconds.labels(
            server=server,
            tool=tool
        ).observe(duration)
    
    def update_sla_compliance(self, sla_type: str, compliance_percent: float):
        """Update SLA compliance metrics."""
        self.sla_compliance_percent.labels(sla_type=sla_type).set(compliance_percent)
    
    def update_availability(self, service: str, availability_percent: float):
        """Update service availability metrics."""
        self.availability_percent.labels(service=service).set(availability_percent)
    
    def set_active_users(self, count: int):
        """Set active users count."""
        self.active_users.set(count)
    
    def set_queue_size(self, queue_name: str, size: int):
        """Set queue size."""
        self.queue_size.labels(queue_name=queue_name).set(size)
    
    def get_metrics(self) -> bytes:
        """Get metrics in Prometheus format."""
        self._update_resource_metrics()
        return generate_latest(self.registry)


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def metrics_decorator(
    operation: Optional[str] = None,
    record_args: bool = False,
    record_result: bool = False
):
    """Decorator to automatically record metrics for functions."""
    def decorator(func: Callable) -> Callable:
        op_name = operation or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                status = 'success'
                return result
            except Exception as e:
                status = 'error'
                collector.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                collector.business_operations_total.labels(
                    operation=op_name,
                    status=status
                ).inc()
                collector.business_operation_duration_seconds.labels(
                    operation=op_name
                ).observe(duration)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                status = 'success'
                return result
            except Exception as e:
                status = 'error'
                collector.record_exception(e)
                raise
            finally:
                duration = time.time() - start_time
                collector.business_operations_total.labels(
                    operation=op_name,
                    status=status
                ).inc()
                collector.business_operation_duration_seconds.labels(
                    operation=op_name
                ).observe(duration)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    return decorator


# Convenience functions
def record_request(method: str, endpoint: str, status: int, duration: float, **kwargs):
    """Record HTTP request metrics."""
    get_metrics_collector().record_http_request(method, endpoint, status, duration, **kwargs)


def record_error(error_type: str, component: str):
    """Record error metrics."""
    get_metrics_collector().record_error(error_type, component)


def record_business_metric(operation: str, status: str = 'success', duration: Optional[float] = None):
    """Record business operation metrics."""
    collector = get_metrics_collector()
    collector.business_operations_total.labels(
        operation=operation,
        status=status
    ).inc()
    
    if duration is not None:
        collector.business_operation_duration_seconds.labels(
            operation=operation
        ).observe(duration)


import asyncio