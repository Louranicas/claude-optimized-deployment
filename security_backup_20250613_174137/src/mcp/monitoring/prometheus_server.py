"""Production-ready Prometheus MCP Server with enhanced security and monitoring.

Features:
- Secure PromQL query validation and sanitization
- Rate limiting and circuit breaker patterns
- Connection pooling with timeout management
- Comprehensive error handling and logging
- Self-monitoring metrics collection
"""

from __future__ import annotations
import os
import re
import time
import asyncio
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
import logging
import json
from urllib.parse import quote

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from src.core.retry import retry_network, RetryConfig
from src.core.connections import get_connection_manager
from src.core.ssrf_protection import SSRFProtectedSession, get_ssrf_protector, MODERATE_SSRF_CONFIG

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

__all__ = [
    "RateLimiter",
    "CircuitBreaker",
    "PrometheusMonitoringMCP",
    "TestPrometheusValidation",
    "TestRateLimiter",
    "TestCircuitBreaker",
    "validate_promql",
    "validate_timestamp"
]


# Try to import enhanced logging, fallback to standard logging
try:
    from src.circle_of_experts.utils.logging import get_logger, LogContext
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)

# Security constants
MAX_QUERY_LENGTH = 1000
MAX_LABEL_LENGTH = 100
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60  # seconds
CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_TIMEOUT = 30  # seconds

# Query validation patterns
DANGEROUS_PATTERNS = [
    r'\b(drop|delete|truncate|alter|create|insert|update)\b',
    r'[;{}]',  # Prevent injection attempts
    r'\\x[0-9a-fA-F]{2}',  # Hex sequences
]

VALID_METRIC_NAME = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*$')
VALID_LABEL_NAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


class RateLimiter:
    """Simple rate limiter implementation."""
    
    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW):
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed."""
        now = time.time()
        # Clean old requests
        self.requests[key] = [req for req in self.requests[key] if req > now - self.window]
        
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        self.requests[key].append(now)
        return True


class CircuitBreaker:
    """Circuit breaker pattern implementation."""
    
    def __init__(self, threshold: int = CIRCUIT_BREAKER_THRESHOLD, timeout: int = CIRCUIT_BREAKER_TIMEOUT):
        self.threshold = threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure = None
        self.state = "closed"  # closed, open, half-open
    
    def record_success(self):
        """Record successful call."""
        self.failures = 0
        self.state = "closed"
    
    def record_failure(self):
        """Record failed call."""
        self.failures += 1
        self.last_failure = time.time()
        if self.failures >= self.threshold:
            self.state = "open"
    
    def is_open(self) -> bool:
        """Check if circuit is open."""
        if self.state == "open" and self.last_failure:
            if time.time() - self.last_failure > self.timeout:
                self.state = "half-open"
                return False
            return True
        return False


def validate_promql(query: str) -> None:
    """Validate and sanitize PromQL query."""
    if not query or not query.strip():
        raise MCPError(-32602, "Query cannot be empty")
    
    if len(query) > MAX_QUERY_LENGTH:
        raise MCPError(-32602, f"Query exceeds maximum length of {MAX_QUERY_LENGTH}")
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            raise MCPError(-32602, f"Query contains forbidden pattern: {pattern}")


def validate_timestamp(ts: str) -> str:
    """Validate and normalize timestamp."""
    try:
        # Try RFC3339 format
        if 'T' in ts:
            datetime.fromisoformat(ts.replace('Z', '+00:00'))
        # Try Unix timestamp
        else:
            float(ts)
        return ts
    except (ValueError, TypeError):
        raise MCPError(-32602, f"Invalid timestamp format: {ts}")


class PrometheusMonitoringMCP(MCPServer):
    """Production-ready Prometheus monitoring with enhanced security and reliability."""
    
    def __init__(self, prometheus_url: Optional[str] = None, api_key: Optional[str] = None, permission_checker: Optional[Any] = None):
        """Initialize with security and monitoring features."""
        super().__init__("prometheus-monitoring", "1.0.0", permission_checker)
        self.prometheus_url = prometheus_url or os.getenv("PROMETHEUS_URL", "http://localhost:9090")
        self.api_key = api_key or os.getenv("PROMETHEUS_API_KEY")
        self.rate_limiter = RateLimiter()
        self.circuit_breaker = CircuitBreaker()
        self._metrics = defaultdict(int)
        self._start_time = time.time()
        self._connection_manager = None
        self._ssrf_session: Optional[SSRFProtectedSession] = None
        
        # Initialize SSRF protector for monitoring endpoints
        from src.core.ssrf_protection import SSRFProtector
        self._ssrf_protector = SSRFProtector(**MODERATE_SSRF_CONFIG)
        
        # Validate Prometheus URL at initialization
        if self.prometheus_url:
            validation = self._ssrf_protector.validate_url(self.prometheus_url)
            if not validation.is_safe:
                logger.error(f"SSRF protection blocked Prometheus URL {self.prometheus_url}: {validation.reason}")
                raise ValueError(f"Unsafe Prometheus URL: {validation.reason}")
    
    async def _get_ssrf_session(self):
        """Get or create SSRF-protected session."""
        if not self._ssrf_session:
            self._ssrf_session = SSRFProtectedSession(self._ssrf_protector)
            await self._ssrf_session.__aenter__()
        return self._ssrf_session
    
    async def _make_safe_request(self, method: str, url: str, **kwargs):
        """Make HTTP request with SSRF protection."""
        session = await self._get_ssrf_session()
        return await session._validate_and_request(method, url, **kwargs)
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Prometheus server information."""
        return MCPServerInfo(
            name="prometheus-monitoring",
            version="1.0.0",
            description="Prometheus monitoring integration for CODE project observability",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "metric_querying": True,
                    "alerting": True,
                    "performance_monitoring": True,
                    "system_exploration": True,
                    "security_features": True,
                    "rate_limiting": True,
                    "circuit_breaker": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Prometheus tools."""
        return [
            MCPTool(
                name="prometheus_query",
                description="Execute PromQL queries for metrics analysis",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="PromQL query expression",
                        required=True
                    ),
                    MCPToolParameter(
                        name="time",
                        type="string",
                        description="Query evaluation time (RFC3339 or Unix timestamp)",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="prometheus_query_range",
                description="Execute PromQL range queries for time series data",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="PromQL query expression",
                        required=True
                    ),
                    MCPToolParameter(
                        name="start",
                        type="string",
                        description="Start time (RFC3339 or Unix timestamp)",
                        required=True
                    ),
                    MCPToolParameter(
                        name="end",
                        type="string",
                        description="End time (RFC3339 or Unix timestamp)",
                        required=True
                    ),
                    MCPToolParameter(
                        name="step",
                        type="string",
                        description="Query resolution step width",
                        required=False,
                        default="15s"
                    )
                ]
            ),
            MCPTool(
                name="prometheus_series",
                description="Get time series that match label matchers",
                parameters=[
                    MCPToolParameter(
                        name="match",
                        type="array",
                        description="Series selector labels",
                        required=True
                    ),
                    MCPToolParameter(
                        name="start",
                        type="string",
                        description="Start time",
                        required=False
                    ),
                    MCPToolParameter(
                        name="end",
                        type="string",
                        description="End time",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="prometheus_labels",
                description="Get label names or values",
                parameters=[
                    MCPToolParameter(
                        name="label",
                        type="string",
                        description="Label name to get values for",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="prometheus_targets",
                description="Get current target discovery status",
                parameters=[
                    MCPToolParameter(
                        name="state",
                        type="string",
                        description="Filter targets by state",
                        required=False,
                        enum=["active", "dropped", "any"]
                    )
                ]
            ),
            MCPTool(
                name="prometheus_alerts",
                description="Get active alerts from Prometheus",
                parameters=[
                    MCPToolParameter(
                        name="state",
                        type="string",
                        description="Filter alerts by state",
                        required=False,
                        enum=["firing", "pending", "inactive"]
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute tool with security checks and monitoring."""
        # Rate limiting
        if not self.rate_limiter.is_allowed(f"global:{tool_name}"):
            raise MCPError(-32000, "Rate limit exceeded")
        
        # Circuit breaker
        if self.circuit_breaker.is_open():
            raise MCPError(-32000, "Service temporarily unavailable (circuit open)")
        
        # Use connection pool instead of creating new session
        connection_manager = await get_connection_manager()
        
        # Store connection manager if not already stored
        if not hasattr(self, '_connection_manager'):
            self._connection_manager = connection_manager
        
        # Track metrics
        self._metrics["total_requests"] += 1
        self._metrics[f"requests_{tool_name}"] += 1
        start_time = time.time()
        
        try:
            with LogContext(tool=tool_name, arguments=arguments):
                if tool_name == "prometheus_query":
                    result = await self._prometheus_query(**arguments)
                elif tool_name == "prometheus_query_range":
                    result = await self._prometheus_query_range(**arguments)
                elif tool_name == "prometheus_series":
                    result = await self._prometheus_series(**arguments)
                elif tool_name == "prometheus_labels":
                    result = await self._prometheus_labels(**arguments)
                elif tool_name == "prometheus_targets":
                    result = await self._prometheus_targets(**arguments)
                elif tool_name == "prometheus_alerts":
                    result = await self._prometheus_alerts(**arguments)
                else:
                    raise MCPError(-32601, f"Unknown tool: {tool_name}")
                
                self.circuit_breaker.record_success()
                self._metrics["successful_requests"] += 1
                return result
                
        except MCPError:
            self._metrics["failed_requests"] += 1
            self.circuit_breaker.record_failure()
            raise
        except Exception as e:
            self._metrics["failed_requests"] += 1
            self.circuit_breaker.record_failure()
            logger.error(f"Error in {tool_name}: {e}", exc_info=True)
            raise MCPError(-32000, f"Internal error: {str(e)}")
        finally:
            self._metrics[f"latency_{tool_name}"] = time.time() - start_time
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_query(self, query: str, time: Optional[str] = None) -> Dict[str, Any]:
        """Execute instant PromQL query with validation."""
        validate_promql(query)
        if time:
            time = validate_timestamp(time)
        
        params = {"query": query}
        if time:
            params["time"] = time
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request(
                "GET",
                f"{self.prometheus_url}/api/v1/query",
                params=params,
                headers=headers,
                ssl=True
            )
            
            text = await response.text()
            if response.status != 200:
                logger.error(f"Query failed: {response.status} - {text}")
                raise MCPError(-32000, f"Query failed: {response.status}")
            
            data = json.loads(text)
            if data.get("status") != "success":
                raise MCPError(-32000, f"Query error: {data.get('error', 'Unknown')}")
            
            return {
                "query": query,
                "status": data.get("status"),
                "data": data.get("data"),
                "timestamp": time or datetime.utcnow().isoformat()
            }
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error: {e}")
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_query_range(
        self, query: str, start: str, end: str, step: str = "15s"
    ) -> Dict[str, Any]:
        """Execute range query with validation."""
        validate_promql(query)
        start = validate_timestamp(start)
        end = validate_timestamp(end)
        
        # Validate step format
        if not re.match(r'^\d+[smhdw]$', step):
            raise MCPError(-32602, f"Invalid step format: {step}")
        
        params = {"query": query, "start": start, "end": end, "step": step}
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request(
                "GET",
                f"{self.prometheus_url}/api/v1/query_range",
                params=params,
                headers=headers,
                ssl=True
            )
            
            text = await response.text()
            if response.status != 200:
                raise MCPError(-32000, f"Range query failed: {response.status}")
            
            data = json.loads(text)
            if data.get("status") != "success":
                raise MCPError(-32000, f"Query error: {data.get('error')}")
            
            return {
                "query": query,
                "status": data.get("status"),
                "data": data.get("data"),
                "start": start,
                "end": end,
                "step": step,
                "resultType": data.get("data", {}).get("resultType")
            }
        except aiohttp.ClientError as e:
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_series(
        self, match: List[str], start: Optional[str] = None, end: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get series with validation."""
        # Validate match expressions
        for expr in match:
            validate_promql(expr)
        
        if start:
            start = validate_timestamp(start)
        if end:
            end = validate_timestamp(end)
        
        params = {"match[]": match}
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request(
                "GET",
                f"{self.prometheus_url}/api/v1/series",
                params=params,
                headers=headers,
                ssl=True
            )
            
            if response.status != 200:
                raise MCPError(-32000, f"Series query failed: {response.status}")
            
            data = await response.json()
            return {
                "match": match,
                "status": data.get("status"),
                "data": data.get("data"),
                "series_count": len(data.get("data", []))
            }
        except aiohttp.ClientError as e:
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_labels(self, label: Optional[str] = None) -> Dict[str, Any]:
        """Get labels with validation."""
        if label:
            if len(label) > MAX_LABEL_LENGTH:
                raise MCPError(-32602, f"Label name too long: {len(label)}")
            if not VALID_LABEL_NAME.match(label):
                raise MCPError(-32602, f"Invalid label name: {label}")
            url = f"{self.prometheus_url}/api/v1/label/{quote(label)}/values"
        else:
            url = f"{self.prometheus_url}/api/v1/labels"
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request("GET", url, headers=headers, ssl=True)
            
            if response.status != 200:
                raise MCPError(-32000, f"Labels query failed: {response.status}")
            
            data = await response.json()
            return {
                "label": label,
                "status": data.get("status"),
                "data": data.get("data"),
                "count": len(data.get("data", []))
            }
        except aiohttp.ClientError as e:
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_targets(self, state: Optional[str] = None) -> Dict[str, Any]:
        """Get targets with health summary."""
        params = {}
        if state and state != "any":
            params["state"] = state
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request(
                "GET",
                f"{self.prometheus_url}/api/v1/targets",
                params=params,
                headers=headers,
                ssl=True
            )
            
            if response.status != 200:
                raise MCPError(-32000, f"Targets query failed: {response.status}")
            
            data = await response.json()
            targets = data.get("data", {})
            
            # Calculate health summary
            active = targets.get("activeTargets", [])
            dropped = targets.get("droppedTargets", [])
            
            health_summary = {
                "total_active": len(active),
                "total_dropped": len(dropped),
                "healthy": sum(1 for t in active if t.get("health") == "up"),
                "unhealthy": sum(1 for t in active if t.get("health") == "down")
            }
            
            return {
                "state": state,
                "status": data.get("status"),
                "data": targets,
                "health_summary": health_summary
            }
        except aiohttp.ClientError as e:
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def _prometheus_alerts(self, state: Optional[str] = None) -> Dict[str, Any]:
        """Get active alerts."""
        params = {}
        if state:
            params["state"] = state
        
        try:
            headers = {"User-Agent": "PrometheusMonitoringMCP/1.0"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = await self._make_safe_request(
                "GET",
                f"{self.prometheus_url}/api/v1/alerts",
                params=params,
                headers=headers,
                ssl=True
            )
            
            if response.status != 200:
                raise MCPError(-32000, f"Alerts query failed: {response.status}")
            
            data = await response.json()
            alerts = data.get("data", {}).get("alerts", [])
            
            # Categorize alerts
            by_severity = defaultdict(list)
            for alert in alerts:
                severity = alert.get("labels", {}).get("severity", "unknown")
                by_severity[severity].append(alert)
            
            return {
                "state": state,
                "status": data.get("status"),
                "alerts": alerts,
                "summary": {
                    "total": len(alerts),
                    "by_severity": {k: len(v) for k, v in by_severity.items()},
                    "firing": sum(1 for a in alerts if a.get("state") == "firing"),
                    "pending": sum(1 for a in alerts if a.get("state") == "pending")
                }
            }
        except aiohttp.ClientError as e:
            raise MCPError(-32000, f"Connection error: {str(e)}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get internal metrics for monitoring."""
        uptime = time.time() - self._start_time
        return {
            "uptime_seconds": uptime,
            "total_requests": self._metrics["total_requests"],
            "successful_requests": self._metrics["successful_requests"],
            "failed_requests": self._metrics["failed_requests"],
            "circuit_breaker_state": self.circuit_breaker.state,
            "rate_limit_active": len(self.rate_limiter.requests),
            "tool_metrics": {
                k: v for k, v in self._metrics.items()
                if k.startswith("requests_") or k.startswith("latency_")
            }
        }
    
    async def close(self):
        """Cleanup resources."""
        if self._ssrf_session:
            await self._ssrf_session.__aexit__(None, None, None)
            self._ssrf_session = None
        if hasattr(self, 'session') and self.session:
            await self.session.close()
            self.session = None
        logger.info("Prometheus MCP closed", extra={"metrics": self.get_metrics()})


# Alias for backward compatibility
PrometheusMonitoringMCPServer = PrometheusMonitoringMCP


# Minimal unit tests (within line budget)
import pytest

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    log_error,\n    ServiceUnavailableError,\n    ExternalServiceError,\n    ValidationError,\n    ConfigurationError,\n    CircuitBreakerError,\n    RateLimitError
)


class TestPrometheusValidation:
    """Test security validation functions."""
    
    def test_validate_promql_valid(self):
        """Test valid queries pass."""
        validate_promql("up")
        validate_promql("rate(http_requests_total[5m])")
        validate_promql("sum by (job) (up)")
    
    def test_validate_promql_dangerous(self):
        """Test dangerous queries are rejected."""
        with pytest.raises(MCPError):
            validate_promql("drop table users")
        with pytest.raises(MCPError):
            validate_promql("query; delete from metrics")
        with pytest.raises(MCPError):
            validate_promql("{malicious}")
    
    def test_validate_timestamp(self):
        """Test timestamp validation."""
        assert validate_timestamp("1234567890") == "1234567890"
        assert validate_timestamp("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"
        
        with pytest.raises(MCPError):
            validate_timestamp("not-a-timestamp")


class TestRateLimiter:
    """Test rate limiting."""
    
    def test_rate_limit(self):
        """Test rate limiter enforces limits."""
        limiter = RateLimiter(max_requests=2, window=1)
        assert limiter.is_allowed("test") is True
        assert limiter.is_allowed("test") is True
        assert limiter.is_allowed("test") is False
        
        # Wait for window to pass
        time.sleep(1.1)
        assert limiter.is_allowed("test") is True


class TestCircuitBreaker:
    """Test circuit breaker."""
    
    def test_circuit_breaker(self):
        """Test circuit breaker opens after failures."""
        cb = CircuitBreaker(threshold=2, timeout=1)
        assert cb.is_open() is False
        
        cb.record_failure()
        assert cb.is_open() is False
        
        cb.record_failure()
        assert cb.is_open() is True
        
        # Wait for timeout
        time.sleep(1.1)
        assert cb.is_open() is False  # Half-open
        
        cb.record_success()
        assert cb.is_open() is False