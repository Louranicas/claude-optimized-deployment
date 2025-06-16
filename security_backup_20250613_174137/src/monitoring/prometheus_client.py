"""
Prometheus client for SLA monitoring with real metrics retrieval.

Provides:
- Secure Prometheus query execution
- Time series data fetching
- Metric aggregation functions
- Connection pooling and error handling
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

import aiohttp
from prometheus_client.parser import text_string_to_metric_families

from src.core.retry import retry_network, RetryConfig
from src.core.ssrf_protection import SSRFProtectedSession, get_ssrf_protector, MODERATE_SSRF_CONFIG
from src.core.exceptions import ExternalServiceError, ValidationError

__all__ = [
    "PrometheusQuery",
    "PrometheusClient",
    "MetricResult",
    "TimeSeriesPoint",
    "get_prometheus_client"
]

logger = logging.getLogger(__name__)


@dataclass
class TimeSeriesPoint:
    """Single time series data point."""
    timestamp: float
    value: float


@dataclass
class MetricResult:
    """Result from a Prometheus query."""
    metric_name: str
    labels: Dict[str, str]
    values: List[TimeSeriesPoint]
    result_type: str
    
    @property
    def latest_value(self) -> Optional[float]:
        """Get the most recent value."""
        if not self.values:
            return None
        return self.values[-1].value
    
    @property
    def average_value(self) -> Optional[float]:
        """Get average value across all points."""
        if not self.values:
            return None
        return sum(p.value for p in self.values) / len(self.values)


class PrometheusQuery:
    """Builder for Prometheus queries."""
    
    def __init__(self, metric: str):
        self.metric = metric
        self.filters = []
        self.functions = []
        self.group_by = []
        
    def filter(self, label: str, operator: str, value: str) -> 'PrometheusQuery':
        """Add a label filter."""
        self.filters.append(f'{label}{operator}"{value}"')
        return self
        
    def rate(self, interval: str = "5m") -> 'PrometheusQuery':
        """Apply rate function."""
        self.functions.append(f"rate({{}[{interval}])")
        return self
        
    def sum(self) -> 'PrometheusQuery':
        """Apply sum aggregation."""
        self.functions.append("sum({})")
        return self
        
    def avg(self) -> 'PrometheusQuery':
        """Apply average aggregation."""
        self.functions.append("avg({})")
        return self
        
    def quantile(self, q: float) -> 'PrometheusQuery':
        """Apply quantile function."""
        self.functions.append(f"quantile({q}, {{}})")
        return self
        
    def by(self, *labels: str) -> 'PrometheusQuery':
        """Group by labels."""
        self.group_by.extend(labels)
        return self
        
    def build(self) -> str:
        """Build the final PromQL query."""
        # Start with metric and filters
        if self.filters:
            query = f'{self.metric}{{{",".join(self.filters)}}}'
        else:
            query = self.metric
            
        # Apply functions in reverse order (innermost first)
        for func in reversed(self.functions):
            query = func.format(query)
            
        # Add group by clause
        if self.group_by and any("sum" in f or "avg" in f for f in self.functions):
            query += f' by ({",".join(self.group_by)})'
            
        return query


class PrometheusClient:
    """Production-ready Prometheus client for SLA monitoring."""
    
    def __init__(self, 
                 prometheus_url: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout: int = 30):
        self.prometheus_url = prometheus_url or os.getenv("PROMETHEUS_URL", "http://localhost:9090")
        self.api_key = api_key or os.getenv("PROMETHEUS_API_KEY")
        self.timeout = timeout
        self._session: Optional[SSRFProtectedSession] = None
        self._ssrf_protector = get_ssrf_protector(**MODERATE_SSRF_CONFIG)
        
        # Validate Prometheus URL
        validation = self._ssrf_protector.validate_url(self.prometheus_url)
        if not validation.is_safe:
            raise ValidationError(f"Unsafe Prometheus URL: {validation.reason}")
    
    async def _get_session(self) -> SSRFProtectedSession:
        """Get or create SSRF-protected session."""
        if not self._session:
            self._session = SSRFProtectedSession(self._ssrf_protector)
            await self._session.__aenter__()
        return self._session
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated request to Prometheus API."""
        session = await self._get_session()
        
        headers = {"User-Agent": "PrometheusClient/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        url = f"{self.prometheus_url}/api/v1/{endpoint}"
        
        try:
            response = await session._validate_and_request(
                "GET", 
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status != 200:
                text = await response.text()
                raise ExternalServiceError(f"Prometheus API error {response.status}: {text}")
            
            data = await response.json()
            
            if data.get("status") != "success":
                error = data.get("error", "Unknown error")
                raise ExternalServiceError(f"Prometheus query failed: {error}")
            
            return data.get("data", {})
            
        except aiohttp.ClientError as e:
            raise ExternalServiceError(f"Failed to connect to Prometheus: {e}")
    
    @retry_network(max_attempts=3, timeout=30)
    async def query(self, promql: str, time: Optional[datetime] = None) -> List[MetricResult]:
        """Execute instant PromQL query."""
        params = {"query": promql}
        if time:
            params["time"] = time.timestamp()
        
        logger.debug(f"Executing Prometheus query: {promql}")
        
        data = await self._make_request("query", params)
        return self._parse_query_result(data)
    
    @retry_network(max_attempts=3, timeout=30)
    async def query_range(self, 
                         promql: str, 
                         start: datetime, 
                         end: datetime,
                         step: str = "15s") -> List[MetricResult]:
        """Execute range PromQL query."""
        params = {
            "query": promql,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step
        }
        
        logger.debug(f"Executing Prometheus range query: {promql} from {start} to {end}")
        
        data = await self._make_request("query_range", params)
        return self._parse_query_result(data)
    
    def _parse_query_result(self, data: Dict[str, Any]) -> List[MetricResult]:
        """Parse Prometheus query result."""
        result_type = data.get("resultType", "")
        result = data.get("result", [])
        
        metrics = []
        
        for item in result:
            metric_name = item.get("metric", {}).get("__name__", "")
            labels = {k: v for k, v in item.get("metric", {}).items() if k != "__name__"}
            
            if result_type == "vector":
                # Instant query result
                value_data = item.get("value", [])
                if len(value_data) >= 2:
                    timestamp = float(value_data[0])
                    value = float(value_data[1])
                    values = [TimeSeriesPoint(timestamp, value)]
                else:
                    values = []
            
            elif result_type == "matrix":
                # Range query result
                values = []
                for value_data in item.get("values", []):
                    if len(value_data) >= 2:
                        timestamp = float(value_data[0])
                        value = float(value_data[1])
                        values.append(TimeSeriesPoint(timestamp, value))
            
            else:
                values = []
            
            metrics.append(MetricResult(
                metric_name=metric_name,
                labels=labels,
                values=values,
                result_type=result_type
            ))
        
        return metrics
    
    async def get_metric_availability(self, 
                                    service: str, 
                                    start: datetime, 
                                    end: datetime) -> float:
        """Calculate service availability from up metric."""
        query = (PrometheusQuery("up")
                .filter("job", "=", service)
                .build())
        
        metrics = await self.query_range(query, start, end, "1m")
        
        if not metrics:
            return 0.0
        
        total_points = 0
        up_points = 0
        
        for metric in metrics:
            for point in metric.values:
                total_points += 1
                if point.value == 1:
                    up_points += 1
        
        if total_points == 0:
            return 0.0
        
        return (up_points / total_points) * 100
    
    async def get_error_rate(self, 
                           service: str, 
                           start: datetime, 
                           end: datetime) -> float:
        """Calculate error rate from HTTP status codes."""
        # Query for total requests
        total_query = (PrometheusQuery("http_requests_total")
                      .filter("job", "=", service)
                      .rate("5m")
                      .sum()
                      .build())
        
        # Query for error requests (4xx, 5xx)
        error_query = (PrometheusQuery("http_requests_total")
                      .filter("job", "=", service)
                      .filter("status", "=~", "4..|5..")
                      .rate("5m")
                      .sum()
                      .build())
        
        total_metrics = await self.query_range(total_query, start, end, "1m")
        error_metrics = await self.query_range(error_query, start, end, "1m")
        
        if not total_metrics:
            return 0.0
        
        total_rate = sum(p.value for m in total_metrics for p in m.values) / len([p for m in total_metrics for p in m.values])
        error_rate = sum(p.value for m in error_metrics for p in m.values) / len([p for m in error_metrics for p in m.values]) if error_metrics else 0
        
        if total_rate == 0:
            return 0.0
        
        return (error_rate / total_rate) * 100
    
    async def get_latency_percentile(self, 
                                   service: str, 
                                   percentile: float,
                                   start: datetime, 
                                   end: datetime) -> float:
        """Get latency percentile from histogram."""
        query = (PrometheusQuery("http_request_duration_seconds")
                .filter("job", "=", service)
                .quantile(percentile)
                .build())
        
        metrics = await self.query_range(query, start, end, "1m")
        
        if not metrics:
            return 0.0
        
        # Get average percentile value
        values = [p.value for m in metrics for p in m.values]
        return sum(values) / len(values) if values else 0.0
    
    async def get_throughput(self, 
                           service: str, 
                           start: datetime, 
                           end: datetime) -> float:
        """Get request throughput (requests per second)."""
        query = (PrometheusQuery("http_requests_total")
                .filter("job", "=", service)
                .rate("5m")
                .sum()
                .build())
        
        metrics = await self.query_range(query, start, end, "1m")
        
        if not metrics:
            return 0.0
        
        # Get average throughput
        values = [p.value for m in metrics for p in m.values]
        return sum(values) / len(values) if values else 0.0
    
    async def close(self):
        """Close the client session."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None


# Global client instance
_prometheus_client: Optional[PrometheusClient] = None


def get_prometheus_client() -> PrometheusClient:
    """Get the global Prometheus client instance."""
    global _prometheus_client
    if _prometheus_client is None:
        _prometheus_client = PrometheusClient()
    return _prometheus_client