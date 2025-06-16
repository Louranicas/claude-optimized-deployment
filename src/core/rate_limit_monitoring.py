"""
Rate Limiting Monitoring and Metrics

This module provides comprehensive monitoring and metrics collection
for the distributed rate limiting system.
"""

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as aioredis
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


@dataclass
class RateLimitMetric:
    """Individual rate limit metric entry."""
    timestamp: float
    endpoint: str
    scope: str
    algorithm: str
    identifier: str
    allowed: bool
    limit: int
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None
    user_tier: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class RateLimitSummary:
    """Summary statistics for rate limiting."""
    total_requests: int
    allowed_requests: int
    denied_requests: int
    denial_rate: float
    top_denied_endpoints: List[Tuple[str, int]]
    top_denied_ips: List[Tuple[str, int]]
    algorithm_usage: Dict[str, int]
    scope_usage: Dict[str, int]
    avg_remaining_quota: float
    peak_request_time: Optional[str] = None


class RateLimitMonitor:
    """Monitor and collect rate limiting metrics."""
    
    def __init__(
        self,
        redis: Redis,
        metrics_key_prefix: str = "rate_limit_metrics",
        retention_days: int = 7,
        batch_size: int = 100
    ):
        self.redis = redis
        self.metrics_key_prefix = metrics_key_prefix
        self.retention_seconds = retention_days * 86400
        self.batch_size = batch_size
        
        # In-memory metrics buffer
        self.metrics_buffer: List[RateLimitMetric] = []
        self.buffer_lock = asyncio.Lock()
        
        # Background task for metric persistence
        self._background_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
    
    async def start(self):
        """Start background metric collection."""
        if self._background_task is None:
            self._background_task = asyncio.create_task(self._background_worker())
            logger.info("Rate limit monitoring started")
    
    async def stop(self):
        """Stop background metric collection."""
        self._shutdown_event.set()
        if self._background_task:
            await self._background_task
            self._background_task = None
        
        # Flush remaining metrics
        await self._flush_metrics()
        logger.info("Rate limit monitoring stopped")
    
    async def record_metric(
        self,
        endpoint: str,
        scope: str,
        algorithm: str,
        identifier: str,
        allowed: bool,
        limit: int,
        remaining: int,
        reset_time: float,
        retry_after: Optional[int] = None,
        user_tier: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Record a rate limiting metric."""
        metric = RateLimitMetric(
            timestamp=time.time(),
            endpoint=endpoint,
            scope=scope,
            algorithm=algorithm,
            identifier=identifier,
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=retry_after,
            user_tier=user_tier,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        async with self.buffer_lock:
            self.metrics_buffer.append(metric)
            
            # Flush if buffer is full
            if len(self.metrics_buffer) >= self.batch_size:
                await self._flush_metrics()
    
    async def _flush_metrics(self):
        """Flush metrics buffer to Redis."""
        if not self.metrics_buffer:
            return
        
        try:
            async with self.buffer_lock:
                metrics_to_flush = self.metrics_buffer.copy()
                self.metrics_buffer.clear()
            
            # Prepare Redis pipeline
            async with self.redis.pipeline() as pipe:
                for metric in metrics_to_flush:
                    # Store metric in time-series format
                    metric_key = f"{self.metrics_key_prefix}:timeseries"
                    metric_data = json.dumps(asdict(metric))
                    
                    # Add to sorted set with timestamp as score
                    await pipe.zadd(metric_key, {metric_data: metric.timestamp})
                
                # Set expiration on the main key
                await pipe.expire(f"{self.metrics_key_prefix}:timeseries", self.retention_seconds)
                
                # Update counters
                await self._update_counters(pipe, metrics_to_flush)
                
                # Execute pipeline
                await pipe.execute()
                
            logger.debug(f"Flushed {len(metrics_to_flush)} rate limit metrics to Redis")
            
        except Exception as e:
            logger.error(f"Failed to flush rate limit metrics: {e}")
            # Re-add metrics to buffer on failure
            async with self.buffer_lock:
                self.metrics_buffer.extend(metrics_to_flush)
    
    async def _update_counters(self, pipe, metrics: List[RateLimitMetric]):
        """Update aggregated counters in Redis."""
        # Global counters
        total_requests = len(metrics)
        allowed_requests = sum(1 for m in metrics if m.allowed)
        denied_requests = total_requests - allowed_requests
        
        await pipe.hincrby(f"{self.metrics_key_prefix}:counters", "total_requests", total_requests)
        await pipe.hincrby(f"{self.metrics_key_prefix}:counters", "allowed_requests", allowed_requests)
        await pipe.hincrby(f"{self.metrics_key_prefix}:counters", "denied_requests", denied_requests)
        
        # Per-endpoint counters
        endpoint_stats = {}
        ip_stats = {}
        algorithm_stats = {}
        scope_stats = {}
        
        for metric in metrics:
            # Endpoint stats
            if not metric.allowed:
                endpoint_stats[metric.endpoint] = endpoint_stats.get(metric.endpoint, 0) + 1
                if metric.ip_address:
                    ip_stats[metric.ip_address] = ip_stats.get(metric.ip_address, 0) + 1
            
            # Algorithm and scope usage
            algorithm_stats[metric.algorithm] = algorithm_stats.get(metric.algorithm, 0) + 1
            scope_stats[metric.scope] = scope_stats.get(metric.scope, 0) + 1
        
        # Update Redis counters
        if endpoint_stats:
            await pipe.zincrby(f"{self.metrics_key_prefix}:denied_endpoints", 1, list(endpoint_stats.keys())[0])
        
        if ip_stats:
            await pipe.zincrby(f"{self.metrics_key_prefix}:denied_ips", 1, list(ip_stats.keys())[0])
        
        # Set expiration on counter keys
        await pipe.expire(f"{self.metrics_key_prefix}:counters", self.retention_seconds)
        await pipe.expire(f"{self.metrics_key_prefix}:denied_endpoints", self.retention_seconds)
        await pipe.expire(f"{self.metrics_key_prefix}:denied_ips", self.retention_seconds)
    
    async def _background_worker(self):
        """Background worker for periodic metric flushing."""
        try:
            while not self._shutdown_event.is_set():
                # Wait for flush interval or shutdown
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=10.0)
                    break  # Shutdown requested
                except asyncio.TimeoutError:
                    pass  # Continue with flush
                
                # Flush metrics
                await self._flush_metrics()
                
                # Clean old metrics
                await self._cleanup_old_metrics()
                
        except Exception as e:
            logger.error(f"Rate limit monitoring background worker error: {e}")
    
    async def _cleanup_old_metrics(self):
        """Remove old metrics beyond retention period."""
        try:
            cutoff_time = time.time() - self.retention_seconds
            
            # Remove old timeseries data
            await self.redis.zremrangebyscore(
                f"{self.metrics_key_prefix}:timeseries",
                0, cutoff_time
            )
            
            logger.debug("Cleaned up old rate limit metrics")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old metrics: {e}")
    
    async def get_metrics_summary(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None
    ) -> RateLimitSummary:
        """Get summary of rate limiting metrics."""
        try:
            # Default to last hour if no time range specified
            if end_time is None:
                end_time = time.time()
            if start_time is None:
                start_time = end_time - 3600  # Last hour
            
            # Get metrics from time range
            metrics_data = await self.redis.zrangebyscore(
                f"{self.metrics_key_prefix}:timeseries",
                start_time, end_time
            )
            
            if not metrics_data:
                return RateLimitSummary(
                    total_requests=0,
                    allowed_requests=0,
                    denied_requests=0,
                    denial_rate=0.0,
                    top_denied_endpoints=[],
                    top_denied_ips=[],
                    algorithm_usage={},
                    scope_usage={},
                    avg_remaining_quota=0.0
                )
            
            # Parse metrics
            metrics = []
            for data in metrics_data:
                try:
                    metric_dict = json.loads(data)
                    metrics.append(RateLimitMetric(**metric_dict))
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse metric data: {e}")
                    continue
            
            # Calculate summary statistics
            total_requests = len(metrics)
            allowed_requests = sum(1 for m in metrics if m.allowed)
            denied_requests = total_requests - allowed_requests
            denial_rate = denied_requests / total_requests if total_requests > 0 else 0.0
            
            # Top denied endpoints and IPs
            denied_endpoints = {}
            denied_ips = {}
            algorithm_usage = {}
            scope_usage = {}
            remaining_quotas = []
            
            for metric in metrics:
                if not metric.allowed:
                    denied_endpoints[metric.endpoint] = denied_endpoints.get(metric.endpoint, 0) + 1
                    if metric.ip_address:
                        denied_ips[metric.ip_address] = denied_ips.get(metric.ip_address, 0) + 1
                
                algorithm_usage[metric.algorithm] = algorithm_usage.get(metric.algorithm, 0) + 1
                scope_usage[metric.scope] = scope_usage.get(metric.scope, 0) + 1
                remaining_quotas.append(metric.remaining)
            
            # Sort and get top items
            top_denied_endpoints = sorted(denied_endpoints.items(), key=lambda x: x[1], reverse=True)[:10]
            top_denied_ips = sorted(denied_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Calculate average remaining quota
            avg_remaining_quota = sum(remaining_quotas) / len(remaining_quotas) if remaining_quotas else 0.0
            
            return RateLimitSummary(
                total_requests=total_requests,
                allowed_requests=allowed_requests,
                denied_requests=denied_requests,
                denial_rate=denial_rate,
                top_denied_endpoints=top_denied_endpoints,
                top_denied_ips=top_denied_ips,
                algorithm_usage=algorithm_usage,
                scope_usage=scope_usage,
                avg_remaining_quota=avg_remaining_quota
            )
            
        except Exception as e:
            logger.error(f"Failed to get metrics summary: {e}")
            return RateLimitSummary(
                total_requests=0,
                allowed_requests=0,
                denied_requests=0,
                denial_rate=0.0,
                top_denied_endpoints=[],
                top_denied_ips=[],
                algorithm_usage={},
                scope_usage={},
                avg_remaining_quota=0.0
            )
    
    async def get_endpoint_metrics(
        self,
        endpoint: str,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get detailed metrics for a specific endpoint."""
        try:
            end_time = time.time()
            start_time = end_time - (hours * 3600)
            
            # Get all metrics for the time range
            metrics_data = await self.redis.zrangebyscore(
                f"{self.metrics_key_prefix}:timeseries",
                start_time, end_time
            )
            
            # Filter for the specific endpoint
            endpoint_metrics = []
            for data in metrics_data:
                try:
                    metric_dict = json.loads(data)
                    if metric_dict.get('endpoint') == endpoint:
                        endpoint_metrics.append(RateLimitMetric(**metric_dict))
                except (json.JSONDecodeError, TypeError):
                    continue
            
            if not endpoint_metrics:
                return {
                    'endpoint': endpoint,
                    'total_requests': 0,
                    'allowed_requests': 0,
                    'denied_requests': 0,
                    'denial_rate': 0.0,
                    'hourly_breakdown': [],
                    'top_denied_ips': []
                }
            
            # Calculate statistics
            total_requests = len(endpoint_metrics)
            allowed_requests = sum(1 for m in endpoint_metrics if m.allowed)
            denied_requests = total_requests - allowed_requests
            denial_rate = denied_requests / total_requests if total_requests > 0 else 0.0
            
            # Hourly breakdown
            hourly_stats = {}
            denied_ips = {}
            
            for metric in endpoint_metrics:
                hour = int(metric.timestamp // 3600) * 3600
                if hour not in hourly_stats:
                    hourly_stats[hour] = {'total': 0, 'allowed': 0, 'denied': 0}
                
                hourly_stats[hour]['total'] += 1
                if metric.allowed:
                    hourly_stats[hour]['allowed'] += 1
                else:
                    hourly_stats[hour]['denied'] += 1
                    if metric.ip_address:
                        denied_ips[metric.ip_address] = denied_ips.get(metric.ip_address, 0) + 1
            
            # Format hourly breakdown
            hourly_breakdown = [
                {
                    'hour': datetime.fromtimestamp(hour).isoformat(),
                    'total': stats['total'],
                    'allowed': stats['allowed'],
                    'denied': stats['denied'],
                    'denial_rate': stats['denied'] / stats['total'] if stats['total'] > 0 else 0.0
                }
                for hour, stats in sorted(hourly_stats.items())
            ]
            
            # Top denied IPs
            top_denied_ips = sorted(denied_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'endpoint': endpoint,
                'total_requests': total_requests,
                'allowed_requests': allowed_requests,
                'denied_requests': denied_requests,
                'denial_rate': denial_rate,
                'hourly_breakdown': hourly_breakdown,
                'top_denied_ips': top_denied_ips
            }
            
        except Exception as e:
            logger.error(f"Failed to get endpoint metrics for {endpoint}: {e}")
            return {
                'endpoint': endpoint,
                'error': str(e)
            }
    
    async def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time rate limiting statistics."""
        try:
            # Get last 5 minutes of metrics
            end_time = time.time()
            start_time = end_time - 300  # 5 minutes
            
            metrics_data = await self.redis.zrangebyscore(
                f"{self.metrics_key_prefix}:timeseries",
                start_time, end_time
            )
            
            if not metrics_data:
                return {
                    'requests_per_minute': 0,
                    'denial_rate': 0.0,
                    'active_algorithms': [],
                    'active_scopes': [],
                    'timestamp': end_time
                }
            
            metrics = []
            for data in metrics_data:
                try:
                    metric_dict = json.loads(data)
                    metrics.append(RateLimitMetric(**metric_dict))
                except (json.JSONDecodeError, TypeError):
                    continue
            
            total_requests = len(metrics)
            denied_requests = sum(1 for m in metrics if not m.allowed)
            denial_rate = denied_requests / total_requests if total_requests > 0 else 0.0
            
            # Requests per minute
            requests_per_minute = total_requests / 5.0  # 5-minute window
            
            # Active algorithms and scopes
            active_algorithms = list(set(m.algorithm for m in metrics))
            active_scopes = list(set(m.scope for m in metrics))
            
            return {
                'requests_per_minute': requests_per_minute,
                'denial_rate': denial_rate,
                'active_algorithms': active_algorithms,
                'active_scopes': active_scopes,
                'timestamp': end_time
            }
            
        except Exception as e:
            logger.error(f"Failed to get real-time stats: {e}")
            return {
                'error': str(e),
                'timestamp': time.time()
            }