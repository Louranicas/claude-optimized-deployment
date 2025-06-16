"""
MCP Performance Optimization Module
Agent 7: Comprehensive performance optimization for MCP servers.

This module implements advanced performance optimizations including:
- Intelligent caching strategies
- Connection pooling and reuse
- Resource monitoring and management
- Startup optimization
- Load balancing and scaling recommendations
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import psutil
import threading
from contextlib import asynccontextmanager

from ..core.mcp_cache import get_mcp_cache, get_tool_cache, CacheConfig, CacheStrategy
from ..core.connections import get_connection_manager, ConnectionPoolConfig
from ..core.circuit_breaker import get_circuit_breaker_manager, CircuitBreakerConfig
from ..monitoring.metrics import get_metrics_collector
from .protocols import MCPTool, MCPError
from .manager import MCPManager, MCPContext, MCPToolCall

logger = logging.getLogger(__name__)


@dataclass
class PerformanceConfig:
    """Configuration for MCP performance optimizations."""
    # Caching configuration
    enable_caching: bool = True
    cache_strategy: CacheStrategy = CacheStrategy.TTL_CACHE
    cache_size: int = 1000
    cache_ttl_seconds: float = 300.0
    
    # Connection pooling
    enable_pooling: bool = True
    max_connections_per_server: int = 20
    connection_timeout: int = 30
    
    # Circuit breaker settings
    enable_circuit_breaker: bool = True
    failure_threshold: int = 5
    circuit_timeout: float = 60.0
    
    # Startup optimization
    lazy_initialization: bool = True
    preload_servers: List[str] = field(default_factory=lambda: ["brave", "docker"])
    warmup_cache: bool = True
    
    # Resource monitoring
    memory_limit_mb: int = 500
    cpu_threshold: float = 80.0
    io_threshold_mb: int = 100
    
    # Performance tuning
    batch_size: int = 10
    concurrent_limit: int = 20
    request_queue_size: int = 100


@dataclass
class PerformanceMetrics:
    """Performance metrics for MCP operations."""
    total_requests: int = 0
    cached_requests: int = 0
    cache_hit_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    error_rate: float = 0.0
    concurrent_requests: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    throughput_rps: float = 0.0
    active_connections: int = 0
    failed_connections: int = 0
    circuit_breaker_trips: int = 0
    
    def update_response_time(self, duration_ms: float):
        """Update response time metrics."""
        if self.avg_response_time_ms == 0:
            self.avg_response_time_ms = duration_ms
        else:
            # Exponential moving average
            self.avg_response_time_ms = (
                self.avg_response_time_ms * 0.9 + duration_ms * 0.1
            )


class MCPPerformanceOptimizer:
    """
    Performance optimizer for MCP operations.
    
    Provides comprehensive performance optimizations including caching,
    connection pooling, resource management, and monitoring.
    """
    
    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or PerformanceConfig()
        self.metrics = PerformanceMetrics()
        
        # Performance tracking
        self._response_times = deque(maxlen=1000)
        self._request_timestamps = deque(maxlen=1000)
        self._resource_usage_history = deque(maxlen=100)
        
        # Optimization state
        self._cache = None
        self._tool_cache = None
        self._connection_manager = None
        self._circuit_breaker_manager = None
        self._metrics_collector = None
        
        # Monitoring tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._optimizer_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        # Request queue for batching
        self._request_queue = asyncio.Queue(maxsize=self.config.request_queue_size)
        self._batch_processor_task: Optional[asyncio.Task] = None
        
        # Performance locks
        self._metrics_lock = threading.Lock()
        self._optimization_lock = asyncio.Lock()
        
        # Server performance profiles
        self._server_profiles: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._tool_profiles: Dict[str, Dict[str, Any]] = defaultdict(dict)
    
    async def initialize(self):
        """Initialize performance optimization components."""
        if self._is_running:
            return
        
        logger.info("Initializing MCP Performance Optimizer...")
        
        # Initialize caching
        if self.config.enable_caching:
            self._cache = await get_mcp_cache()
            self._tool_cache = await get_tool_cache()
            logger.info("MCP caching initialized")
        
        # Initialize connection pooling
        if self.config.enable_pooling:
            pool_config = ConnectionPoolConfig(
                http_total_connections=self.config.max_connections_per_server,
                http_connect_timeout=self.config.connection_timeout
            )
            self._connection_manager = await get_connection_manager(pool_config)
            logger.info("Connection pooling initialized")
        
        # Initialize circuit breakers
        if self.config.enable_circuit_breaker:
            self._circuit_breaker_manager = get_circuit_breaker_manager()
            logger.info("Circuit breakers initialized")
        
        # Initialize metrics collection
        self._metrics_collector = get_metrics_collector()
        
        # Start background tasks
        self._is_running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._optimizer_task = asyncio.create_task(self._optimizer_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._batch_processor_task = asyncio.create_task(self._batch_processor())
        
        logger.info("MCP Performance Optimizer initialized successfully")
    
    async def optimize_tool_call(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[MCPContext] = None
    ) -> Any:
        """
        Execute optimized tool call with caching, pooling, and monitoring.
        """
        start_time = time.time()
        request_id = f"{server_name}.{tool_name}_{int(start_time * 1000)}"
        
        # Update concurrent request count
        self.metrics.concurrent_requests += 1
        
        try:
            # 1. Check cache first
            if self._tool_cache and self.config.enable_caching:
                cached_result = await self._tool_cache.get_tool_result(
                    server_name, tool_name, arguments
                )
                if cached_result is not None:
                    self.metrics.cached_requests += 1
                    self._record_request_metrics(time.time() - start_time, True)
                    return cached_result
            
            # 2. Apply circuit breaker protection
            circuit_breaker = None
            if self._circuit_breaker_manager and self.config.enable_circuit_breaker:
                breaker_config = CircuitBreakerConfig(
                    failure_threshold=self.config.failure_threshold,
                    timeout=self.config.circuit_timeout,
                    name=f"{server_name}_{tool_name}"
                )
                circuit_breaker = await self._circuit_breaker_manager.get_or_create(
                    f"{server_name}_{tool_name}", breaker_config
                )
            
            # 3. Execute with optimizations
            if circuit_breaker:
                result = await circuit_breaker.call(
                    self._execute_tool_with_pool,
                    server_name, tool_name, arguments, context
                )
            else:
                result = await self._execute_tool_with_pool(
                    server_name, tool_name, arguments, context
                )
            
            # 4. Cache successful results
            if self._tool_cache and self.config.enable_caching and result is not None:
                await self._tool_cache.cache_tool_result(
                    server_name, tool_name, arguments, result
                )
            
            # 5. Update performance profiles
            duration_ms = (time.time() - start_time) * 1000
            await self._update_performance_profiles(
                server_name, tool_name, duration_ms, True
            )
            
            self._record_request_metrics(duration_ms / 1000, False)
            return result
            
        except Exception as e:
            # Record error metrics
            duration_ms = (time.time() - start_time) * 1000
            await self._update_performance_profiles(
                server_name, tool_name, duration_ms, False
            )
            
            self._record_error_metrics()
            
            # Log with metrics
            if self._metrics_collector:
                self._metrics_collector.record_mcp_tool_call(
                    server_name, tool_name, "error", duration_ms / 1000
                )
            
            raise
        
        finally:
            self.metrics.concurrent_requests -= 1
    
    async def _execute_tool_with_pool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[MCPContext]
    ) -> Any:
        """Execute tool call with connection pooling optimization."""
        # Get MCP manager instance (simplified for this example)
        from .manager import get_mcp_manager
        manager = get_mcp_manager()
        
        # Execute with connection pooling if available
        if self._connection_manager:
            # For HTTP-based MCP servers, use pooled connections
            # This would be implemented based on the specific server type
            pass
        
        # Standard execution
        return await manager.call_tool(
            f"{server_name}.{tool_name}",
            arguments,
            context.query.id if context and context.query else None
        )
    
    async def batch_tool_calls(
        self,
        calls: List[Tuple[str, str, Dict[str, Any]]],
        context: Optional[MCPContext] = None
    ) -> List[Any]:
        """
        Execute multiple tool calls in optimized batches.
        """
        if len(calls) <= self.config.batch_size:
            # Small batch - execute concurrently
            tasks = [
                self.optimize_tool_call(server, tool, args, context)
                for server, tool, args in calls
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)
        
        # Large batch - process in chunks
        results = []
        for i in range(0, len(calls), self.config.batch_size):
            batch = calls[i:i + self.config.batch_size]
            batch_tasks = [
                self.optimize_tool_call(server, tool, args, context)
                for server, tool, args in batch
            ]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)
            
            # Small delay between batches to prevent overwhelming
            await asyncio.sleep(0.1)
        
        return results
    
    async def optimize_server_startup(self, server_names: List[str]) -> Dict[str, bool]:
        """
        Optimize server startup with preloading and warmup.
        """
        logger.info(f"Optimizing startup for servers: {server_names}")
        
        results = {}
        
        # Lazy initialization for non-critical servers
        critical_servers = set(self.config.preload_servers)
        
        # Start critical servers first
        for server_name in server_names:
            if server_name in critical_servers:
                try:
                    # Initialize server immediately
                    await self._initialize_server(server_name)
                    results[server_name] = True
                    logger.info(f"Preloaded critical server: {server_name}")
                except Exception as e:
                    logger.error(f"Failed to preload {server_name}: {e}")
                    results[server_name] = False
        
        # Schedule lazy initialization for others
        for server_name in server_names:
            if server_name not in critical_servers:
                # Mark for lazy initialization
                results[server_name] = "lazy"
        
        # Warm up cache if enabled
        if self.config.warmup_cache and self._cache:
            await self._warmup_cache(server_names)
        
        return results
    
    async def _initialize_server(self, server_name: str):
        """Initialize a specific MCP server."""
        # Implementation would depend on the MCP manager
        # This is a placeholder for the actual initialization logic
        pass
    
    async def _warmup_cache(self, server_names: List[str]):
        """Warm up cache with frequently used data."""
        if not self._cache:
            return
        
        warmup_data = {
            # Common tool metadata
            "tools:brave": {"web_search": {"avg_time": 1.2}, "news_search": {"avg_time": 0.8}},
            "tools:docker": {"ps": {"avg_time": 0.3}, "images": {"avg_time": 0.5}},
            "tools:kubernetes": {"get_pods": {"avg_time": 0.7}, "get_nodes": {"avg_time": 0.4}},
            
            # Server capabilities
            "capabilities:brave": {"search": True, "local": True, "news": True},
            "capabilities:docker": {"containers": True, "images": True, "volumes": True},
        }
        
        await self._cache.warm_up(warmup_data)
        logger.info(f"Cache warmed up with {len(warmup_data)} entries")
    
    def _record_request_metrics(self, duration: float, from_cache: bool):
        """Record request performance metrics."""
        with self._metrics_lock:
            self.metrics.total_requests += 1
            
            duration_ms = duration * 1000
            self._response_times.append(duration_ms)
            self._request_timestamps.append(time.time())
            
            # Update response time metrics
            self.metrics.update_response_time(duration_ms)
            
            # Update cache hit rate
            if from_cache:
                self.metrics.cached_requests += 1
            
            total_requests = self.metrics.total_requests
            self.metrics.cache_hit_rate = (
                self.metrics.cached_requests / total_requests
            ) if total_requests > 0 else 0.0
            
            # Calculate percentiles if we have enough data
            if len(self._response_times) >= 10:
                sorted_times = sorted(self._response_times)
                self.metrics.p95_response_time_ms = sorted_times[int(len(sorted_times) * 0.95)]
                self.metrics.p99_response_time_ms = sorted_times[int(len(sorted_times) * 0.99)]
            
            # Calculate throughput (requests per second over last minute)
            now = time.time()
            recent_requests = [
                ts for ts in self._request_timestamps 
                if now - ts <= 60
            ]
            self.metrics.throughput_rps = len(recent_requests) / 60.0
    
    def _record_error_metrics(self):
        """Record error metrics."""
        with self._metrics_lock:
            # Update error rate
            total = self.metrics.total_requests
            if total > 0:
                error_count = total - (self.metrics.total_requests - 1)  # Simplified
                self.metrics.error_rate = error_count / total
    
    async def _update_performance_profiles(
        self,
        server_name: str,
        tool_name: str,
        duration_ms: float,
        success: bool
    ):
        """Update performance profiles for servers and tools."""
        async with self._optimization_lock:
            # Update server profile
            server_profile = self._server_profiles[server_name]
            if "avg_response_time" not in server_profile:
                server_profile["avg_response_time"] = duration_ms
                server_profile["request_count"] = 1
                server_profile["success_count"] = 1 if success else 0
            else:
                # Exponential moving average
                server_profile["avg_response_time"] = (
                    server_profile["avg_response_time"] * 0.9 + duration_ms * 0.1
                )
                server_profile["request_count"] += 1
                if success:
                    server_profile["success_count"] += 1
            
            # Update tool profile
            tool_key = f"{server_name}.{tool_name}"
            tool_profile = self._tool_profiles[tool_key]
            if "avg_response_time" not in tool_profile:
                tool_profile["avg_response_time"] = duration_ms
                tool_profile["request_count"] = 1
                tool_profile["success_count"] = 1 if success else 0
            else:
                tool_profile["avg_response_time"] = (
                    tool_profile["avg_response_time"] * 0.9 + duration_ms * 0.1
                )
                tool_profile["request_count"] += 1
                if success:
                    tool_profile["success_count"] += 1
    
    async def _monitor_loop(self):
        """Background monitoring loop."""
        while self._is_running:
            try:
                await asyncio.sleep(10)  # Monitor every 10 seconds
                await self._collect_system_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            # Memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.metrics.memory_usage_mb = memory_mb
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.metrics.cpu_usage_percent = cpu_percent
            
            # Connection metrics
            if self._connection_manager:
                conn_metrics = self._connection_manager.get_all_metrics()
                total_active = sum(
                    sum(m.active_connections for m in pool_metrics.values())
                    for pool_metrics in conn_metrics.values()
                )
                total_failed = sum(
                    sum(m.failed_connections for m in pool_metrics.values())
                    for pool_metrics in conn_metrics.values()
                )
                self.metrics.active_connections = total_active
                self.metrics.failed_connections = total_failed
            
            # Circuit breaker metrics
            if self._circuit_breaker_manager:
                breaker_summary = self._circuit_breaker_manager.get_summary()
                self.metrics.circuit_breaker_trips = len(breaker_summary.get("open_circuits", []))
            
            # Store resource usage history
            self._resource_usage_history.append({
                "timestamp": time.time(),
                "memory_mb": memory_mb,
                "cpu_percent": cpu_percent
            })
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    async def _optimizer_loop(self):
        """Background optimization loop."""
        while self._is_running:
            try:
                await asyncio.sleep(60)  # Optimize every minute
                await self._auto_optimize()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Optimizer loop error: {e}")
    
    async def _auto_optimize(self):
        """Automatic performance optimization based on metrics."""
        # Check memory usage
        if self.metrics.memory_usage_mb > self.config.memory_limit_mb * 0.8:
            logger.warning(f"High memory usage: {self.metrics.memory_usage_mb:.1f} MB")
            
            # Trigger cache cleanup
            if self._cache:
                cleaned = await self._cache._cleanup_expired()
                logger.info(f"Cleaned {cleaned} expired cache entries")
        
        # Check error rate
        if self.metrics.error_rate > 0.1:  # 10% error rate
            logger.warning(f"High error rate: {self.metrics.error_rate:.2%}")
            
            # Could trigger circuit breaker adjustments or server health checks
        
        # Check response times
        if self.metrics.avg_response_time_ms > 5000:  # 5 second average
            logger.warning(f"High response times: {self.metrics.avg_response_time_ms:.1f} ms")
            
            # Could trigger connection pool adjustments or caching optimization
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._is_running:
            try:
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                await self._cleanup_resources()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    async def _cleanup_resources(self):
        """Clean up resources and expired data."""
        # Clean up old response times
        cutoff_time = time.time() - 3600  # Keep last hour
        while self._request_timestamps and self._request_timestamps[0] < cutoff_time:
            self._request_timestamps.popleft()
            if self._response_times:
                self._response_times.popleft()
        
        # Clean up resource usage history
        if len(self._resource_usage_history) > 100:
            # Keep only last 100 entries
            for _ in range(len(self._resource_usage_history) - 100):
                self._resource_usage_history.popleft()
    
    async def _batch_processor(self):
        """Process batched requests for optimization."""
        batch = []
        last_process_time = time.time()
        
        while self._is_running:
            try:
                # Wait for requests or timeout
                try:
                    request = await asyncio.wait_for(
                        self._request_queue.get(), timeout=1.0
                    )
                    batch.append(request)
                except asyncio.TimeoutError:
                    pass
                
                # Process batch if it's full or enough time has passed
                current_time = time.time()
                should_process = (
                    len(batch) >= self.config.batch_size or
                    (batch and current_time - last_process_time > 1.0)
                )
                
                if should_process and batch:
                    await self._process_batch(batch)
                    batch.clear()
                    last_process_time = current_time
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Batch processor error: {e}")
    
    async def _process_batch(self, batch: List[Any]):
        """Process a batch of requests."""
        # Implementation would depend on the specific batch processing logic
        # This is a placeholder for batch optimization
        pass
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        return {
            "summary": {
                "total_requests": self.metrics.total_requests,
                "cache_hit_rate": f"{self.metrics.cache_hit_rate:.2%}",
                "avg_response_time_ms": f"{self.metrics.avg_response_time_ms:.1f}",
                "error_rate": f"{self.metrics.error_rate:.2%}",
                "throughput_rps": f"{self.metrics.throughput_rps:.1f}",
                "memory_usage_mb": f"{self.metrics.memory_usage_mb:.1f}",
                "cpu_usage_percent": f"{self.metrics.cpu_usage_percent:.1f}%"
            },
            "response_times": {
                "average_ms": self.metrics.avg_response_time_ms,
                "p95_ms": self.metrics.p95_response_time_ms,
                "p99_ms": self.metrics.p99_response_time_ms
            },
            "caching": {
                "total_requests": self.metrics.total_requests,
                "cached_requests": self.metrics.cached_requests,
                "hit_rate": self.metrics.cache_hit_rate,
                "cache_stats": self._cache.get_stats() if self._cache else {}
            },
            "connections": {
                "active": self.metrics.active_connections,
                "failed": self.metrics.failed_connections,
                "pool_stats": (
                    self._connection_manager.get_all_metrics() 
                    if self._connection_manager else {}
                )
            },
            "circuit_breakers": {
                "trips": self.metrics.circuit_breaker_trips,
                "summary": (
                    self._circuit_breaker_manager.get_summary()
                    if self._circuit_breaker_manager else {}
                )
            },
            "server_profiles": dict(self._server_profiles),
            "tool_profiles": dict(self._tool_profiles),
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # Cache hit rate recommendations
        if self.metrics.cache_hit_rate < 0.3:  # Less than 30%
            recommendations.append(
                "Low cache hit rate detected. Consider increasing cache TTL or size."
            )
        
        # Response time recommendations
        if self.metrics.avg_response_time_ms > 2000:  # Over 2 seconds
            recommendations.append(
                "High response times detected. Consider optimizing slow tools or increasing concurrency."
            )
        
        # Memory recommendations
        if self.metrics.memory_usage_mb > self.config.memory_limit_mb * 0.8:
            recommendations.append(
                "High memory usage detected. Consider reducing cache size or implementing more aggressive cleanup."
            )
        
        # Error rate recommendations
        if self.metrics.error_rate > 0.05:  # Over 5%
            recommendations.append(
                "High error rate detected. Check server health and consider adjusting circuit breaker settings."
            )
        
        # Throughput recommendations
        if self.metrics.throughput_rps < 1.0:  # Less than 1 RPS
            recommendations.append(
                "Low throughput detected. Consider optimizing request batching or connection pooling."
            )
        
        return recommendations
    
    async def shutdown(self):
        """Shutdown performance optimizer and cleanup resources."""
        logger.info("Shutting down MCP Performance Optimizer...")
        
        self._is_running = False
        
        # Cancel background tasks
        for task in [self._monitor_task, self._optimizer_task, self._cleanup_task, self._batch_processor_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Shutdown components
        if self._cache:
            await self._cache.shutdown()
        
        if self._connection_manager:
            await self._connection_manager.close()
        
        logger.info("MCP Performance Optimizer shutdown complete")


# Global performance optimizer instance
_performance_optimizer: Optional[MCPPerformanceOptimizer] = None


async def get_performance_optimizer(
    config: Optional[PerformanceConfig] = None
) -> MCPPerformanceOptimizer:
    """Get the global performance optimizer instance."""
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = MCPPerformanceOptimizer(config)
        await _performance_optimizer.initialize()
    return _performance_optimizer


__all__ = [
    "PerformanceConfig",
    "PerformanceMetrics", 
    "MCPPerformanceOptimizer",
    "get_performance_optimizer"
]