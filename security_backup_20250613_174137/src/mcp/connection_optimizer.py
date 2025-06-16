"""
MCP Connection Optimization Module
Agent 7: Advanced connection pooling and resource management for MCP servers.

This module provides optimized connection management specifically designed for MCP
server operations, including intelligent pooling, load balancing, and failover.
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Optional, Union, Callable, TypeVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from enum import Enum
import threading
import weakref
import random

from ..core.connections import ConnectionPoolManager, ConnectionPoolConfig, ConnectionMetrics
from ..core.circuit_breaker import get_circuit_breaker_manager, CircuitBreakerConfig
from .protocols import MCPTool, MCPError, MCPServerInfo

logger = logging.getLogger(__name__)

T = TypeVar('T')


class LoadBalancingStrategy(Enum):
    """Load balancing strategies for MCP connections."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_RANDOM = "weighted_random"
    RESPONSE_TIME = "response_time"
    ADAPTIVE = "adaptive"


class ConnectionHealth(Enum):
    """Connection health states."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class MCPConnectionConfig:
    """Configuration for MCP connection optimization."""
    # Pool settings
    max_connections_per_server: int = 20
    min_connections_per_server: int = 2
    connection_timeout: float = 30.0
    idle_timeout: float = 300.0
    
    # Load balancing
    load_balancing_strategy: LoadBalancingStrategy = LoadBalancingStrategy.ADAPTIVE
    health_check_interval: float = 30.0
    failover_enabled: bool = True
    
    # Connection optimization
    keep_alive_enabled: bool = True
    connection_prewarming: bool = True
    retry_attempts: int = 3
    retry_backoff: float = 1.0
    
    # Performance tuning
    batch_request_size: int = 10
    concurrent_request_limit: int = 50
    request_queue_size: int = 100
    
    # Monitoring
    enable_metrics: bool = True
    metrics_collection_interval: float = 10.0


@dataclass
class ServerEndpoint:
    """Represents an MCP server endpoint."""
    name: str
    url: Optional[str] = None
    weight: float = 1.0
    priority: int = 0
    health: ConnectionHealth = ConnectionHealth.UNKNOWN
    last_health_check: Optional[datetime] = None
    response_time_ms: float = 0.0
    active_connections: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    
    def get_success_rate(self) -> float:
        """Calculate success rate for this endpoint."""
        if self.total_requests == 0:
            return 1.0
        return 1.0 - (self.failed_requests / self.total_requests)
    
    def get_load_score(self) -> float:
        """Calculate load score for load balancing."""
        base_score = self.active_connections / max(self.weight, 0.1)
        
        # Adjust based on health
        if self.health == ConnectionHealth.UNHEALTHY:
            return float('inf')
        elif self.health == ConnectionHealth.DEGRADED:
            base_score *= 2.0
        
        # Adjust based on response time
        if self.response_time_ms > 0:
            base_score *= (1.0 + self.response_time_ms / 1000.0)
        
        return base_score


@dataclass
class ConnectionPoolMetrics:
    """Metrics for MCP connection pools."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    avg_response_time_ms: float = 0.0
    success_rate: float = 1.0
    pool_utilization: float = 0.0
    queue_size: int = 0
    created_at: datetime = field(default_factory=datetime.now)


class MCPConnectionPool:
    """
    Optimized connection pool for MCP server operations.
    
    Features:
    - Multiple endpoints with load balancing
    - Health monitoring and failover
    - Connection reuse and optimization
    - Intelligent retry logic
    - Performance monitoring
    """
    
    def __init__(self, server_name: str, config: MCPConnectionConfig):
        self.server_name = server_name
        self.config = config
        
        # Endpoint management
        self._endpoints: List[ServerEndpoint] = []
        self._endpoint_index = 0  # For round-robin
        self._endpoint_lock = asyncio.Lock()
        
        # Connection pools
        self._connection_pools: Dict[str, ConnectionPoolManager] = {}
        self._pool_lock = asyncio.Lock()
        
        # Request queue and processing
        self._request_queue = asyncio.Queue(maxsize=config.request_queue_size)
        self._active_requests: Dict[str, asyncio.Task] = {}
        self._request_processors: List[asyncio.Task] = []
        
        # Health monitoring
        self._health_check_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        # Performance tracking
        self._metrics = ConnectionPoolMetrics()
        self._response_times: deque = deque(maxlen=1000)
        self._connection_history: deque = deque(maxlen=100)
        
        # Circuit breaker integration
        self._circuit_breaker_manager = None
    
    async def initialize(self):
        """Initialize the connection pool."""
        if self._is_running:
            return
        
        logger.info(f"Initializing MCP connection pool for {self.server_name}")
        
        # Initialize circuit breaker manager
        self._circuit_breaker_manager = get_circuit_breaker_manager()
        
        # Start background tasks
        self._is_running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        if self.config.enable_metrics:
            self._metrics_task = asyncio.create_task(self._metrics_loop())
        
        # Start request processors
        for i in range(min(5, self.config.concurrent_request_limit)):
            processor = asyncio.create_task(self._request_processor())
            self._request_processors.append(processor)
        
        logger.info(f"MCP connection pool for {self.server_name} initialized")
    
    def add_endpoint(
        self,
        name: str,
        url: Optional[str] = None,
        weight: float = 1.0,
        priority: int = 0
    ):
        """Add an endpoint to the pool."""
        endpoint = ServerEndpoint(
            name=name,
            url=url,
            weight=weight,
            priority=priority
        )
        self._endpoints.append(endpoint)
        
        # Sort endpoints by priority (higher priority first)
        self._endpoints.sort(key=lambda e: e.priority, reverse=True)
        
        logger.info(f"Added endpoint {name} to pool {self.server_name}")
    
    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """
        Execute a tool call with optimized connection management.
        """
        request_id = f"{tool_name}_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
        start_time = time.time()
        
        try:
            # Create request for queue processing
            request = {
                "id": request_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "timeout": timeout or self.config.connection_timeout,
                "start_time": start_time,
                "future": asyncio.Future()
            }
            
            # Add to queue
            await self._request_queue.put(request)
            
            # Wait for result
            result = await request["future"]
            
            # Record metrics
            duration_ms = (time.time() - start_time) * 1000
            self._record_success(duration_ms)
            
            return result
            
        except Exception as e:
            # Record failure
            duration_ms = (time.time() - start_time) * 1000
            self._record_failure(duration_ms)
            
            logger.error(f"Tool execution failed for {tool_name}: {e}")
            raise
    
    async def _request_processor(self):
        """Process requests from the queue."""
        while self._is_running:
            try:
                # Get request from queue
                request = await asyncio.wait_for(
                    self._request_queue.get(),
                    timeout=1.0
                )
                
                # Process request
                task = asyncio.create_task(self._process_request(request))
                self._active_requests[request["id"]] = task
                
                # Clean up completed tasks periodically
                if len(self._active_requests) > 100:
                    await self._cleanup_completed_requests()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Request processor error: {e}")
    
    async def _process_request(self, request: Dict[str, Any]):
        """Process a single request with connection optimization."""
        request_id = request["id"]
        
        try:
            # Select optimal endpoint
            endpoint = await self._select_endpoint()
            if not endpoint:
                raise MCPError(-32000, "No healthy endpoints available")
            
            # Get circuit breaker for this endpoint
            circuit_breaker = await self._circuit_breaker_manager.get_or_create(
                f"{self.server_name}_{endpoint.name}",
                CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=30,
                    name=f"{self.server_name}_{endpoint.name}"
                )
            )
            
            # Execute with circuit breaker protection
            result = await circuit_breaker.call(
                self._execute_with_endpoint,
                endpoint,
                request["tool_name"],
                request["arguments"],
                request["timeout"]
            )
            
            # Set result
            if not request["future"].done():
                request["future"].set_result(result)
            
        except Exception as e:
            # Set exception
            if not request["future"].done():
                request["future"].set_exception(e)
        
        finally:
            # Clean up
            self._active_requests.pop(request_id, None)
    
    async def _execute_with_endpoint(
        self,
        endpoint: ServerEndpoint,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: float
    ) -> Any:
        """Execute tool call with a specific endpoint."""
        start_time = time.time()
        
        try:
            # Increment active connections
            endpoint.active_connections += 1
            endpoint.total_requests += 1
            
            # Get connection pool for this endpoint
            pool = await self._get_connection_pool(endpoint)
            
            # Execute the actual tool call
            # This would integrate with the actual MCP server implementation
            result = await self._execute_tool_call(
                pool, endpoint, tool_name, arguments, timeout
            )
            
            # Update endpoint metrics
            duration_ms = (time.time() - start_time) * 1000
            endpoint.response_time_ms = (
                endpoint.response_time_ms * 0.8 + duration_ms * 0.2
            )
            
            return result
            
        except Exception as e:
            endpoint.failed_requests += 1
            raise
        
        finally:
            endpoint.active_connections -= 1
    
    async def _execute_tool_call(
        self,
        pool: ConnectionPoolManager,
        endpoint: ServerEndpoint,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: float
    ) -> Any:
        """Execute the actual tool call (implementation specific)."""
        # This is a placeholder for the actual MCP tool execution
        # In practice, this would:
        # 1. Get a connection from the pool
        # 2. Send the MCP request
        # 3. Parse the response
        # 4. Return the result
        
        # For now, simulate the execution
        await asyncio.sleep(0.1)  # Simulate network delay
        
        return {
            "tool": tool_name,
            "result": f"Executed {tool_name} with {arguments}",
            "endpoint": endpoint.name,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _get_connection_pool(self, endpoint: ServerEndpoint) -> ConnectionPoolManager:
        """Get or create connection pool for endpoint."""
        async with self._pool_lock:
            if endpoint.name not in self._connection_pools:
                # Create new pool with optimized configuration
                pool_config = ConnectionPoolConfig(
                    http_total_connections=self.config.max_connections_per_server,
                    http_per_host_connections=self.config.max_connections_per_server,
                    http_connect_timeout=int(self.config.connection_timeout),
                    http_request_timeout=int(self.config.connection_timeout * 2),
                    http_keepalive_timeout=int(self.config.idle_timeout)
                )
                
                pool = await ConnectionPoolManager.get_instance(pool_config)
                self._connection_pools[endpoint.name] = pool
                
                logger.debug(f"Created connection pool for endpoint {endpoint.name}")
            
            return self._connection_pools[endpoint.name]
    
    async def _select_endpoint(self) -> Optional[ServerEndpoint]:
        """Select optimal endpoint based on load balancing strategy."""
        async with self._endpoint_lock:
            healthy_endpoints = [
                e for e in self._endpoints 
                if e.health != ConnectionHealth.UNHEALTHY
            ]
            
            if not healthy_endpoints:
                return None
            
            if self.config.load_balancing_strategy == LoadBalancingStrategy.ROUND_ROBIN:
                return self._select_round_robin(healthy_endpoints)
            elif self.config.load_balancing_strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
                return self._select_least_connections(healthy_endpoints)
            elif self.config.load_balancing_strategy == LoadBalancingStrategy.WEIGHTED_RANDOM:
                return self._select_weighted_random(healthy_endpoints)
            elif self.config.load_balancing_strategy == LoadBalancingStrategy.RESPONSE_TIME:
                return self._select_by_response_time(healthy_endpoints)
            elif self.config.load_balancing_strategy == LoadBalancingStrategy.ADAPTIVE:
                return self._select_adaptive(healthy_endpoints)
            else:
                return healthy_endpoints[0]
    
    def _select_round_robin(self, endpoints: List[ServerEndpoint]) -> ServerEndpoint:
        """Round-robin endpoint selection."""
        endpoint = endpoints[self._endpoint_index % len(endpoints)]
        self._endpoint_index += 1
        return endpoint
    
    def _select_least_connections(self, endpoints: List[ServerEndpoint]) -> ServerEndpoint:
        """Select endpoint with least active connections."""
        return min(endpoints, key=lambda e: e.active_connections / max(e.weight, 0.1))
    
    def _select_weighted_random(self, endpoints: List[ServerEndpoint]) -> ServerEndpoint:
        """Weighted random endpoint selection."""
        total_weight = sum(e.weight for e in endpoints)
        if total_weight == 0:
            return random.choice(endpoints)
        
        r = random.random() * total_weight
        cumulative = 0
        for endpoint in endpoints:
            cumulative += endpoint.weight
            if r <= cumulative:
                return endpoint
        
        return endpoints[-1]
    
    def _select_by_response_time(self, endpoints: List[ServerEndpoint]) -> ServerEndpoint:
        """Select endpoint with best response time."""
        return min(endpoints, key=lambda e: e.response_time_ms or float('inf'))
    
    def _select_adaptive(self, endpoints: List[ServerEndpoint]) -> ServerEndpoint:
        """Adaptive endpoint selection based on multiple factors."""
        scored_endpoints = []
        
        for endpoint in endpoints:
            # Calculate composite score
            load_score = endpoint.get_load_score()
            success_rate = endpoint.get_success_rate()
            response_time_factor = 1.0 + (endpoint.response_time_ms / 1000.0)
            
            # Lower score is better
            composite_score = load_score * response_time_factor / max(success_rate, 0.1)
            scored_endpoints.append((composite_score, endpoint))
        
        # Select endpoint with lowest score
        scored_endpoints.sort(key=lambda x: x[0])
        return scored_endpoints[0][1]
    
    async def _health_check_loop(self):
        """Background health checking for endpoints."""
        while self._is_running:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._check_endpoint_health()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _check_endpoint_health(self):
        """Check health of all endpoints."""
        for endpoint in self._endpoints:
            try:
                # Perform health check (implementation specific)
                is_healthy = await self._perform_health_check(endpoint)
                
                # Update health status
                old_health = endpoint.health
                if is_healthy:
                    endpoint.health = ConnectionHealth.HEALTHY
                else:
                    endpoint.health = ConnectionHealth.UNHEALTHY
                
                endpoint.last_health_check = datetime.now()
                
                # Log health changes
                if old_health != endpoint.health:
                    logger.info(f"Endpoint {endpoint.name} health changed: {old_health.value} -> {endpoint.health.value}")
                
            except Exception as e:
                logger.warning(f"Health check failed for endpoint {endpoint.name}: {e}")
                endpoint.health = ConnectionHealth.UNHEALTHY
    
    async def _perform_health_check(self, endpoint: ServerEndpoint) -> bool:
        """Perform health check on an endpoint."""
        try:
            # Simple health check - try to get server info
            # This would be implemented based on the specific MCP protocol
            
            # For now, simulate health check
            start_time = time.time()
            await asyncio.sleep(0.05)  # Simulate health check request
            
            # Update response time
            duration_ms = (time.time() - start_time) * 1000
            endpoint.response_time_ms = (
                endpoint.response_time_ms * 0.9 + duration_ms * 0.1
            )
            
            return True  # Assume healthy for simulation
            
        except Exception:
            return False
    
    async def _metrics_loop(self):
        """Background metrics collection."""
        while self._is_running:
            try:
                await asyncio.sleep(self.config.metrics_collection_interval)
                await self._collect_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
    
    async def _collect_metrics(self):
        """Collect pool metrics."""
        # Calculate pool-wide metrics
        total_active = sum(e.active_connections for e in self._endpoints)
        total_requests = sum(e.total_requests for e in self._endpoints)
        total_failed = sum(e.failed_requests for e in self._endpoints)
        
        self._metrics.active_connections = total_active
        self._metrics.queue_size = self._request_queue.qsize()
        
        if total_requests > 0:
            self._metrics.success_rate = 1.0 - (total_failed / total_requests)
        
        if self._response_times:
            self._metrics.avg_response_time_ms = sum(self._response_times) / len(self._response_times)
        
        # Pool utilization
        max_connections = self.config.max_connections_per_server * len(self._endpoints)
        if max_connections > 0:
            self._metrics.pool_utilization = total_active / max_connections
    
    def _record_success(self, duration_ms: float):
        """Record successful request."""
        self._response_times.append(duration_ms)
        
        # Keep response times history manageable
        if len(self._response_times) > 1000:
            # Remove oldest 10%
            for _ in range(100):
                self._response_times.popleft()
    
    def _record_failure(self, duration_ms: float):
        """Record failed request."""
        self._response_times.append(duration_ms)
    
    async def _cleanup_completed_requests(self):
        """Clean up completed request tasks."""
        completed_ids = []
        for request_id, task in self._active_requests.items():
            if task.done():
                completed_ids.append(request_id)
        
        for request_id in completed_ids:
            self._active_requests.pop(request_id, None)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get connection pool metrics."""
        return {
            "server_name": self.server_name,
            "endpoints": [
                {
                    "name": e.name,
                    "health": e.health.value,
                    "active_connections": e.active_connections,
                    "response_time_ms": e.response_time_ms,
                    "success_rate": e.get_success_rate(),
                    "total_requests": e.total_requests,
                    "failed_requests": e.failed_requests
                }
                for e in self._endpoints
            ],
            "pool_metrics": {
                "active_connections": self._metrics.active_connections,
                "queue_size": self._metrics.queue_size,
                "avg_response_time_ms": self._metrics.avg_response_time_ms,
                "success_rate": self._metrics.success_rate,
                "pool_utilization": self._metrics.pool_utilization
            },
            "config": {
                "load_balancing_strategy": self.config.load_balancing_strategy.value,
                "max_connections_per_server": self.config.max_connections_per_server,
                "concurrent_request_limit": self.config.concurrent_request_limit
            }
        }
    
    async def shutdown(self):
        """Shutdown the connection pool."""
        logger.info(f"Shutting down MCP connection pool for {self.server_name}")
        
        self._is_running = False
        
        # Cancel background tasks
        if self._health_check_task:
            self._health_check_task.cancel()
        
        if self._metrics_task:
            self._metrics_task.cancel()
        
        # Cancel request processors
        for processor in self._request_processors:
            processor.cancel()
        
        # Cancel active requests
        for task in self._active_requests.values():
            task.cancel()
        
        # Close connection pools
        async with self._pool_lock:
            for pool in self._connection_pools.values():
                await pool.close()
            self._connection_pools.clear()
        
        logger.info(f"MCP connection pool for {self.server_name} shutdown complete")


class MCPConnectionManager:
    """
    Central manager for all MCP connection pools.
    
    Provides unified management of connections across multiple MCP servers
    with load balancing, failover, and performance optimization.
    """
    
    def __init__(self, config: Optional[MCPConnectionConfig] = None):
        self.config = config or MCPConnectionConfig()
        self._pools: Dict[str, MCPConnectionPool] = {}
        self._pool_lock = asyncio.Lock()
        self._is_initialized = False
    
    async def initialize(self):
        """Initialize the connection manager."""
        if self._is_initialized:
            return
        
        logger.info("Initializing MCP Connection Manager")
        self._is_initialized = True
        logger.info("MCP Connection Manager initialized")
    
    async def get_or_create_pool(self, server_name: str) -> MCPConnectionPool:
        """Get or create connection pool for a server."""
        async with self._pool_lock:
            if server_name not in self._pools:
                pool = MCPConnectionPool(server_name, self.config)
                await pool.initialize()
                self._pools[server_name] = pool
                logger.info(f"Created connection pool for server: {server_name}")
            
            return self._pools[server_name]
    
    async def execute_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """Execute tool with optimized connection management."""
        pool = await self.get_or_create_pool(server_name)
        return await pool.execute_tool(tool_name, arguments, timeout)
    
    def add_server_endpoint(
        self,
        server_name: str,
        endpoint_name: str,
        url: Optional[str] = None,
        weight: float = 1.0,
        priority: int = 0
    ):
        """Add endpoint to server pool."""
        # Note: This creates the pool if it doesn't exist
        # In practice, you'd want to defer pool creation until first use
        asyncio.create_task(self._add_endpoint_async(
            server_name, endpoint_name, url, weight, priority
        ))
    
    async def _add_endpoint_async(
        self,
        server_name: str,
        endpoint_name: str,
        url: Optional[str],
        weight: float,
        priority: int
    ):
        """Add endpoint asynchronously."""
        pool = await self.get_or_create_pool(server_name)
        pool.add_endpoint(endpoint_name, url, weight, priority)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all connection pools."""
        return {
            server_name: pool.get_metrics()
            for server_name, pool in self._pools.items()
        }
    
    async def shutdown(self):
        """Shutdown all connection pools."""
        logger.info("Shutting down MCP Connection Manager")
        
        # Shutdown all pools
        shutdown_tasks = [
            pool.shutdown() for pool in self._pools.values()
        ]
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        self._pools.clear()
        self._is_initialized = False
        
        logger.info("MCP Connection Manager shutdown complete")


# Global connection manager instance
_connection_manager: Optional[MCPConnectionManager] = None


async def get_mcp_connection_manager(
    config: Optional[MCPConnectionConfig] = None
) -> MCPConnectionManager:
    """Get the global MCP connection manager."""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = MCPConnectionManager(config)
        await _connection_manager.initialize()
    return _connection_manager


__all__ = [
    "LoadBalancingStrategy",
    "ConnectionHealth",
    "MCPConnectionConfig",
    "ServerEndpoint",
    "ConnectionPoolMetrics",
    "MCPConnectionPool",
    "MCPConnectionManager",
    "get_mcp_connection_manager"
]