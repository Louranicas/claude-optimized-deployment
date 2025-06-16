"""
Core infrastructure modules for Claude-Optimized Deployment Engine.

This package provides essential infrastructure components including:
- Connection pooling for all network operations
- Retry logic with circuit breakers
- Monitoring and metrics collection
- Parallel execution utilities
"""

from src.core.connections import (
    ConnectionPoolConfig,
    ConnectionPoolManager,
    get_connection_manager,
    close_all_connections,
    HTTPConnectionPool,
    DatabaseConnectionPool,
    RedisConnectionPool,
    WebSocketConnectionPool
)

from src.core.connection_monitoring import (
    ConnectionPoolMonitor,
    ConnectionPoolHealthCheck,
    get_connection_monitor,
    stop_connection_monitor
)

from src.core.retry import (
    retry_api_call,
    retry_network,
    RetryConfig,
    RetryStrategy
)

from src.core.parallel_executor import ParallelExecutor

__all__ = [
    # Connection pooling
    "ConnectionPoolConfig",
    "ConnectionPoolManager",
    "get_connection_manager",
    "close_all_connections",
    "HTTPConnectionPool",
    "DatabaseConnectionPool",
    "RedisConnectionPool",
    "WebSocketConnectionPool",
    
    # Connection monitoring
    "ConnectionPoolMonitor",
    "ConnectionPoolHealthCheck",
    "get_connection_monitor",
    "stop_connection_monitor",
    
    # Retry logic
    "retry_api_call",
    "retry_network",
    "RetryConfig",
    "RetryStrategy",
    
    # Parallel execution
    "ParallelExecutor"
]

# Version info
__version__ = "1.0.0"