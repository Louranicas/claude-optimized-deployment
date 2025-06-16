"""
Core infrastructure modules for Claude-Optimized Deployment Engine.

This package provides essential infrastructure components including:
- Connection pooling for all network operations
- Retry logic with circuit breakers
- Monitoring and metrics collection
- Parallel execution utilities
- Comprehensive distributed caching system
- Performance optimization and tuning
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

from src.core.rate_limiter import (
    DistributedRateLimiter,
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitScope,
    RateLimitExceeded,
    get_rate_limiter,
    initialize_rate_limiter,
    close_rate_limiter
)

from src.core.rate_limit_middleware import (
    RateLimitMiddleware,
    RateLimitDependency,
    rate_limit_dependency
)

from src.core.rate_limit_config import (
    RateLimitingConfig,
    UserTierConfig,
    EndpointRateLimitConfig,
    get_rate_limiting_config,
    initialize_rate_limiting_config
)

from src.core.rate_limit_monitoring import (
    RateLimitMonitor,
    RateLimitMetric,
    RateLimitSummary
)

from src.core.rate_limit_init import (
    RateLimitingSetup,
    get_rate_limiting_setup,
    initialize_rate_limiting_for_app,
    setup_production_rate_limiting,
    setup_development_rate_limiting,
    setup_testing_rate_limiting
)

from src.core.cache_integration import (
    IntegratedCacheManager,
    IntegratedCacheConfig,
    CacheStats,
    CacheHealthCheck,
    create_integrated_cache,
    setup_production_cache,
    CacheClusterManager
)

from src.core.distributed_cache import (
    CacheManager,
    CacheConfig,
    CacheMetrics,
    CacheLevel,
    CachePattern,
    create_cache_manager
)

from src.core.cache_security import (
    CacheSecurityManager,
    SecurityConfig,
    Role,
    Permission,
    SecurityLevel
)

from src.core.cache_patterns import (
    PatternManager,
    CachePatternConfig,
    ConsistencyLevel,
    InvalidationStrategy,
    DataLoader,
    DataWriter
)

from src.core.cache_benchmarks import (
    CacheBenchmarker,
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkType,
    WorkloadPattern,
    quick_benchmark,
    comprehensive_benchmark,
    stress_benchmark
)

from src.core.cache_tuning_guide import (
    CacheTuner,
    AutoOptimizer,
    TuningConfig,
    TuningReport,
    PerformanceGoal,
    quick_tune,
    auto_optimize
)

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
    "ParallelExecutor",
    
    # Rate limiting core
    "DistributedRateLimiter",
    "RateLimitAlgorithm",
    "RateLimitConfig",
    "RateLimitScope",
    "RateLimitExceeded",
    "get_rate_limiter",
    "initialize_rate_limiter",
    "close_rate_limiter",
    
    # Rate limiting middleware
    "RateLimitMiddleware",
    "RateLimitDependency",
    "rate_limit_dependency",
    
    # Rate limiting configuration
    "RateLimitingConfig",
    "UserTierConfig",
    "EndpointRateLimitConfig",
    "get_rate_limiting_config",
    "initialize_rate_limiting_config",
    
    # Rate limiting monitoring
    "RateLimitMonitor",
    "RateLimitMetric",
    "RateLimitSummary",
    
    # Rate limiting initialization
    "RateLimitingSetup",
    "get_rate_limiting_setup",
    "initialize_rate_limiting_for_app",
    "setup_production_rate_limiting",
    "setup_development_rate_limiting",
    "setup_testing_rate_limiting",
    
    # Distributed caching - Integration
    "IntegratedCacheManager",
    "IntegratedCacheConfig", 
    "CacheStats",
    "CacheHealthCheck",
    "create_integrated_cache",
    "setup_production_cache",
    "CacheClusterManager",
    
    # Distributed caching - Core
    "CacheManager",
    "CacheConfig",
    "CacheMetrics",
    "CacheLevel",
    "CachePattern",
    "create_cache_manager",
    
    # Cache security
    "CacheSecurityManager",
    "SecurityConfig",
    "Role",
    "Permission", 
    "SecurityLevel",
    
    # Cache patterns
    "PatternManager",
    "CachePatternConfig",
    "ConsistencyLevel",
    "InvalidationStrategy",
    "DataLoader",
    "DataWriter",
    
    # Cache benchmarking
    "CacheBenchmarker",
    "BenchmarkConfig",
    "BenchmarkResult",
    "BenchmarkType",
    "WorkloadPattern",
    "quick_benchmark",
    "comprehensive_benchmark",
    "stress_benchmark",
    
    # Cache tuning
    "CacheTuner",
    "AutoOptimizer",
    "TuningConfig",
    "TuningReport",
    "PerformanceGoal",
    "quick_tune",
    "auto_optimize"
]

# Version info
__version__ = "1.0.0"