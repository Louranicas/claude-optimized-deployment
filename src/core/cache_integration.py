"""
Comprehensive cache integration module.

This module provides a unified interface to all caching functionality,
integrating distributed caching, security, patterns, benchmarking,
and monitoring into a cohesive system.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass, asdict
import structlog

from .distributed_cache import (
    CacheManager, CacheConfig, create_cache_manager,
    CacheMetrics, CacheLevel, CachePattern
)
from .cache_security import (
    CacheSecurityManager, SecurityConfig, Role, Permission,
    SecurityLevel
)
from .cache_patterns import (
    PatternManager, CachePatternConfig, DataLoader, DataWriter,
    ConsistencyLevel, InvalidationStrategy
)
from .cache_benchmarks import (
    CacheBenchmarker, BenchmarkConfig, BenchmarkResult,
    BenchmarkSuite, BenchmarkType
)
from .memory_monitor import get_memory_monitor, MemoryPressureLevel
from .cache_config import get_cache_config

__all__ = [
    "IntegratedCacheConfig",
    "CacheStats",
    "CacheHealthCheck",
    "IntegratedCacheManager",
    "create_integrated_cache",
    "CacheClusterManager"
]

logger = structlog.get_logger(__name__)


@dataclass
class IntegratedCacheConfig:
    """Unified configuration for all cache components."""
    # Core cache configuration
    redis_url: str = "redis://localhost:6379"
    redis_cluster_nodes: Optional[List[str]] = None
    enable_l1_cache: bool = True
    l1_max_size: int = 1000
    default_ttl: float = 3600.0
    
    # Security configuration
    enable_security: bool = True
    enable_encryption: bool = True
    enable_access_control: bool = True
    enable_audit_logging: bool = True
    enable_rate_limiting: bool = True
    
    # Pattern configuration
    default_read_pattern: CachePattern = CachePattern.CACHE_ASIDE
    default_write_pattern: CachePattern = CachePattern.CACHE_ASIDE
    consistency_level: ConsistencyLevel = ConsistencyLevel.EVENTUAL
    invalidation_strategy: InvalidationStrategy = InvalidationStrategy.TTL_BASED
    
    # Performance configuration
    enable_compression: bool = True
    enable_monitoring: bool = True
    enable_benchmarking: bool = False
    
    # Memory integration
    enable_memory_monitoring: bool = True
    memory_pressure_threshold: MemoryPressureLevel = MemoryPressureLevel.HIGH
    
    # Cluster configuration
    enable_clustering: bool = False
    cluster_nodes: Optional[List[str]] = None
    replication_factor: int = 2
    
    def to_cache_config(self) -> CacheConfig:
        """Convert to CacheConfig."""
        return CacheConfig(
            redis_url=self.redis_url,
            redis_cluster_nodes=self.redis_cluster_nodes,
            enable_l1_cache=self.enable_l1_cache,
            l1_max_size=self.l1_max_size,
            default_ttl=self.default_ttl,
            enable_compression=self.enable_compression,
            enable_encryption=self.enable_encryption,
            enable_metrics=self.enable_monitoring
        )
    
    def to_security_config(self) -> SecurityConfig:
        """Convert to SecurityConfig."""
        return SecurityConfig(
            enable_encryption=self.enable_encryption,
            enable_access_control=self.enable_access_control,
            enable_audit_logging=self.enable_audit_logging,
            enable_rate_limiting=self.enable_rate_limiting
        )
    
    def to_pattern_config(self) -> CachePatternConfig:
        """Convert to CachePatternConfig."""
        return CachePatternConfig(
            read_pattern=self.default_read_pattern,
            write_pattern=self.default_write_pattern,
            consistency_level=self.consistency_level,
            invalidation_strategy=self.invalidation_strategy
        )


@dataclass
class CacheStats:
    """Comprehensive cache statistics."""
    # Basic metrics
    total_operations: int = 0
    hit_rate: float = 0.0
    miss_rate: float = 0.0
    avg_latency_ms: float = 0.0
    
    # Memory metrics
    memory_usage_mb: float = 0.0
    item_count: int = 0
    l1_cache_size: int = 0
    
    # Security metrics
    auth_failures: int = 0
    rate_limit_violations: int = 0
    
    # Performance metrics
    ops_per_second: float = 0.0
    peak_memory_mb: float = 0.0
    error_rate: float = 0.0
    
    # Pattern metrics
    read_pattern_usage: Dict[str, int] = None
    write_pattern_usage: Dict[str, int] = None
    
    def __post_init__(self):
        if self.read_pattern_usage is None:
            self.read_pattern_usage = {}
        if self.write_pattern_usage is None:
            self.write_pattern_usage = {}


@dataclass
class CacheHealthCheck:
    """Cache health check results."""
    timestamp: float
    overall_health: str  # "healthy", "degraded", "unhealthy"
    redis_connected: bool
    l1_cache_healthy: bool
    memory_pressure: str
    security_status: str
    pattern_status: str
    issues: List[str]
    recommendations: List[str]


class IntegratedCacheManager:
    """Unified cache manager integrating all components."""
    
    def __init__(self, config: IntegratedCacheConfig):
        self.config = config
        
        # Initialize core components
        self.cache_manager = CacheManager(config.to_cache_config())
        
        # Initialize security manager if enabled
        self.security_manager = None
        if config.enable_security:
            self.security_manager = CacheSecurityManager(config.to_security_config())
        
        # Initialize pattern manager
        self.pattern_manager = PatternManager(
            self.cache_manager,
            config.to_pattern_config()
        )
        
        # Initialize benchmarker if enabled
        self.benchmarker = None
        if config.enable_benchmarking:
            self.benchmarker = CacheBenchmarker(self.cache_manager)
        
        # Memory monitor integration
        self.memory_monitor = None
        if config.enable_memory_monitoring:
            self.memory_monitor = get_memory_monitor()
            self._setup_memory_integration()
        
        # State tracking
        self._initialized = False
        self._stats = CacheStats()
        self._operation_count = 0
        self._last_stats_update = time.time()
    
    def _setup_memory_integration(self) -> None:
        """Setup memory pressure handling for cache."""
        if not self.memory_monitor:
            return
        
        # Add cache cleanup action for memory pressure
        from .memory_monitor import ClearCachesAction, MemoryPressureLevel
        
        cache_clearer = lambda: asyncio.create_task(self._handle_memory_pressure())
        
        self.memory_monitor.add_pressure_action(
            MemoryPressureLevel.HIGH,
            ClearCachesAction([cache_clearer])
        )
        
        # Add callback for memory pressure monitoring
        self.memory_monitor.add_pressure_callback(self._on_memory_pressure)
    
    async def _handle_memory_pressure(self) -> None:
        """Handle memory pressure by reducing cache size."""
        try:
            # Clear L1 cache first
            if hasattr(self.cache_manager.cache, 'l1_cache') and self.cache_manager.cache.l1_cache:
                self.cache_manager.cache.l1_cache.clear()
                logger.info("Cleared L1 cache due to memory pressure")
            
            # Trigger pattern manager cleanup
            if hasattr(self.pattern_manager, 'invalidation_manager'):
                await self.pattern_manager.invalidation_manager.invalidate_pattern("temp:*")
                logger.info("Invalidated temporary cache entries due to memory pressure")
                
        except Exception as e:
            logger.error("Failed to handle memory pressure in cache", error=str(e))
    
    def _on_memory_pressure(self, metrics) -> None:
        """Callback for memory pressure events."""
        if metrics.pressure_level == MemoryPressureLevel.CRITICAL:
            logger.warning(
                "Critical memory pressure detected",
                process_memory_mb=metrics.process_memory_mb,
                system_memory_percent=metrics.system_memory_percent
            )
    
    async def initialize(self) -> None:
        """Initialize all cache components."""
        if self._initialized:
            return
        
        try:
            # Initialize core cache
            await self.cache_manager.initialize()
            
            # Start memory monitoring if enabled
            if self.memory_monitor and self.config.enable_memory_monitoring:
                await self.memory_monitor.start_monitoring()
            
            self._initialized = True
            logger.info("Integrated cache manager initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize integrated cache manager", error=str(e))
            raise
    
    async def get(
        self,
        key: str,
        default: Any = None,
        session_id: Optional[str] = None,
        pattern: Optional[CachePattern] = None
    ) -> Any:
        """Get value from cache with integrated security and patterns."""
        start_time = time.time()
        
        try:
            # Security check
            if self.security_manager and session_id:
                authorized, user_id, role = await self.security_manager.authorize_operation(
                    session_id, "get", key
                )
                if not authorized:
                    await self.security_manager.log_operation(user_id or "unknown", "get", key, False)
                    return default
            
            # Use pattern manager for retrieval
            if pattern and hasattr(self.pattern_manager, 'get_or_set'):
                # For pattern-based access, we need a data loader
                # This is a simplified version - real implementation would need proper data loader
                value = await self.cache_manager.cache.get(key, default)
            else:
                value = await self.cache_manager.cache.get(key, default)
            
            # Update statistics
            self._operation_count += 1
            duration = (time.time() - start_time) * 1000
            
            # Log successful operation
            if self.security_manager and session_id:
                await self.security_manager.log_operation(user_id, "get", key, True, {
                    "duration_ms": duration,
                    "cache_hit": value is not default
                })
            
            return value
            
        except Exception as e:
            logger.error("Cache get operation failed", key=key, error=str(e))
            if self.security_manager and session_id:
                await self.security_manager.log_operation("unknown", "get", key, False, {
                    "error": str(e)
                })
            return default
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        session_id: Optional[str] = None,
        pattern: Optional[CachePattern] = None,
        tags: Optional[set] = None
    ) -> bool:
        """Set value in cache with integrated security and patterns."""
        start_time = time.time()
        
        try:
            # Security check
            if self.security_manager and session_id:
                authorized, user_id, role = await self.security_manager.authorize_operation(
                    session_id, "set", key
                )
                if not authorized:
                    await self.security_manager.log_operation(user_id or "unknown", "set", key, False)
                    return False
            
            # Use pattern manager for storage
            if pattern:
                success = await self.pattern_manager.set_with_pattern(
                    key, value, pattern=pattern
                )
            else:
                success = await self.cache_manager.cache.set(key, value, ttl, tags)
            
            # Update statistics
            self._operation_count += 1
            duration = (time.time() - start_time) * 1000
            
            # Log operation
            if self.security_manager and session_id:
                await self.security_manager.log_operation(user_id, "set", key, success, {
                    "duration_ms": duration,
                    "value_size": len(str(value)) if value else 0
                })
            
            return success
            
        except Exception as e:
            logger.error("Cache set operation failed", key=key, error=str(e))
            if self.security_manager and session_id:
                await self.security_manager.log_operation("unknown", "set", key, False, {
                    "error": str(e)
                })
            return False
    
    async def delete(
        self,
        key: str,
        session_id: Optional[str] = None
    ) -> bool:
        """Delete value from cache with security checks."""
        try:
            # Security check
            if self.security_manager and session_id:
                authorized, user_id, role = await self.security_manager.authorize_operation(
                    session_id, "delete", key
                )
                if not authorized:
                    await self.security_manager.log_operation(user_id or "unknown", "delete", key, False)
                    return False
            
            success = await self.cache_manager.cache.delete(key)
            
            # Log operation
            if self.security_manager and session_id:
                await self.security_manager.log_operation(user_id, "delete", key, success)
            
            return success
            
        except Exception as e:
            logger.error("Cache delete operation failed", key=key, error=str(e))
            return False
    
    async def invalidate_pattern(
        self,
        pattern: str,
        session_id: Optional[str] = None,
        strategy: Optional[InvalidationStrategy] = None
    ) -> int:
        """Invalidate keys matching pattern."""
        try:
            # Security check for admin operations
            if self.security_manager and session_id:
                authorized, user_id, role = await self.security_manager.authorize_operation(
                    session_id, "delete", pattern  # Use delete permission for pattern operations
                )
                if not authorized:
                    return 0
            
            count = await self.pattern_manager.invalidate_by_pattern(pattern)
            
            if self.security_manager and session_id:
                await self.security_manager.log_operation(user_id, "invalidate_pattern", pattern, True, {
                    "invalidated_count": count
                })
            
            return count
            
        except Exception as e:
            logger.error("Pattern invalidation failed", pattern=pattern, error=str(e))
            return 0
    
    async def create_session(
        self,
        user_id: str,
        role_name: str = "user",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Create user session for security-enabled operations."""
        if not self.security_manager:
            return "no-security"  # Return dummy session when security is disabled
        
        try:
            # Assign role to user if not already assigned
            self.security_manager.assign_user_role(user_id, role_name)
            
            # Create session
            session_id = self.security_manager.create_user_session(user_id, metadata)
            
            logger.info("User session created", user_id=user_id, role=role_name, session_id=session_id)
            return session_id
            
        except Exception as e:
            logger.error("Failed to create user session", user_id=user_id, error=str(e))
            return None
    
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke user session."""
        if not self.security_manager:
            return True
        
        return self.security_manager.access_control.revoke_session(session_id)
    
    async def get_stats(self) -> CacheStats:
        """Get comprehensive cache statistics."""
        try:
            # Update basic metrics
            cache_metrics = await self.cache_manager.get_metrics()
            
            self._stats.total_operations = self._operation_count
            self._stats.hit_rate = cache_metrics.hit_rate
            self._stats.miss_rate = cache_metrics.miss_rate
            self._stats.avg_latency_ms = cache_metrics.avg_get_time
            self._stats.memory_usage_mb = cache_metrics.memory_usage / (1024 * 1024)
            self._stats.item_count = cache_metrics.item_count
            self._stats.ops_per_second = self._operation_count / max(1, time.time() - self._last_stats_update)
            
            # Security metrics
            if self.security_manager:
                security_stats = self.security_manager.monitor_security_events()
                self._stats.auth_failures = security_stats.get("failed_auth_attempts", 0)
            
            # Pattern metrics
            if self.pattern_manager:
                pattern_stats = await self.pattern_manager.get_stats()
                self._stats.read_pattern_usage = {"cache_aside": self._operation_count}  # Simplified
                self._stats.write_pattern_usage = {"cache_aside": self._operation_count}  # Simplified
            
            return self._stats
            
        except Exception as e:
            logger.error("Failed to get cache statistics", error=str(e))
            return self._stats
    
    async def health_check(self) -> CacheHealthCheck:
        """Perform comprehensive health check."""
        timestamp = time.time()
        issues = []
        recommendations = []
        
        try:
            # Check Redis connectivity
            redis_connected = False
            try:
                info = await self.cache_manager.get_info()
                redis_connected = bool(info.get("redis_info"))
            except Exception as e:
                issues.append(f"Redis connection issue: {str(e)}")
            
            # Check L1 cache
            l1_cache_healthy = True
            if self.cache_manager.cache.l1_cache:
                try:
                    # Simple test
                    test_key = f"health_check_{timestamp}"
                    self.cache_manager.cache.l1_cache.set(test_key, "test")
                    self.cache_manager.cache.l1_cache.delete(test_key)
                except Exception as e:
                    l1_cache_healthy = False
                    issues.append(f"L1 cache issue: {str(e)}")
            
            # Check memory pressure
            memory_pressure = "normal"
            if self.memory_monitor:
                try:
                    metrics = self.memory_monitor.get_current_metrics()
                    memory_pressure = metrics.pressure_level.value
                    if metrics.pressure_level in [MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL]:
                        issues.append(f"High memory pressure: {metrics.pressure_level.value}")
                        recommendations.append("Consider reducing cache size or clearing unused entries")
                except Exception as e:
                    issues.append(f"Memory monitoring issue: {str(e)}")
            
            # Check security status
            security_status = "disabled"
            if self.security_manager:
                try:
                    security_events = self.security_manager.monitor_security_events()
                    security_status = "healthy"
                    if security_events.get("failed_auth_attempts", 0) > 10:
                        security_status = "concerning"
                        issues.append("High number of authentication failures")
                except Exception as e:
                    security_status = "error"
                    issues.append(f"Security system issue: {str(e)}")
            
            # Check pattern status
            pattern_status = "healthy"
            try:
                pattern_stats = await self.pattern_manager.get_stats()
                if not pattern_stats:
                    pattern_status = "degraded"
            except Exception as e:
                pattern_status = "error"
                issues.append(f"Pattern system issue: {str(e)}")
            
            # Determine overall health
            if not redis_connected:
                overall_health = "unhealthy"
            elif issues:
                overall_health = "degraded"
            else:
                overall_health = "healthy"
            
            # Generate recommendations
            if not redis_connected:
                recommendations.append("Check Redis server status and network connectivity")
            if memory_pressure in ["high", "critical"]:
                recommendations.append("Monitor memory usage and consider cache optimization")
            if len(issues) > 5:
                recommendations.append("Multiple issues detected - consider cache restart")
            
            return CacheHealthCheck(
                timestamp=timestamp,
                overall_health=overall_health,
                redis_connected=redis_connected,
                l1_cache_healthy=l1_cache_healthy,
                memory_pressure=memory_pressure,
                security_status=security_status,
                pattern_status=pattern_status,
                issues=issues,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return CacheHealthCheck(
                timestamp=timestamp,
                overall_health="error",
                redis_connected=False,
                l1_cache_healthy=False,
                memory_pressure="unknown",
                security_status="unknown",
                pattern_status="unknown",
                issues=[f"Health check error: {str(e)}"],
                recommendations=["Investigate health check system"]
            )
    
    async def benchmark(
        self,
        benchmark_type: BenchmarkType = BenchmarkType.LATENCY,
        duration_seconds: float = 60.0
    ) -> Optional[BenchmarkResult]:
        """Run cache benchmark."""
        if not self.benchmarker:
            logger.warning("Benchmarking not enabled")
            return None
        
        try:
            config = BenchmarkConfig(duration_seconds=duration_seconds)
            return await self.benchmarker.run_benchmark(config, benchmark_type)
            
        except Exception as e:
            logger.error("Benchmark failed", error=str(e))
            return None
    
    async def export_config(self, file_path: str) -> bool:
        """Export current configuration to file."""
        try:
            config_dict = asdict(self.config)
            
            with open(file_path, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
            
            logger.info("Configuration exported", file_path=file_path)
            return True
            
        except Exception as e:
            logger.error("Failed to export configuration", file_path=file_path, error=str(e))
            return False
    
    async def close(self) -> None:
        """Close all cache components."""
        try:
            # Close pattern manager
            if self.pattern_manager:
                await self.pattern_manager.close()
            
            # Close cache manager
            await self.cache_manager.close()
            
            # Stop memory monitoring
            if self.memory_monitor and self.config.enable_memory_monitoring:
                await self.memory_monitor.stop_monitoring()
            
            logger.info("Integrated cache manager closed")
            
        except Exception as e:
            logger.error("Error closing integrated cache manager", error=str(e))


class CacheClusterManager:
    """Manages multiple cache instances in a cluster."""
    
    def __init__(self, cluster_config: Dict[str, IntegratedCacheConfig]):
        self.cluster_config = cluster_config
        self.cache_instances: Dict[str, IntegratedCacheManager] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize all cache instances in cluster."""
        if self._initialized:
            return
        
        try:
            for node_name, config in self.cluster_config.items():
                cache_instance = IntegratedCacheManager(config)
                await cache_instance.initialize()
                self.cache_instances[node_name] = cache_instance
                logger.info("Cache node initialized", node_name=node_name)
            
            self._initialized = True
            logger.info("Cache cluster initialized", node_count=len(self.cache_instances))
            
        except Exception as e:
            logger.error("Failed to initialize cache cluster", error=str(e))
            raise
    
    async def get_cluster_stats(self) -> Dict[str, CacheStats]:
        """Get statistics from all cluster nodes."""
        cluster_stats = {}
        
        for node_name, cache_instance in self.cache_instances.items():
            try:
                stats = await cache_instance.get_stats()
                cluster_stats[node_name] = stats
            except Exception as e:
                logger.error("Failed to get stats from node", node_name=node_name, error=str(e))
        
        return cluster_stats
    
    async def health_check_cluster(self) -> Dict[str, CacheHealthCheck]:
        """Health check all cluster nodes."""
        cluster_health = {}
        
        for node_name, cache_instance in self.cache_instances.items():
            try:
                health = await cache_instance.health_check()
                cluster_health[node_name] = health
            except Exception as e:
                logger.error("Failed to health check node", node_name=node_name, error=str(e))
        
        return cluster_health
    
    async def close_cluster(self) -> None:
        """Close all cache instances in cluster."""
        for node_name, cache_instance in self.cache_instances.items():
            try:
                await cache_instance.close()
                logger.info("Cache node closed", node_name=node_name)
            except Exception as e:
                logger.error("Failed to close cache node", node_name=node_name, error=str(e))


def create_integrated_cache(
    redis_url: str = "redis://localhost:6379",
    enable_security: bool = True,
    enable_patterns: bool = True,
    enable_monitoring: bool = True,
    **kwargs
) -> IntegratedCacheManager:
    """Create an integrated cache manager with default configuration."""
    config = IntegratedCacheConfig(
        redis_url=redis_url,
        enable_security=enable_security,
        enable_monitoring=enable_monitoring,
        **kwargs
    )
    
    return IntegratedCacheManager(config)


# Convenience function for quick setup
async def setup_production_cache(
    redis_cluster_nodes: List[str],
    encryption_key: Optional[str] = None
) -> IntegratedCacheManager:
    """Setup production-ready cache with clustering and security."""
    config = IntegratedCacheConfig(
        redis_cluster_nodes=redis_cluster_nodes,
        enable_security=True,
        enable_encryption=True,
        enable_access_control=True,
        enable_audit_logging=True,
        enable_monitoring=True,
        enable_compression=True,
        consistency_level=ConsistencyLevel.STRONG,
        default_ttl=7200.0,  # 2 hours
        l1_max_size=10000
    )
    
    cache_manager = IntegratedCacheManager(config)
    await cache_manager.initialize()
    
    logger.info("Production cache setup completed", nodes=len(redis_cluster_nodes))
    return cache_manager