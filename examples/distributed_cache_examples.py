"""
Comprehensive examples for the distributed cache system.

This module demonstrates various usage patterns and best practices
for the integrated distributed caching system.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Import cache components
from src.core.cache_integration import (
    IntegratedCacheManager, IntegratedCacheConfig,
    create_integrated_cache, setup_production_cache
)
from src.core.cache_security import Role, Permission, SecurityLevel
from src.core.cache_patterns import CachePattern, ConsistencyLevel, InvalidationStrategy
from src.core.cache_benchmarks import BenchmarkType, quick_benchmark
from src.core.cache_tuning_guide import quick_tune, auto_optimize, PerformanceGoal


@dataclass
class User:
    """Example user data structure."""
    id: str
    name: str
    email: str
    preferences: Dict[str, Any]
    created_at: float


class DatabaseSimulator:
    """Simulated database for examples."""
    
    def __init__(self):
        self.users = {
            "user1": User("user1", "Alice Smith", "alice@example.com", {"theme": "dark"}, time.time()),
            "user2": User("user2", "Bob Jones", "bob@example.com", {"theme": "light"}, time.time()),
            "user3": User("user3", "Carol Wilson", "carol@example.com", {"theme": "auto"}, time.time()),
        }
        self.access_count = 0
    
    async def get_user(self, user_id: str) -> Optional[User]:
        """Simulate database lookup with latency."""
        await asyncio.sleep(0.1)  # Simulate DB latency
        self.access_count += 1
        print(f"🗄️  Database access #{self.access_count}: fetching user {user_id}")
        return self.users.get(user_id)
    
    async def save_user(self, user: User) -> bool:
        """Simulate database save."""
        await asyncio.sleep(0.05)  # Simulate write latency
        self.users[user.id] = user
        print(f"💾 Database: saved user {user.id}")
        return True


# Example 1: Basic Cache Usage
async def example_basic_usage():
    """Demonstrate basic cache operations."""
    print("\n🚀 Example 1: Basic Cache Usage")
    print("=" * 50)
    
    # Create cache with simple configuration
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",
        enable_security=False,  # Simplified for basic example
        enable_monitoring=True
    )
    
    try:
        await cache.initialize()
        
        # Basic set and get operations
        print("Setting values in cache...")
        await cache.set("user:123", {"name": "John Doe", "email": "john@example.com"})
        await cache.set("config:app", {"theme": "dark", "notifications": True})
        
        # Retrieve values
        print("Retrieving values from cache...")
        user = await cache.get("user:123")
        config = await cache.get("config:app")
        missing = await cache.get("nonexistent", "default_value")
        
        print(f"✅ User: {user}")
        print(f"✅ Config: {config}")
        print(f"✅ Missing key: {missing}")
        
        # Get cache statistics
        stats = await cache.get_stats()
        print(f"📊 Cache hit rate: {stats.hit_rate:.2%}")
        print(f"📊 Total operations: {stats.total_operations}")
        
    finally:
        await cache.close()


# Example 2: Security and Access Control
async def example_security_features():
    """Demonstrate security features including roles and permissions."""
    print("\n🔐 Example 2: Security Features")
    print("=" * 50)
    
    # Create cache with security enabled
    config = IntegratedCacheConfig(
        redis_url="redis://localhost:6379",
        enable_security=True,
        enable_encryption=True,
        enable_access_control=True,
        enable_audit_logging=True
    )
    
    cache = IntegratedCacheManager(config)
    
    try:
        await cache.initialize()
        
        # Create custom roles
        admin_role = Role(
            name="admin",
            permissions={Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN},
            security_level=SecurityLevel.RESTRICTED
        )
        
        readonly_role = Role(
            name="readonly",
            permissions={Permission.READ},
            key_patterns=["public:*", "user:*"],
            rate_limit=100,
            security_level=SecurityLevel.PUBLIC
        )
        
        cache.security_manager.add_custom_role(admin_role)
        cache.security_manager.add_custom_role(readonly_role)
        
        # Create user sessions
        admin_session = await cache.create_session("admin_user", "admin")
        readonly_session = await cache.create_session("readonly_user", "readonly")
        
        print(f"👤 Created admin session: {admin_session}")
        print(f"👤 Created readonly session: {readonly_session}")
        
        # Test operations with different permissions
        print("\nTesting admin operations...")
        await cache.set("admin:config", {"setting": "value"}, session_id=admin_session)
        admin_value = await cache.get("admin:config", session_id=admin_session)
        print(f"✅ Admin read: {admin_value}")
        
        print("\nTesting readonly operations...")
        await cache.set("public:data", {"info": "public"}, session_id=admin_session)
        readonly_value = await cache.get("public:data", session_id=readonly_session)
        print(f"✅ Readonly access: {readonly_value}")
        
        # This should fail due to permissions
        print("\nTesting unauthorized operation...")
        unauthorized_result = await cache.set("admin:secret", {"data": "classified"}, session_id=readonly_session)
        print(f"❌ Unauthorized write result: {unauthorized_result}")
        
        # Get security statistics
        user_stats = cache.security_manager.get_user_stats("readonly_user")
        print(f"📊 Readonly user stats: {user_stats}")
        
    finally:
        await cache.close()


# Example 3: Cache Patterns
async def example_cache_patterns():
    """Demonstrate different cache patterns."""
    print("\n🔄 Example 3: Cache Patterns")
    print("=" * 50)
    
    # Create cache with pattern configuration
    config = IntegratedCacheConfig(
        redis_url="redis://localhost:6379",
        enable_security=False,
        default_read_pattern=CachePattern.CACHE_ASIDE,
        default_write_pattern=CachePattern.WRITE_THROUGH,
        consistency_level=ConsistencyLevel.EVENTUAL
    )
    
    cache = IntegratedCacheManager(config)
    db = DatabaseSimulator()
    
    try:
        await cache.initialize()
        
        print("Testing Cache-Aside pattern...")
        
        # First access - cache miss, loads from database
        start_time = time.time()
        user = await cache.get("user:user1")
        if user is None:
            user_data = await db.get_user("user1")
            if user_data:
                await cache.set("user:user1", user_data.__dict__)
                user = user_data.__dict__
        
        first_access_time = time.time() - start_time
        print(f"⏱️  First access (cache miss): {first_access_time:.3f}s")
        print(f"👤 User data: {user}")
        
        # Second access - cache hit
        start_time = time.time()
        cached_user = await cache.get("user:user1")
        second_access_time = time.time() - start_time
        print(f"⏱️  Second access (cache hit): {second_access_time:.3f}s")
        print(f"🚀 Speed improvement: {first_access_time/second_access_time:.1f}x faster")
        
        print(f"\n📊 Database access count: {db.access_count}")
        
        # Test invalidation
        print("\nTesting cache invalidation...")
        await cache.invalidate_pattern("user:*")
        invalidated_user = await cache.get("user:user1")
        print(f"After invalidation: {invalidated_user}")
        
    finally:
        await cache.close()


# Example 4: Multi-Level Caching
async def example_multilevel_caching():
    """Demonstrate multi-level caching (L1 memory + L2 Redis)."""
    print("\n📚 Example 4: Multi-Level Caching")
    print("=" * 50)
    
    config = IntegratedCacheConfig(
        redis_url="redis://localhost:6379",
        enable_l1_cache=True,
        l1_max_size=1000,
        default_ttl=3600.0
    )
    
    cache = IntegratedCacheManager(config)
    
    try:
        await cache.initialize()
        
        # Set data that will be cached in both L1 and L2
        test_data = {"large_dataset": list(range(1000)), "timestamp": time.time()}
        
        print("Setting data in multi-level cache...")
        await cache.set("dataset:large", test_data)
        
        # First retrieval - from L2 (Redis) to L1 (memory)
        print("First retrieval (L2 -> L1)...")
        start_time = time.time()
        data1 = await cache.get("dataset:large")
        l2_time = time.time() - start_time
        
        # Second retrieval - from L1 (memory)
        print("Second retrieval (L1 memory)...")
        start_time = time.time()
        data2 = await cache.get("dataset:large")
        l1_time = time.time() - start_time
        
        print(f"⏱️  L2 (Redis) access time: {l2_time:.4f}s")
        print(f"⏱️  L1 (Memory) access time: {l1_time:.4f}s")
        print(f"🚀 L1 speed advantage: {l2_time/l1_time:.1f}x faster")
        
        # Show cache statistics
        stats = await cache.get_stats()
        print(f"📊 L1 cache size: {stats.l1_cache_size} items")
        print(f"📊 Hit rate: {stats.hit_rate:.2%}")
        
    finally:
        await cache.close()


# Example 5: Cache Benchmarking
async def example_benchmarking():
    """Demonstrate cache performance benchmarking."""
    print("\n⚡ Example 5: Cache Benchmarking")
    print("=" * 50)
    
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",
        enable_benchmarking=True
    )
    
    try:
        await cache.initialize()
        
        print("Running latency benchmark...")
        latency_result = await cache.benchmark(BenchmarkType.LATENCY, duration_seconds=30)
        
        if latency_result:
            print(f"📊 Operations per second: {latency_result.operations_per_second:.0f}")
            print(f"📊 Average latency: {latency_result.avg_latency_ms:.2f} ms")
            print(f"📊 95th percentile: {latency_result.latency_percentiles.get(95, 0):.2f} ms")
            print(f"📊 Hit rate: {latency_result.hit_rate:.2%}")
        
        print("\nRunning throughput benchmark...")
        throughput_result = await cache.benchmark(BenchmarkType.THROUGHPUT, duration_seconds=30)
        
        if throughput_result:
            print(f"📊 Peak throughput: {throughput_result.operations_per_second:.0f} ops/sec")
            print(f"📊 Total operations: {throughput_result.total_operations}")
        
        # Quick benchmark using convenience function
        print("\nRunning quick benchmark suite...")
        quick_results = await quick_benchmark(cache.cache_manager)
        print(f"📊 Quick benchmark completed: {len(quick_results)} tests")
        
    finally:
        await cache.close()


# Example 6: Performance Tuning
async def example_performance_tuning():
    """Demonstrate automated performance tuning."""
    print("\n🔧 Example 6: Performance Tuning")
    print("=" * 50)
    
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",
        enable_monitoring=True
    )
    
    try:
        await cache.initialize()
        
        # Generate some load for analysis
        print("Generating cache load for analysis...")
        for i in range(100):
            await cache.set(f"test:key:{i}", {"data": f"value_{i}", "index": i})
            if i % 10 == 0:
                await cache.get(f"test:key:{i//2}")  # Create some cache hits
        
        # Quick tune analysis
        print("\nRunning quick tune analysis...")
        tuning_report = await quick_tune(cache)
        
        print(f"📊 Performance analysis completed")
        print(f"📊 Current hit rate: {tuning_report.performance_metrics.get('hit_rate', 0):.2%}")
        print(f"📊 Memory usage: {tuning_report.performance_metrics.get('memory_usage_mb', 0):.1f} MB")
        print(f"📊 Recommendations: {len(tuning_report.recommendations)}")
        
        # Show top recommendations
        top_recommendations = tuning_report.get_top_recommendations(3)
        for i, rec in enumerate(top_recommendations, 1):
            print(f"\n🔧 Recommendation #{i}: {rec.title}")
            print(f"   Priority: {rec.priority}, Impact: {rec.impact}")
            print(f"   {rec.description}")
        
        # Auto-optimization example
        print("\n🤖 Running auto-optimization...")
        optimization_result = await auto_optimize(cache, PerformanceGoal.MAXIMIZE_HIT_RATE)
        
        print(f"✅ Optimization status: {optimization_result['status']}")
        if optimization_result['optimizations_applied']:
            print(f"🔧 Applied optimizations: {optimization_result['optimizations_applied']}")
        
    finally:
        await cache.close()


# Example 7: Health Monitoring
async def example_health_monitoring():
    """Demonstrate cache health monitoring."""
    print("\n🏥 Example 7: Health Monitoring")
    print("=" * 50)
    
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",
        enable_monitoring=True
    )
    
    try:
        await cache.initialize()
        
        # Perform health check
        health_check = await cache.health_check()
        
        print(f"🏥 Overall health: {health_check.overall_health}")
        print(f"🔌 Redis connected: {health_check.redis_connected}")
        print(f"💾 L1 cache healthy: {health_check.l1_cache_healthy}")
        print(f"🧠 Memory pressure: {health_check.memory_pressure}")
        print(f"🔐 Security status: {health_check.security_status}")
        
        if health_check.issues:
            print(f"\n⚠️  Issues found:")
            for issue in health_check.issues:
                print(f"   - {issue}")
        
        if health_check.recommendations:
            print(f"\n💡 Recommendations:")
            for recommendation in health_check.recommendations:
                print(f"   - {recommendation}")
        
        # Get comprehensive statistics
        stats = await cache.get_stats()
        print(f"\n📊 Cache Statistics:")
        print(f"   Hit rate: {stats.hit_rate:.2%}")
        print(f"   Total operations: {stats.total_operations}")
        print(f"   Memory usage: {stats.memory_usage_mb:.1f} MB")
        print(f"   Average latency: {stats.avg_latency_ms:.2f} ms")
        
    finally:
        await cache.close()


# Example 8: Production Setup
async def example_production_setup():
    """Demonstrate production-ready cache setup."""
    print("\n🏭 Example 8: Production Setup")
    print("=" * 50)
    
    # Note: This example assumes you have Redis cluster nodes available
    # For demonstration, we'll show the configuration
    
    print("Production cache configuration:")
    
    config = IntegratedCacheConfig(
        # Redis cluster for high availability
        redis_cluster_nodes=[
            "redis-node1:6379",
            "redis-node2:6379", 
            "redis-node3:6379"
        ],
        
        # Security enabled
        enable_security=True,
        enable_encryption=True,
        enable_access_control=True,
        enable_audit_logging=True,
        
        # Performance optimizations
        enable_compression=True,
        enable_l1_cache=True,
        l1_max_size=10000,
        default_ttl=7200.0,  # 2 hours
        
        # Monitoring enabled
        enable_monitoring=True,
        enable_memory_monitoring=True,
        
        # Consistency settings
        consistency_level=ConsistencyLevel.EVENTUAL,
        invalidation_strategy=InvalidationStrategy.EVENT_BASED
    )
    
    print(f"✅ Redis cluster nodes: {len(config.redis_cluster_nodes or [])}")
    print(f"✅ Security enabled: {config.enable_security}")
    print(f"✅ Encryption enabled: {config.enable_encryption}")
    print(f"✅ L1 cache size: {config.l1_max_size}")
    print(f"✅ Default TTL: {config.default_ttl}s")
    print(f"✅ Monitoring enabled: {config.enable_monitoring}")
    
    # For actual production use:
    # cache = IntegratedCacheManager(config)
    # await cache.initialize()
    
    print("\n🔧 Production setup would include:")
    print("   - Redis cluster with replication")
    print("   - SSL/TLS encryption in transit")
    print("   - Role-based access control")
    print("   - Comprehensive monitoring")
    print("   - Automated performance tuning")
    print("   - Health checks and alerting")


# Example 9: Error Handling and Resilience
async def example_error_handling():
    """Demonstrate error handling and resilience features."""
    print("\n🛡️  Example 9: Error Handling and Resilience")
    print("=" * 50)
    
    # Create cache with resilience settings
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",  # This might fail in CI
        enable_monitoring=True
    )
    
    try:
        await cache.initialize()
        print("✅ Cache initialized successfully")
        
        # Test graceful degradation
        print("\nTesting graceful degradation...")
        
        # Even if Redis is unavailable, L1 cache should work
        await cache.set("local:test", {"message": "L1 cache working"})
        local_data = await cache.get("local:test")
        print(f"✅ L1 cache operation: {local_data}")
        
        # Test with invalid key
        invalid_result = await cache.get("", "default")
        print(f"✅ Invalid key handling: {invalid_result}")
        
        # Test large value handling
        large_value = {"data": "x" * 1000000}  # 1MB of data
        large_set_result = await cache.set("large:value", large_value)
        print(f"✅ Large value handling: {large_set_result}")
        
    except Exception as e:
        print(f"⚠️  Cache initialization failed: {e}")
        print("   This is normal in CI environments without Redis")
        print("   In production, implement proper Redis availability")
    
    finally:
        try:
            await cache.close()
            print("✅ Cache closed gracefully")
        except Exception as e:
            print(f"⚠️  Cache close warning: {e}")


# Main demonstration function
async def run_all_examples():
    """Run all cache examples in sequence."""
    print("🚀 Distributed Cache System Examples")
    print("=" * 60)
    
    examples = [
        example_basic_usage,
        example_security_features,
        example_cache_patterns,
        example_multilevel_caching,
        example_benchmarking,
        example_performance_tuning,
        example_health_monitoring,
        example_production_setup,
        example_error_handling
    ]
    
    for i, example in enumerate(examples, 1):
        try:
            await example()
            print(f"\n✅ Example {i} completed successfully")
        except Exception as e:
            print(f"\n❌ Example {i} failed: {e}")
            # Continue with other examples
        
        if i < len(examples):
            print("\n" + "─" * 30)
            await asyncio.sleep(1)  # Brief pause between examples
    
    print("\n🎉 All examples completed!")
    print("\nNext steps:")
    print("1. Set up Redis server for full functionality")
    print("2. Configure Redis cluster for production")
    print("3. Implement custom data loaders and writers")
    print("4. Set up monitoring and alerting")
    print("5. Configure automated performance tuning")


if __name__ == "__main__":
    # Run examples
    asyncio.run(run_all_examples())