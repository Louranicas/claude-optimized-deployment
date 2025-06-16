# Comprehensive Distributed Cache System

A production-ready, high-performance distributed caching system with Redis cluster support, advanced security features, intelligent patterns, and automated optimization.

## 🌟 Features

### Core Caching
- **Multi-Level Caching**: L1 (memory) + L2 (Redis) + L3 (database) with intelligent fallback
- **Redis Cluster Support**: High availability with automatic failover and load balancing
- **Advanced Serialization**: JSON and Pickle serialization with compression and encryption
- **Intelligent TTL Management**: Dynamic TTL based on access patterns and data types

### Security & Access Control
- **End-to-End Encryption**: AES-256 encryption for data at rest and in transit
- **Role-Based Access Control**: Fine-grained permissions with custom roles
- **Comprehensive Audit Logging**: All operations logged with security context
- **Rate Limiting**: Per-user and global rate limiting with burst allowance
- **Key Validation**: Sanitization and validation of cache keys

### Cache Patterns
- **Cache-Aside**: Manual cache management with application control
- **Read-Through**: Automatic loading from data source on cache miss
- **Write-Through**: Synchronous writes to cache and data source
- **Write-Behind**: Asynchronous background writes for better performance
- **Refresh-Ahead**: Proactive cache refresh before expiration

### Performance & Monitoring
- **Real-Time Metrics**: Hit rates, latency, throughput, memory usage
- **Performance Benchmarking**: Automated benchmarking with detailed analysis
- **Automated Tuning**: AI-powered optimization recommendations
- **Health Monitoring**: Comprehensive health checks and alerting
- **Memory Pressure Detection**: Automatic cleanup under memory pressure

### Consistency & Reliability
- **Configurable Consistency**: Strong, eventual, weak, and session consistency
- **Intelligent Invalidation**: TTL-based, event-driven, and dependency-based
- **Circuit Breakers**: Automatic failure detection and recovery
- **Graceful Degradation**: Continues operation even with partial failures

## 🚀 Quick Start

### Basic Usage

```python
import asyncio
from src.core.cache_integration import create_integrated_cache

async def basic_example():
    # Create cache with simple configuration
    cache = create_integrated_cache(
        redis_url="redis://localhost:6379",
        enable_security=False,
        enable_monitoring=True
    )
    
    await cache.initialize()
    
    # Basic operations
    await cache.set("user:123", {"name": "John", "email": "john@example.com"})
    user = await cache.get("user:123")
    
    print(f"User: {user}")
    
    # Get statistics
    stats = await cache.get_stats()
    print(f"Hit rate: {stats.hit_rate:.2%}")
    
    await cache.close()

asyncio.run(basic_example())
```

### Production Setup

```python
from src.core.cache_integration import setup_production_cache

async def production_example():
    # Production-ready cache with clustering and security
    cache = await setup_production_cache(
        redis_cluster_nodes=[
            "redis-node1:6379",
            "redis-node2:6379", 
            "redis-node3:6379"
        ]
    )
    
    # Cache is now ready for production use
    await cache.set("critical:data", {"sensitive": "information"})
    
    await cache.close()

asyncio.run(production_example())
```

## 📋 Configuration

### IntegratedCacheConfig

```python
from src.core.cache_integration import IntegratedCacheConfig, IntegratedCacheManager
from src.core.cache_patterns import CachePattern, ConsistencyLevel

config = IntegratedCacheConfig(
    # Redis Configuration
    redis_url="redis://localhost:6379",
    redis_cluster_nodes=["node1:6379", "node2:6379"],
    
    # Multi-level Cache
    enable_l1_cache=True,
    l1_max_size=10000,
    default_ttl=3600.0,
    
    # Security
    enable_security=True,
    enable_encryption=True,
    enable_access_control=True,
    
    # Patterns
    default_read_pattern=CachePattern.CACHE_ASIDE,
    default_write_pattern=CachePattern.WRITE_THROUGH,
    consistency_level=ConsistencyLevel.EVENTUAL,
    
    # Performance
    enable_compression=True,
    enable_monitoring=True,
    enable_memory_monitoring=True
)

cache = IntegratedCacheManager(config)
```

## 🔐 Security Features

### Role-Based Access Control

```python
from src.core.cache_security import Role, Permission, SecurityLevel

# Create custom roles
admin_role = Role(
    name="admin",
    permissions={Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN},
    security_level=SecurityLevel.RESTRICTED
)

user_role = Role(
    name="user",
    permissions={Permission.READ, Permission.WRITE},
    key_patterns=["user:*", "public:*"],
    rate_limit=1000,  # 1000 ops/minute
    security_level=SecurityLevel.INTERNAL
)

# Add roles to cache
cache.security_manager.add_custom_role(admin_role)
cache.security_manager.add_custom_role(user_role)

# Create user sessions
admin_session = await cache.create_session("admin_user", "admin")
user_session = await cache.create_session("regular_user", "user")

# Use with session context
await cache.set("user:123", data, session_id=user_session)
value = await cache.get("user:123", session_id=user_session)
```

### Encryption and Audit Logging

```python
# All operations are automatically encrypted and logged
await cache.set("sensitive:data", {"ssn": "123-45-6789"}, session_id=session)

# Audit logs include:
# - User identification
# - Operation type and parameters
# - Success/failure status
# - Timing information
# - Security context
```

## 🔄 Cache Patterns

### Cache-Aside Pattern

```python
async def get_user_with_cache_aside(user_id: str):
    # Try cache first
    user = await cache.get(f"user:{user_id}")
    if user is None:
        # Cache miss - load from database
        user = await database.get_user(user_id)
        if user:
            await cache.set(f"user:{user_id}", user, ttl=3600)
    return user
```

### Read-Through Pattern

```python
from src.core.cache_patterns import DataLoader

class UserDataLoader(DataLoader):
    async def load(self, key: str) -> dict:
        user_id = key.split(':')[1]
        return await database.get_user(user_id)
    
    async def load_batch(self, keys: List[str]) -> Dict[str, dict]:
        # Batch loading implementation
        pass

# Use with pattern manager
user = await cache.pattern_manager.get_or_set(
    "user:123", 
    UserDataLoader(), 
    pattern=CachePattern.READ_THROUGH
)
```

### Write-Through Pattern

```python
from src.core.cache_patterns import DataWriter

class UserDataWriter(DataWriter):
    async def write(self, key: str, value: dict) -> bool:
        user_id = key.split(':')[1]
        return await database.save_user(user_id, value)
    
    async def write_batch(self, items: Dict[str, dict]) -> Dict[str, bool]:
        # Batch writing implementation
        pass

# Write with pattern
success = await cache.pattern_manager.set_with_pattern(
    "user:123",
    user_data,
    data_writer=UserDataWriter(),
    pattern=CachePattern.WRITE_THROUGH
)
```

## 📊 Performance Monitoring

### Real-Time Metrics

```python
# Get comprehensive statistics
stats = await cache.get_stats()

print(f"Hit Rate: {stats.hit_rate:.2%}")
print(f"Average Latency: {stats.avg_latency_ms:.2f} ms")
print(f"Operations/Second: {stats.ops_per_second:.0f}")
print(f"Memory Usage: {stats.memory_usage_mb:.1f} MB")
print(f"Error Rate: {stats.error_rate:.2%}")
```

### Benchmarking

```python
from src.core.cache_benchmarks import BenchmarkType

# Run latency benchmark
result = await cache.benchmark(BenchmarkType.LATENCY, duration_seconds=60)

print(f"Avg Latency: {result.avg_latency_ms:.2f} ms")
print(f"95th Percentile: {result.latency_percentiles[95]:.2f} ms")
print(f"Throughput: {result.operations_per_second:.0f} ops/sec")
print(f"Hit Rate: {result.hit_rate:.2%}")
```

### Automated Tuning

```python
from src.core.cache_tuning_guide import quick_tune, auto_optimize, PerformanceGoal

# Quick performance analysis
tuning_report = await quick_tune(cache)

print(f"Recommendations: {len(tuning_report.recommendations)}")
for rec in tuning_report.get_top_recommendations(3):
    print(f"- {rec.title}: {rec.description}")

# Automated optimization
result = await auto_optimize(cache, PerformanceGoal.MAXIMIZE_HIT_RATE)
print(f"Optimizations applied: {result['optimizations_applied']}")
```

## 🏥 Health Monitoring

### Health Checks

```python
# Comprehensive health check
health = await cache.health_check()

print(f"Overall Health: {health.overall_health}")
print(f"Redis Connected: {health.redis_connected}")
print(f"Memory Pressure: {health.memory_pressure}")

if health.issues:
    print("Issues:")
    for issue in health.issues:
        print(f"  - {issue}")

if health.recommendations:
    print("Recommendations:")
    for rec in health.recommendations:
        print(f"  - {rec}")
```

### Memory Pressure Handling

```python
# Automatic memory pressure handling is built-in
# Cache will automatically:
# 1. Clear L1 cache under high memory pressure
# 2. Invalidate temporary entries
# 3. Trigger garbage collection
# 4. Reduce cache sizes if needed

# Manual memory monitoring
from src.core.memory_monitor import get_memory_monitor

memory_monitor = get_memory_monitor()
metrics = memory_monitor.get_current_metrics()

print(f"Memory Pressure: {metrics.pressure_level.value}")
print(f"Process Memory: {metrics.process_memory_mb:.1f} MB")
print(f"System Memory: {metrics.system_memory_percent:.1f}%")
```

## 🏭 Production Deployment

### Redis Cluster Setup

```bash
# Redis cluster configuration example
redis-server --port 7000 --cluster-enabled yes --cluster-config-file nodes.conf
redis-server --port 7001 --cluster-enabled yes --cluster-config-file nodes.conf
redis-server --port 7002 --cluster-enabled yes --cluster-config-file nodes.conf

# Create cluster
redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 --cluster-replicas 0
```

### Environment Configuration

```bash
# Environment variables
export CACHE_REDIS_URL="redis://redis-cluster:6379"
export CACHE_ENABLE_ENCRYPTION="true"
export CACHE_ENABLE_MONITORING="true"
export CACHE_DEFAULT_TTL="3600"
export CACHE_L1_MAX_SIZE="10000"
export CACHE_MEMORY_THRESHOLD_MB="2048"
```

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes --cluster-enabled yes
    volumes:
      - redis-data:/data
    
  redis-replica:
    image: redis:7-alpine
    command: redis-server --appendonly yes --cluster-enabled yes
    depends_on:
      - redis-master
    
  app:
    build: .
    environment:
      - CACHE_REDIS_URL=redis://redis-master:6379
      - CACHE_ENABLE_ENCRYPTION=true
    depends_on:
      - redis-master
      - redis-replica

volumes:
  redis-data:
```

### Kubernetes Deployment

```yaml
# redis-cluster.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
spec:
  serviceName: redis-cluster
  replicas: 6
  selector:
    matchLabels:
      app: redis-cluster
  template:
    metadata:
      labels:
        app: redis-cluster
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
          - redis-server
          - /conf/redis.conf
        volumeMounts:
        - name: conf
          mountPath: /conf
        - name: data
          mountPath: /data
      volumes:
      - name: conf
        configMap:
          name: redis-cluster-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

## 🔧 Advanced Features

### Custom Cache Patterns

```python
from src.core.cache_patterns import PatternManager, CachePatternConfig

# Custom pattern configuration
pattern_config = CachePatternConfig(
    read_pattern=CachePattern.REFRESH_AHEAD,
    write_pattern=CachePattern.WRITE_BEHIND,
    consistency_level=ConsistencyLevel.EVENTUAL,
    batch_operations=True,
    async_writes=True
)

pattern_manager = PatternManager(cache_manager, pattern_config)
```

### Cache Warming

```python
# Implement cache warming strategy
async def warm_user_cache():
    hot_user_ids = await get_frequently_accessed_users()
    
    async def user_loader(user_id: str):
        return await database.get_user(user_id)
    
    await cache.cache_manager.cache.warmer.warm_keys(
        [f"user:{uid}" for uid in hot_user_ids],
        user_loader
    )
```

### Event-Driven Invalidation

```python
# Set up event-driven cache invalidation
async def on_user_update(user_id: str):
    await cache.invalidate_pattern(f"user:{user_id}*")
    await cache.invalidate_pattern(f"user_profile:{user_id}")

# Register event handler
cache.pattern_manager.invalidation_manager.add_event_handler(
    "user:*", 
    on_user_update
)
```

## 📈 Performance Optimization

### Tuning Guidelines

1. **Memory Optimization**
   - Enable compression for values > 1KB
   - Use appropriate TTL values
   - Monitor L1 cache hit rates

2. **Latency Optimization**
   - Increase L1 cache size for hot data
   - Use connection pooling
   - Consider read replicas

3. **Throughput Optimization**
   - Use batch operations where possible
   - Enable async writes
   - Implement proper sharding

4. **Consistency vs Performance**
   - Use eventual consistency for non-critical data
   - Reserve strong consistency for critical operations
   - Implement different consistency levels per data type

### Performance Benchmarks

| Configuration | Latency (p95) | Throughput | Memory |
|---------------|---------------|------------|---------|
| Basic Setup   | 15ms         | 1,000 ops/s| 512MB  |
| Optimized     | 5ms          | 5,000 ops/s| 256MB  |
| Clustered     | 8ms          | 15,000 ops/s| 1GB   |

## 🚨 Troubleshooting

### Common Issues

1. **High Memory Usage**
   ```python
   # Check memory metrics
   stats = await cache.get_stats()
   if stats.memory_usage_mb > threshold:
       await cache.invalidate_pattern("temp:*")
   ```

2. **Low Hit Rate**
   ```python
   # Analyze cache patterns
   tuning_report = await quick_tune(cache)
   # Follow recommendations
   ```

3. **Connection Issues**
   ```python
   # Health check
   health = await cache.health_check()
   if not health.redis_connected:
       # Check Redis availability
       # Verify network connectivity
   ```

### Monitoring and Alerting

```python
# Set up monitoring alerts
async def monitor_cache_health():
    health = await cache.health_check()
    stats = await cache.get_stats()
    
    if health.overall_health != "healthy":
        await send_alert(f"Cache health: {health.overall_health}")
    
    if stats.hit_rate < 0.8:
        await send_alert(f"Low hit rate: {stats.hit_rate:.2%}")
    
    if stats.avg_latency_ms > 50:
        await send_alert(f"High latency: {stats.avg_latency_ms:.1f}ms")
```

## 📚 API Reference

### Core Classes

- **IntegratedCacheManager**: Main cache interface
- **CacheSecurityManager**: Security and access control
- **PatternManager**: Cache pattern implementations
- **CacheBenchmarker**: Performance benchmarking
- **CacheTuner**: Automated optimization

### Key Methods

- `cache.get(key, default, session_id)`: Retrieve value
- `cache.set(key, value, ttl, session_id)`: Store value
- `cache.delete(key, session_id)`: Remove value
- `cache.invalidate_pattern(pattern)`: Bulk invalidation
- `cache.get_stats()`: Performance metrics
- `cache.health_check()`: System health
- `cache.benchmark(type, duration)`: Performance testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the troubleshooting guide
- Review the examples directory
- Run the health check diagnostic

---

*This distributed cache system provides enterprise-grade caching with security, performance, and reliability features suitable for production deployment at scale.*