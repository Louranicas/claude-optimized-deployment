# Connection Pooling Configuration Guide

This guide explains how to configure and optimize connection pooling in the Claude-Optimized Deployment Engine for production use.

## Overview

The connection pooling system provides centralized management of all network connections, preventing resource exhaustion and improving performance through:

- **HTTP/HTTPS Connection Pooling**: For API calls to AI providers and external services
- **Database Connection Pooling**: For PostgreSQL and MongoDB connections
- **Redis Connection Pooling**: For caching and session management
- **WebSocket Connection Management**: For real-time connections with automatic reconnection

## Configuration

### Environment Variables

```bash
# Connection Pool Limits
CONNECTION_POOL_HTTP_TOTAL=200          # Total HTTP connections across all hosts
CONNECTION_POOL_HTTP_PER_HOST=20        # Max connections per host
CONNECTION_POOL_HTTP_KEEPALIVE=60       # Keepalive timeout in seconds
CONNECTION_POOL_HTTP_TIMEOUT=120        # Request timeout in seconds

# Database Pool Settings
CONNECTION_POOL_DB_MIN=5                # Minimum database connections
CONNECTION_POOL_DB_MAX=20               # Maximum database connections
CONNECTION_POOL_DB_IDLE_TIMEOUT=300     # Idle connection timeout (5 minutes)
CONNECTION_POOL_DB_COMMAND_TIMEOUT=30   # Query timeout in seconds

# Redis Pool Settings
CONNECTION_POOL_REDIS_MAX=50            # Maximum Redis connections
CONNECTION_POOL_REDIS_TIMEOUT=5         # Connection timeout in seconds

# WebSocket Settings
CONNECTION_POOL_WS_MAX=50               # Maximum WebSocket connections
CONNECTION_POOL_WS_HEARTBEAT=30         # Heartbeat interval in seconds
CONNECTION_POOL_WS_RECONNECT=5          # Reconnection interval in seconds

# Monitoring
CONNECTION_POOL_MONITORING=true         # Enable connection monitoring
CONNECTION_POOL_HEALTH_CHECK=60         # Health check interval in seconds
```

### Programmatic Configuration

```python
from src.core.connections import ConnectionPoolConfig, get_connection_manager

# Create custom configuration
config = ConnectionPoolConfig(
    # HTTP settings
    http_total_connections=200,
    http_per_host_connections=20,
    http_keepalive_timeout=60,
    http_connect_timeout=15,
    http_request_timeout=120,
    
    # Database settings
    db_min_connections=5,
    db_max_connections=20,
    db_connection_timeout=10,
    db_command_timeout=30,
    db_idle_timeout=300,
    
    # Redis settings
    redis_max_connections=50,
    redis_connection_timeout=5,
    redis_socket_timeout=5,
    redis_keepalive=True,
    
    # WebSocket settings
    ws_max_connections=50,
    ws_heartbeat_interval=30,
    ws_reconnect_interval=5,
    
    # General settings
    health_check_interval=60,
    connection_lifetime=3600,  # 1 hour
    enable_monitoring=True
)

# Initialize with custom config
manager = await get_connection_manager(config)
```

## Usage Examples

### HTTP Connections

```python
from src.core.connections import get_connection_manager

# Get connection manager
manager = await get_connection_manager()

# Use HTTP pool
async with manager.http_pool.get_session("https://api.example.com") as session:
    async with session.get("/endpoint") as response:
        data = await response.json()

# Or use the request method directly
response = await manager.http_pool.request("GET", "https://api.example.com/endpoint")
```

### Database Connections

```python
# PostgreSQL
async with manager.db_pool.get_postgres_connection("postgresql://user:pass@host/db") as conn:
    result = await conn.fetch("SELECT * FROM users")

# MongoDB
client = manager.db_pool.get_mongo_client("mongodb://localhost:27017")
db = client.mydatabase
collection = db.mycollection
```

### Redis Connections

```python
# Get Redis connection
redis = await manager.redis_pool.get_redis("redis://localhost:6379")

# Execute commands
await redis.set("key", "value")
value = await redis.get("key")

# Or use execute method
result = await manager.redis_pool.execute(
    "redis://localhost:6379",
    "hset",
    "myhash",
    "field",
    "value"
)
```

### WebSocket Connections

```python
# Connect to WebSocket
ws = await manager.ws_pool.connect("wss://example.com/ws")

# Send and receive
await manager.ws_pool.send("wss://example.com/ws", "Hello")
msg = await manager.ws_pool.receive("wss://example.com/ws")
```

## Monitoring and Metrics

### Enable Monitoring

```python
from src.core.connection_monitoring import get_connection_monitor

# Get monitor instance
monitor = await get_connection_monitor()

# Start monitoring (automatically started on first access)
await monitor.start()

# Get health report
health = await monitor.get_health_report()
print(f"Status: {health['status']}")
print(f"Error rate: {health['overall_error_rate']:.1%}")

# Get Prometheus metrics
metrics = monitor.get_metrics()
```

### Available Metrics

- `connection_pool_active_connections`: Current active connections by pool and host
- `connection_pool_total_connections`: Total connections created
- `connection_pool_failed_connections`: Failed connection attempts
- `connection_pool_wait_seconds`: Time spent waiting for connections
- `connection_pool_request_duration_seconds`: Request duration through pools
- `connection_pool_error_rate`: Connection error rate
- `connection_pool_efficiency`: Connection reuse efficiency

### Health Check Endpoint

```python
from src.core.connection_monitoring import ConnectionPoolHealthCheck

# Create health check
health_check = ConnectionPoolHealthCheck(monitor)

# In your FastAPI/Flask app
@app.get("/health/connections")
async def connection_health():
    return await health_check.check_health()

@app.get("/metrics")
async def prometheus_metrics():
    metrics = await health_check.get_metrics()
    return Response(metrics, media_type="text/plain")
```

## Production Best Practices

### 1. Resource Limits

Set appropriate limits based on your infrastructure:

```python
# For high-traffic production
config = ConnectionPoolConfig(
    http_total_connections=500,      # Support many concurrent requests
    http_per_host_connections=50,    # Higher per-host for main APIs
    db_max_connections=100,          # Scale with database capacity
    redis_max_connections=200        # Redis can handle many connections
)

# For resource-constrained environments
config = ConnectionPoolConfig(
    http_total_connections=50,
    http_per_host_connections=5,
    db_max_connections=10,
    redis_max_connections=20
)
```

### 2. Timeout Configuration

Balance between reliability and resource usage:

```python
config = ConnectionPoolConfig(
    # Short timeouts for fast failure
    http_connect_timeout=5,          # Fail fast on connection
    redis_connection_timeout=2,      # Redis should be fast
    
    # Longer timeouts for operations
    http_request_timeout=60,         # Allow time for AI responses
    db_command_timeout=30,           # Complex queries need time
    
    # Keepalive for connection reuse
    http_keepalive_timeout=120,      # Keep connections alive longer
    db_idle_timeout=600              # Database connections are expensive
)
```

### 3. Monitoring and Alerting

Set up alerts for connection pool health:

```yaml
# Prometheus alert rules
groups:
  - name: connection_pools
    rules:
      - alert: HighConnectionPoolErrorRate
        expr: connection_pool_error_rate > 0.1
        for: 5m
        annotations:
          summary: "High error rate in connection pool"
          
      - alert: ConnectionPoolExhaustion
        expr: connection_pool_active_connections / CONNECTION_LIMIT > 0.9
        for: 2m
        annotations:
          summary: "Connection pool near exhaustion"
```

### 4. Graceful Shutdown

Always close connection pools properly:

```python
import signal
import asyncio
from src.core.connections import close_all_connections

async def shutdown():
    """Graceful shutdown handler."""
    logger.info("Shutting down connection pools...")
    await close_all_connections()
    logger.info("Connection pools closed")

# Register shutdown handler
loop = asyncio.get_event_loop()
for sig in (signal.SIGTERM, signal.SIGINT):
    loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown()))
```

### 5. Connection Pool Tuning

Monitor and adjust based on metrics:

```python
# Check efficiency
health = await monitor.get_health_report()
for pool_type, data in health['pools'].items():
    for host, metrics in data['hosts'].items():
        efficiency = metrics['efficiency']
        if efficiency < 0.5:
            logger.warning(
                f"Low efficiency for {pool_type} {host}: {efficiency:.1%}"
            )
            # Consider increasing pool size or connection lifetime
```

## Troubleshooting

### Common Issues

1. **Connection Pool Exhaustion**
   ```python
   # Symptom: Timeouts waiting for connections
   # Solution: Increase pool limits
   config.http_total_connections = 300
   config.http_per_host_connections = 30
   ```

2. **High Connection Wait Times**
   ```python
   # Symptom: Slow requests despite fast backends
   # Solution: Pre-warm connections
   async def prewarm_connections():
       manager = await get_connection_manager()
       critical_hosts = ["https://api.openai.com", "https://api.anthropic.com"]
       for host in critical_hosts:
           async with manager.http_pool.get_session(host) as session:
               pass  # Just establish connection
   ```

3. **Memory Leaks**
   ```python
   # Symptom: Growing memory usage
   # Solution: Set connection lifetime limits
   config.connection_lifetime = 1800  # 30 minutes
   config.http_keepalive_timeout = 30  # Shorter keepalive
   ```

### Debug Logging

Enable detailed logging for troubleshooting:

```python
import logging

# Enable connection pool logging
logging.getLogger("src.core.connections").setLevel(logging.DEBUG)
logging.getLogger("aiohttp.client").setLevel(logging.DEBUG)

# Log pool metrics periodically
async def log_pool_stats():
    manager = await get_connection_manager()
    while True:
        metrics = manager.get_all_metrics()
        for pool_type, pool_metrics in metrics.items():
            logger.info(f"{pool_type} pool stats: {pool_metrics}")
        await asyncio.sleep(60)
```

## Integration with Existing Code

### Updating Expert Clients

The expert clients have been updated to use connection pooling automatically:

```python
# No code changes needed - pooling is transparent
expert = DeepSeekExpertClient(api_key="...")
response = await expert.generate_response(query)
```

### Updating MCP Servers

MCP servers now use pooled connections:

```python
# Prometheus server example
prometheus_server = PrometheusMonitoringMCP()
# Connection pooling is handled internally
result = await prometheus_server.call_tool("prometheus_query", {"query": "up"})
```

## Performance Impact

Expected improvements with connection pooling:

- **Reduced Latency**: 30-50% reduction in connection establishment time
- **Higher Throughput**: 2-3x increase in requests per second
- **Lower Resource Usage**: 60-80% reduction in file descriptors
- **Better Reliability**: Automatic retry and reconnection
- **Improved Monitoring**: Real-time visibility into connection health

## Conclusion

Proper connection pooling is essential for production deployments. Follow these guidelines to:

1. Configure appropriate limits for your workload
2. Monitor connection health and efficiency
3. Set up alerting for pool exhaustion
4. Implement graceful shutdown
5. Tune based on real-world metrics

For additional support, check the monitoring dashboard or review the connection pool metrics in Prometheus.