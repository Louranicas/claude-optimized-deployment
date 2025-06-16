# Comprehensive Retry Patterns Guide

This guide covers the comprehensive retry patterns implementation designed to prevent thundering herd and cascading failures.

## Overview

The retry patterns system provides:

- **Multiple retry strategies** with jitter to prevent thundering herd
- **Retry budgets** to prevent cascading failures
- **Idempotency key management** for safe retries
- **Service-specific retry policies** optimized for different service types
- **Circuit breaker integration** for fast failure detection
- **Graceful degradation patterns** with fallback strategies
- **Comprehensive monitoring** and metrics collection
- **Configuration management** for easy setup and updates
- **Testing framework** for validation and performance benchmarking

## Key Components

### 1. Retry Patterns (`src/core/retry_patterns.py`)

The core retry system with advanced strategies:

```python
from src.core.retry_patterns import comprehensive_retry, RetryStrategy, ServiceType

@comprehensive_retry(
    service_name="api_service",
    service_type=ServiceType.HTTP_API,
    custom_config=RetryPolicyConfig(
        max_attempts=5,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        enable_circuit_breaker=True,
        enable_retry_budget=True
    )
)
async def call_api():
    # Your API call here
    pass
```

**Available Retry Strategies:**
- `EXPONENTIAL` - Standard exponential backoff
- `EXPONENTIAL_JITTER` - Exponential with random jitter (recommended)
- `LINEAR` - Linear delay increase
- `FIXED` - Fixed delay between attempts
- `ADAPTIVE` - Adaptive delay based on system metrics
- `FIBONACCI` - Fibonacci sequence delays
- `DECORRELATED_JITTER` - AWS-style decorrelated jitter
- `CONSTANT_JITTER` - Fixed delay with jitter

### 2. Configuration Management (`src/core/retry_config.py`)

Centralized configuration with validation:

```python
from src.core.retry_config import create_default_config_file, load_config_from_file

# Create default configuration
create_default_config_file("retry_config.yaml")

# Load configuration
load_config_from_file("retry_config.yaml")
```

**Configuration Templates:**
- `ai_service` - Optimized for AI/ML services
- `database` - Optimized for database operations
- `cache` - Optimized for cache operations
- `http_api` - Optimized for HTTP APIs
- `message_queue` - Optimized for message queues
- `microservice` - Optimized for microservices

### 3. Monitoring and Metrics (`src/core/retry_monitoring.py`)

Comprehensive monitoring with Prometheus integration:

```python
from src.core.retry_monitoring import get_retry_monitor, start_prometheus_server

# Start Prometheus metrics server
start_prometheus_server(port=8000)

# Get monitoring data
monitor = get_retry_monitor()
dashboard_data = await monitor.get_dashboard_data()
```

**Key Metrics:**
- Total retry attempts and success rates
- Response time distributions
- Circuit breaker state changes
- Retry budget consumption
- Error pattern analysis
- Service health scores

### 4. Graceful Degradation (`src/core/graceful_degradation.py`)

Service mesh with fallback strategies:

```python
from src.core.graceful_degradation import graceful_degradation, FallbackStrategy

@graceful_degradation(
    service_name="ai_service",
    fallback_strategy=FallbackStrategy(
        name="ai_fallback",
        fallback_func=lambda prompt: f"Cached response for: {prompt}",
        cache_enabled=True,
        cache_ttl=600
    )
)
async def call_ai_service(prompt):
    # AI service call
    pass
```

**Degradation Features:**
- Fallback functions and static responses
- Response caching with TTL
- Service redirection
- Load shedding based on system metrics
- Bulkhead isolation patterns
- Quality of Service (QoS) management

### 5. Unified Integration (`src/core/retry_integration.py`)

Unified interface for all resilience patterns:

```python
from src.core.retry_integration import resilient_service, resilient_call

@resilient_service(
    service_name="payment_service",
    service_type=ServiceType.MICROSERVICE,
    retry_enabled=True,
    circuit_breaker_enabled=True,
    degradation_enabled=True
)
async def process_payment(amount, currency):
    # Payment processing logic
    pass
```

### 6. Testing Framework (`src/core/retry_testing.py`)

Comprehensive testing and validation:

```python
from src.core.retry_testing import run_comprehensive_test_suite

# Run full test suite
test_results = await run_comprehensive_test_suite()
```

**Testing Features:**
- Unit tests for retry patterns
- Load testing with configurable parameters
- Chaos engineering for failure simulation
- Performance benchmarking
- Configuration validation

## Usage Examples

### Basic Retry with Jitter

```python
@comprehensive_retry(
    service_name="external_api",
    service_type=ServiceType.HTTP_API
)
async def call_external_api(data):
    async with httpx.AsyncClient() as client:
        response = await client.post("https://api.example.com", json=data)
        return response.json()
```

### AI Service with Specialized Policy

```python
@retry_ai_service("claude_api", max_attempts=5, base_delay=2.0)
async def call_claude(prompt):
    # Claude API call with AI-optimized retry
    response = await anthropic_client.completions.create(
        model="claude-3-sonnet-20240229",
        prompt=prompt
    )
    return response.completion
```

### Database with Linear Backoff

```python
@retry_database("postgres_db", max_attempts=3, base_delay=0.5)
async def db_query(query, params):
    async with database.transaction():
        return await database.fetch_all(query, params)
```

### Service with Complete Resilience

```python
@resilient_service(
    service_name="critical_service",
    service_type=ServiceType.MICROSERVICE,
    priority=ServicePriority.CRITICAL
)
async def critical_operation(data):
    # Critical business operation with full protection
    return await process_critical_data(data)
```

## Configuration File Example

```yaml
global:
  enable_global_metrics: true
  metrics_export_interval: 300
  max_concurrent_retries_global: 100
  circuit_breaker_enabled_globally: true
  retry_budget_enabled_globally: true
  prometheus_enabled: true
  prometheus_port: 8000

services:
  claude_api:
    template: ai_service
    max_attempts: 5
    base_delay: 2.0
    max_delay: 60.0
    strategy: exponential_jitter
    service_type: ai_claude
    retryable_status_codes: [408, 429, 500, 502, 503, 504]
    
  postgres_db:
    template: database
    max_attempts: 3
    base_delay: 0.5
    max_delay: 5.0
    strategy: linear
    
  redis_cache:
    template: cache
    max_attempts: 2
    base_delay: 0.1
    max_delay: 1.0
    strategy: fixed
```

## Best Practices

### 1. Preventing Thundering Herd

- **Use jitter in retry strategies** - Always prefer `EXPONENTIAL_JITTER` or `DECORRELATED_JITTER`
- **Implement retry budgets** - Set appropriate limits per service and globally
- **Stagger retry attempts** - Use different base delays for different service instances

### 2. Preventing Cascading Failures

- **Enable circuit breakers** - Set appropriate failure thresholds
- **Use bulkhead isolation** - Limit concurrent operations per service
- **Implement load shedding** - Drop non-critical requests under high load
- **Set retry budgets** - Prevent retry storms during outages

### 3. Service-Specific Optimization

- **AI Services**: Use longer delays (2-5s base) with exponential jitter
- **Databases**: Use short linear delays (0.5-2s) with few attempts
- **Caches**: Use minimal retries (1-2 attempts) with fixed short delays
- **HTTP APIs**: Use exponential jitter with status code-based retries

### 4. Monitoring and Alerting

- **Track success rates** - Alert on drops below 95%
- **Monitor response times** - Alert on P95 increases
- **Watch circuit breaker activations** - Investigate frequent trips
- **Track retry budget consumption** - Adjust limits as needed

### 5. Testing and Validation

- **Run load tests** - Validate behavior under high concurrency
- **Test failure scenarios** - Ensure graceful degradation works
- **Validate configuration** - Use the built-in validation framework
- **Monitor in production** - Continuously adjust based on real metrics

## Advanced Features

### Idempotency Management

```python
from src.core.retry_patterns import RedisIdempotencyProvider

# Use Redis for distributed idempotency
config = RetryPolicyConfig(
    enable_idempotency=True,
    idempotency_provider=RedisIdempotencyProvider(redis_client)
)
```

### Custom Fallback Strategies

```python
def intelligent_fallback(prompt):
    # Check cache first
    cached = cache.get(f"fallback:{hash(prompt)}")
    if cached:
        return cached
    
    # Generate simplified response
    simplified = generate_simple_response(prompt)
    cache.set(f"fallback:{hash(prompt)}", simplified, ttl=3600)
    return simplified

fallback_strategy = FallbackStrategy(
    name="intelligent_ai_fallback",
    fallback_func=intelligent_fallback,
    cache_enabled=True,
    cache_ttl=3600
)
```

### Dynamic Configuration Updates

```python
manager = get_unified_manager()

# Update service configuration at runtime
await manager.update_service_config(
    "api_service",
    {
        "max_attempts": 3,
        "base_delay": 1.5,
        "strategy": RetryStrategy.LINEAR
    }
)
```

### Custom Retry Budgets

```python
from src.core.retry_patterns import RetryBudgetConfig, RetryBudgetType

budget_config = RetryBudgetConfig(
    budget_type=RetryBudgetType.SLIDING_WINDOW,
    max_retries_per_minute=100,
    max_retries_per_hour=1000,
    burst_capacity=20
)
```

## Performance Considerations

### Memory Usage

- Retry handlers cache minimal state
- Event history is bounded with configurable limits
- Weak references prevent memory leaks
- Automatic cleanup between retry attempts

### CPU Usage

- Efficient jitter calculations
- Minimal overhead per retry attempt
- Asynchronous operations throughout
- Optional Prometheus metrics (can be disabled)

### Network Efficiency

- Jitter prevents synchronized retries
- Circuit breakers reduce unnecessary calls
- Load shedding protects downstream services
- Adaptive timeouts based on service health

## Troubleshooting

### High Retry Rates

1. Check service health metrics
2. Verify retry configuration isn't too aggressive
3. Look for patterns in error types
4. Consider increasing base delays or reducing attempts

### Circuit Breaker Frequently Open

1. Review failure thresholds
2. Check if timeouts are appropriate
3. Verify service dependency health
4. Consider implementing better fallbacks

### Poor Performance

1. Monitor retry distribution metrics
2. Check if jitter is enabled
3. Verify timeouts aren't too long
4. Review concurrent operation limits

### Configuration Issues

1. Use the validation framework
2. Check logs for configuration errors
3. Verify service type mappings
4. Test with minimal configuration first

## Migration Guide

### From Basic Retry

```python
# Old approach
@retry(max_attempts=3)
async def old_function():
    pass

# New approach
@comprehensive_retry("service_name", ServiceType.HTTP_API)
async def new_function():
    pass
```

### From Custom Circuit Breaker

```python
# Old approach
circuit_breaker = CircuitBreaker()
await circuit_breaker.call(my_function)

# New approach
@resilient_service("service_name")
async def my_function():
    pass
```

### Adding to Existing Services

1. Start with monitoring only
2. Add basic retry patterns
3. Enable circuit breakers
4. Implement graceful degradation
5. Optimize based on metrics

## Security Considerations

- Idempotency keys are hashed for privacy
- Sensitive data is not logged in retry events
- Redis connections should use authentication
- Prometheus metrics don't expose sensitive information
- Configuration files should be secured appropriately

## Deployment Checklist

- [ ] Configuration file created and validated
- [ ] Prometheus monitoring configured (optional)
- [ ] Redis available for distributed features (optional)
- [ ] Service dependencies mapped correctly
- [ ] Fallback strategies implemented for critical services
- [ ] Retry budgets set appropriately
- [ ] Circuit breaker thresholds configured
- [ ] Load testing completed
- [ ] Monitoring and alerting set up
- [ ] Documentation updated for team