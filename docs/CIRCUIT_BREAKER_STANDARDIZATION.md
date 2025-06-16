# Circuit Breaker Standardization Guide

This document provides a comprehensive guide to the standardized circuit breaker patterns implemented across all services in the project.

## Table of Contents

1. [Overview](#overview)
2. [Circuit Breaker Types](#circuit-breaker-types)
3. [Core Components](#core-components)
4. [Integration Patterns](#integration-patterns)
5. [Configuration Management](#configuration-management)
6. [Monitoring and Metrics](#monitoring-and-metrics)
7. [Best Practices](#best-practices)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

## Overview

The standardized circuit breaker system provides unified protection for all external dependencies, ensuring system resilience and graceful degradation under failure conditions.

### Key Features

- **Multiple Circuit Breaker Types**: Count-based, time-based, percentage-based, and adaptive
- **Service-Specific Protection**: AI providers, MCP servers, databases, external APIs
- **FastAPI Middleware Integration**: Route-level protection
- **Bulkhead Pattern**: Service isolation and resource management
- **Health Monitoring**: Automatic recovery and health checking
- **Comprehensive Metrics**: Real-time monitoring and alerting
- **Configuration Management**: Environment-specific settings and templates

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Standardized Circuit Breaker System      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   AI/LLM    │  │     MCP     │  │  Database   │          │
│  │  Services   │  │   Servers   │  │ Connections │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  External   │  │   FastAPI   │  │  Monitoring │          │
│  │    APIs     │  │ Middleware  │  │ & Alerting  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Configuration Management               │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Circuit Breaker Types

### 1. Count-Based Circuit Breaker

Opens after a specific number of consecutive failures.

```python
from src.core.circuit_breaker_standard import StandardizedCircuitBreakerFactory, CircuitBreakerType

# Create count-based breaker
breaker = StandardizedCircuitBreakerFactory.create_mcp_service_breaker(
    "docker_service", 
    CircuitBreakerType.COUNT_BASED
)

# Use the breaker
@breaker
async def docker_operation():
    return await docker_client.list_containers()
```

**Best for**: MCP servers, internal services with predictable failure patterns

### 2. Time-Based Circuit Breaker

Opens based on failure rate within a time window.

```python
# Create time-based breaker
breaker = StandardizedCircuitBreakerFactory.create_external_api_breaker(
    "payment_api",
    CircuitBreakerType.TIME_BASED
)

# Use with explicit calls
result = await breaker.call(payment_api.charge, amount=100.0)
```

**Best for**: External APIs, services with variable load patterns

### 3. Percentage-Based Circuit Breaker

Opens when failure percentage exceeds threshold in sliding window.

```python
# Create percentage-based breaker
breaker = StandardizedCircuitBreakerFactory.create_database_breaker(
    "main_db",
    CircuitBreakerType.PERCENTAGE_BASED
)

# Use with database operations
async with breaker.get_connection() as conn:
    result = await conn.execute("SELECT * FROM users")
```

**Best for**: Databases, high-volume services

### 4. Adaptive Circuit Breaker

Dynamically adjusts thresholds based on service behavior and performance.

```python
# Create adaptive breaker
breaker = StandardizedCircuitBreakerFactory.create_ai_provider_breaker(
    "claude_anthropic",
    CircuitBreakerType.ADAPTIVE
)

# Use for AI calls
result = await breaker.call(ai_client.complete, prompt="Hello, world!")
```

**Best for**: AI/LLM providers, services with variable performance characteristics

## Core Components

### StandardizedCircuitBreaker

Main interface for all circuit breaker operations.

```python
from src.core.circuit_breaker_standard import get_standardized_circuit_breaker

# Get or create a standardized breaker
breaker = get_standardized_circuit_breaker(
    name="my_service",
    breaker_type="external",  # ai, mcp, database, external
    circuit_type=CircuitBreakerType.ADAPTIVE
)

# Execute protected calls
result = await breaker.call(my_function, arg1, arg2)

# Get metrics
metrics = breaker.get_metrics()
print(f"State: {breaker.get_state()}")
```

### DatabaseCircuitBreaker

Specialized protection for database operations.

```python
from src.core.circuit_breaker_database import get_database_circuit_breaker

# Get database breaker
db_breaker = get_database_circuit_breaker("main_database")

# Connection management
async with db_breaker.get_connection() as conn:
    # Execute queries with protection
    result = await db_breaker.execute_query(
        "SELECT * FROM users WHERE active = ?", 
        [True]
    )

# Transaction management
async with db_breaker.transaction() as tx:
    await tx.execute("INSERT INTO audit_log ...")
    await tx.execute("UPDATE user_stats ...")
```

### MCPCircuitBreaker

Specialized protection for MCP server communications.

```python
from src.core.circuit_breaker_mcp import get_mcp_circuit_breaker, MCPServerConfig, MCPServerType

# Configure MCP server
server_config = MCPServerConfig(
    name="docker_server",
    server_type=MCPServerType.DOCKER,
    transport_uri="stdio",
    command=["docker", "mcp"],
    tools={"run_container", "list_containers"},
    resources={"container_logs"}
)

# Get MCP breaker
mcp_breaker = get_mcp_circuit_breaker("docker_server", server_config)

# Connect and use
await mcp_breaker.connect()
result = await mcp_breaker.call_tool("list_containers", {"filter": "running"})
logs = await mcp_breaker.read_resource("container://nginx/logs")
```

## Integration Patterns

### FastAPI Middleware

Automatic route-level protection for web APIs.

```python
from fastapi import FastAPI
from src.core.circuit_breaker_middleware import setup_fastapi_circuit_breakers, RouteCircuitBreakerConfig

app = FastAPI()

# Configure route protection
route_configs = [
    RouteCircuitBreakerConfig(
        route_pattern="/api/v1/query/*",
        service_name="query_handler",
        circuit_type=CircuitBreakerType.ADAPTIVE,
        failure_threshold=3,
        max_concurrent_requests=50,
        fallback_response={"error": "Service temporarily unavailable"}
    ),
    RouteCircuitBreakerConfig(
        route_pattern="/api/v1/experts/*",
        service_name="experts",
        circuit_type=CircuitBreakerType.COUNT_BASED,
        failure_threshold=5,
        max_concurrent_requests=30
    )
]

# Setup middleware
setup_fastapi_circuit_breakers(app, route_configs)
```

### External Service Integration

Protect external API calls with standardized patterns.

```python
from src.core.circuit_breaker_middleware import get_external_service_manager, external_service_call

# Register external service
manager = get_external_service_manager()
manager.register_service(
    "payment_service",
    "https://api.payments.com",
    CircuitBreakerType.TIME_BASED,
    config_overrides={"failure_threshold": 3, "timeout": 30.0}
)

# Use decorator pattern
@external_service_call("payment_service")
async def process_payment(amount: float, currency: str):
    async with aiohttp.ClientSession() as session:
        async with session.post("/charge", json={"amount": amount, "currency": currency}) as resp:
            return await resp.json()

# Or direct calls
result = await manager.call_service("payment_service", process_payment, 100.0, "USD")
```

### Decorator Patterns

Convenient decorator-based protection.

```python
from src.core.circuit_breaker_database import database_operation
from src.core.circuit_breaker_mcp import mcp_tool_call

# Database operations
@database_operation("user_db")
async def get_user_profile(user_id: int):
    async with get_db_connection() as conn:
        return await conn.fetch("SELECT * FROM users WHERE id = $1", user_id)

# MCP tool calls
@mcp_tool_call("docker_server")
async def deploy_container(image: str, config: dict):
    return await docker_tools.run_container(image, config)
```

## Configuration Management

### Templates and Environments

```python
from src.core.circuit_breaker_configuration import create_circuit_breaker_config, get_configuration_manager

# Create from template
config = create_circuit_breaker_config(
    name="claude_production",
    template="ai_provider",
    environment="production",
    failure_threshold=2,  # Override for production
    timeout=30.0
)

# Manage configurations
config_manager = get_configuration_manager()

# Update existing configuration
config_manager.update_configuration(
    "claude_production",
    {"failure_threshold": 1, "timeout": 15.0}
)

# Environment-specific configs
prod_configs = config_manager.get_configurations_by_environment("production")
ai_configs = config_manager.get_configurations_by_tag("ai")
```

### Configuration Files

YAML configuration example:

```yaml
# config/circuit_breakers/claude_production.yaml
name: claude_production
circuit_type: adaptive
failure_threshold: 2
timeout: 30.0
failure_rate_threshold: 0.3
minimum_calls: 10
service_category: ai
priority: 1

bulkhead_config:
  max_concurrent_calls: 20
  isolation_pool_name: ai_claude_prod
  queue_timeout: 10.0

health_check_config:
  health_check_interval: 30.0
  health_check_timeout: 5.0

metadata:
  version: "1.0.0"
  environment: production
  template: ai_provider
  description: "Production Claude configuration"
  tags: ["ai", "production", "critical"]
```

## Monitoring and Metrics

### Real-time Monitoring

```python
from src.core.circuit_breaker_monitoring import get_circuit_breaker_monitor, start_circuit_breaker_monitoring

# Start monitoring system
await start_circuit_breaker_monitoring()

# Get monitor instance
monitor = get_circuit_breaker_monitor()

# Add custom alert rules
from src.core.circuit_breaker_monitoring import AlertRule, AlertType, AlertSeverity

custom_rule = AlertRule(
    name="critical_ai_failure",
    alert_type=AlertType.HIGH_FAILURE_RATE,
    severity=AlertSeverity.CRITICAL,
    condition=lambda m: m.service_category == "ai" and m.failure_rate > 0.8,
    cooldown_minutes=5
)
monitor.add_custom_alert_rule(custom_rule)

# Get dashboard data
dashboard = monitor.get_dashboard_data()
print(f"Overall health: {dashboard['overview']['health_percentage']:.1f}%")
```

### Custom Notifications

```python
# Add notification handlers
def slack_notification(alert):
    # Send to Slack
    slack_client.send_message(
        channel="#alerts",
        message=f"🚨 {alert.severity}: {alert.message}"
    )

def email_notification(alert):
    # Send email alert
    if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
        email_client.send_alert_email(alert)

monitor.add_notification_handler(slack_notification)
monitor.add_notification_handler(email_notification)
```

### Metrics Collection

```python
# Get comprehensive metrics
all_metrics = {}

# Standardized breakers
from src.core.circuit_breaker_standard import get_all_standardized_breakers
standardized = get_all_standardized_breakers()
for name, breaker in standardized.items():
    all_metrics[f"standard_{name}"] = breaker.get_metrics()

# Database breakers
from src.core.circuit_breaker_database import get_database_circuit_breaker_manager
db_manager = get_database_circuit_breaker_manager()
db_metrics = db_manager.get_all_metrics()
all_metrics.update({f"db_{k}": v for k, v in db_metrics.items()})

# MCP breakers
from src.core.circuit_breaker_mcp import get_mcp_circuit_breaker_manager
mcp_manager = get_mcp_circuit_breaker_manager()
mcp_metrics = mcp_manager.get_all_metrics()
all_metrics.update({f"mcp_{k}": v for k, v in mcp_metrics.items()})
```

## Best Practices

### 1. Service Type Selection

- **AI/LLM Services**: Use `ADAPTIVE` circuit breakers for variable response times
- **Databases**: Use `PERCENTAGE_BASED` for high-volume, consistent operations
- **MCP Servers**: Use `COUNT_BASED` for tool/resource-based operations
- **External APIs**: Use `TIME_BASED` for rate-limited or variable services

### 2. Configuration Guidelines

```python
# Production AI service
StandardCircuitBreakerConfig(
    failure_threshold=2,        # Low threshold for critical services
    timeout=30.0,              # Quick recovery attempts
    failure_rate_threshold=0.3, # Conservative failure rate
    minimum_calls=10,          # Sufficient sample size
    priority=1                 # High priority
)

# Development external API
StandardCircuitBreakerConfig(
    failure_threshold=10,       # Higher threshold for testing
    timeout=120.0,             # Longer recovery time
    failure_rate_threshold=0.7, # More permissive
    minimum_calls=5,           # Smaller sample for faster feedback
    priority=3                 # Lower priority
)
```

### 3. Error Handling

```python
from src.core.circuit_breaker_standard import CircuitOpenError

async def robust_ai_call():
    try:
        return await ai_breaker.call(ai_client.complete, prompt="Hello")
    except CircuitOpenError:
        # Circuit is open, use fallback
        return {"response": "Service temporarily unavailable", "fallback": True}
    except Exception as e:
        # Other errors - let circuit breaker handle them
        logger.error(f"AI call failed: {e}")
        raise
```

### 4. Bulkhead Configuration

```python
# High-priority service pool
BulkheadConfig(
    max_concurrent_calls=50,    # Higher capacity
    isolation_pool_name="critical_ai",
    queue_timeout=2.0          # Fast fail for high priority
)

# Low-priority service pool
BulkheadConfig(
    max_concurrent_calls=10,    # Limited capacity
    isolation_pool_name="batch_processing",
    queue_timeout=30.0         # Longer wait acceptable
)
```

### 5. Health Check Strategy

```python
# Database health check
HealthCheckConfig(
    health_check_interval=15.0,  # Frequent checks for critical service
    health_check_timeout=3.0,    # Quick timeout
    health_check_function=lambda: db.execute("SELECT 1")
)

# External API health check
HealthCheckConfig(
    health_check_interval=60.0,  # Less frequent for external services
    health_check_timeout=10.0,   # Longer timeout for network calls
    health_check_url="https://api.service.com/health"
)
```

## Examples

### Complete AI Provider Setup

```python
from src.core.circuit_breaker_standard import StandardizedCircuitBreakerFactory, CircuitBreakerType
from src.core.circuit_breaker_configuration import create_circuit_breaker_config

# 1. Create configuration
config = create_circuit_breaker_config(
    name="claude_anthropic_prod",
    template="ai_provider",
    environment="production",
    failure_threshold=2,
    timeout=30.0,
    priority=1
)

# 2. Create circuit breaker
claude_breaker = StandardizedCircuitBreakerFactory.create_ai_provider_breaker(
    "claude_anthropic",
    CircuitBreakerType.ADAPTIVE
)

# 3. Add state transition monitoring
async def log_state_change(service_name, from_state, to_state):
    logger.warning(f"Claude circuit breaker: {from_state} -> {to_state}")

claude_breaker.add_state_transition_callback(log_state_change)

# 4. Use in application
async def generate_response(prompt: str) -> str:
    try:
        response = await claude_breaker.call(
            anthropic_client.completions.create,
            model="claude-3-opus-20240229",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except CircuitOpenError:
        return "I'm temporarily unavailable. Please try again in a moment."
```

### Database Integration Example

```python
from src.core.circuit_breaker_database import get_database_circuit_breaker, DatabaseCircuitBreakerConfig
from src.core.circuit_breaker_configuration import create_circuit_breaker_config

# 1. Configure database circuit breaker
db_config = DatabaseCircuitBreakerConfig(
    database_name="main_db",
    max_connections=50,
    min_connections=5,
    query_timeout=30.0,
    health_check_query="SELECT 1",
    health_check_interval=15.0
)

# 2. Get database breaker
db_breaker = get_database_circuit_breaker("main_db", db_config)

# 3. Create repository with protection
class UserRepository:
    def __init__(self):
        self.db_breaker = db_breaker
    
    async def get_user(self, user_id: int):
        return await self.db_breaker.execute_query(
            "SELECT * FROM users WHERE id = ?", [user_id]
        )
    
    async def create_user(self, user_data: dict):
        async with self.db_breaker.transaction() as tx:
            user_id = await tx.execute(
                "INSERT INTO users (name, email) VALUES (?, ?)",
                [user_data["name"], user_data["email"]]
            )
            await tx.execute(
                "INSERT INTO user_profiles (user_id) VALUES (?)",
                [user_id]
            )
            return user_id
```

### MCP Server Example

```python
from src.core.circuit_breaker_mcp import (
    get_mcp_circuit_breaker, MCPServerConfig, MCPServerType, MCPCircuitBreakerConfig
)

# 1. Configure MCP server
server_config = MCPServerConfig(
    name="docker_server",
    server_type=MCPServerType.DOCKER,
    transport_uri="stdio",
    command=["python", "-m", "mcp_docker"],
    tools={"run_container", "list_containers", "stop_container"},
    resources={"container_logs", "container_stats"}
)

circuit_config = MCPCircuitBreakerConfig(
    tool_timeout=60.0,
    max_concurrent_tools=10,
    enable_tool_level_breakers=True,
    enable_server_failover=True
)

# 2. Get MCP breaker
docker_breaker = get_mcp_circuit_breaker("docker_server", server_config, circuit_config)

# 3. Create service wrapper
class DockerService:
    def __init__(self):
        self.mcp_breaker = docker_breaker
    
    async def initialize(self):
        return await self.mcp_breaker.connect()
    
    async def run_container(self, image: str, config: dict):
        return await self.mcp_breaker.call_tool(
            "run_container", 
            {"image": image, "config": config}
        )
    
    async def get_container_logs(self, container_id: str):
        return await self.mcp_breaker.read_resource(
            f"container://{container_id}/logs"
        )
```

## Troubleshooting

### Common Issues

#### 1. Circuit Breaker Opening Too Frequently

**Symptoms**: Circuit opens after few failures
**Solutions**:
- Increase `failure_threshold`
- Adjust `failure_rate_threshold` to be more permissive
- Increase `minimum_calls` for better sample size
- Check if service is actually unhealthy

```python
# More permissive configuration
config = StandardCircuitBreakerConfig(
    failure_threshold=10,        # Higher threshold
    failure_rate_threshold=0.7,  # More permissive rate
    minimum_calls=20             # Larger sample size
)
```

#### 2. Circuit Breaker Not Opening When Service is Down

**Symptoms**: Calls continue failing without circuit opening
**Solutions**:
- Decrease `failure_threshold`
- Lower `failure_rate_threshold`
- Ensure exceptions are not being caught before circuit breaker
- Check `excluded_exceptions` configuration

```python
# More sensitive configuration
config = StandardCircuitBreakerConfig(
    failure_threshold=3,         # Lower threshold
    failure_rate_threshold=0.3,  # Stricter rate
    minimum_calls=5              # Smaller sample for faster response
)
```

#### 3. Slow Recovery from Circuit Open State

**Symptoms**: Circuit stays open longer than expected
**Solutions**:
- Reduce `timeout` value
- Check health check configuration
- Verify service is actually recovering
- Consider using adaptive circuit breaker

```python
# Faster recovery configuration
config = StandardCircuitBreakerConfig(
    timeout=15.0,  # Shorter timeout
    health_check_config=HealthCheckConfig(
        health_check_interval=10.0,  # More frequent checks
        health_check_timeout=3.0     # Quick health verification
    )
)
```

#### 4. Memory Issues with Metrics Collection

**Symptoms**: High memory usage from metrics storage
**Solutions**:
- Adjust metrics collection interval
- Reduce sliding window size
- Limit history retention

```python
# Memory-optimized configuration
config = StandardCircuitBreakerConfig(
    sliding_window_size=50  # Smaller window
)

# Adjust monitoring collection interval
monitor = CircuitBreakerMonitor(collection_interval=60.0)  # Less frequent
```

### Debugging Tools

#### Enable Debug Logging

```python
import logging

# Enable debug logging for circuit breakers
logging.getLogger("src.core.circuit_breaker").setLevel(logging.DEBUG)
logging.getLogger("src.core.circuit_breaker_standard").setLevel(logging.DEBUG)
logging.getLogger("src.core.circuit_breaker_monitoring").setLevel(logging.DEBUG)
```

#### Metrics Inspection

```python
# Get detailed metrics for debugging
breaker = get_standardized_circuit_breaker("my_service")
metrics = breaker.get_metrics()

print(f"Current state: {breaker.get_state()}")
print(f"Total calls: {metrics['total_calls']}")
print(f"Failed calls: {metrics['failed_calls']}")
print(f"Failure rate: {metrics['failed_calls'] / max(1, metrics['total_calls']):.2%}")
print(f"Recent state changes: {metrics.get('state_changes', [])[-5:]}")
```

#### Health Status Check

```python
# Check comprehensive health status
from src.core.circuit_breaker_database import get_database_circuit_breaker_manager
from src.core.circuit_breaker_mcp import get_mcp_circuit_breaker_manager

# Database health
db_health = get_database_circuit_breaker_manager().get_health_summary()
print("Database Health:", db_health)

# MCP health
mcp_health = get_mcp_circuit_breaker_manager().get_health_summary()
print("MCP Health:", mcp_health)

# Overall monitoring health
monitor = get_circuit_breaker_monitor()
dashboard = monitor.get_dashboard_data()
print("Overall Health:", dashboard['overview'])
```

#### Configuration Validation

```python
from src.core.circuit_breaker_configuration import get_configuration_manager

config_manager = get_configuration_manager()
validator = config_manager.validator

# Validate specific configuration
config = {"failure_threshold": 5, "timeout": 30.0}
errors = validator.validate_config(config)
if errors:
    print("Configuration errors:", errors)
else:
    print("Configuration is valid")
```

## Conclusion

The standardized circuit breaker system provides comprehensive protection for all external dependencies while maintaining flexibility and ease of use. By following the patterns and best practices outlined in this guide, you can ensure your services are resilient, well-monitored, and properly configured for your specific environment and requirements.

For additional examples and advanced usage patterns, see the `examples/circuit_breaker_demo.py` file which demonstrates all the features described in this guide.