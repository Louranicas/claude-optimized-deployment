# Logging Best Practices
[CREATED: 2025-05-31]
[STATUS: Active]

## Overview

This guide outlines logging best practices for the Claude-Optimized Deployment Engine codebase. Following these practices ensures consistent, secure, and production-ready logging across all modules.

## Quick Start

```python
from src.core.logging_config import get_logger, get_performance_logger, get_security_logger

# Basic logging
logger = get_logger(__name__)
logger.info("Service started", extra={"structured_data": {"port": 8080}})

# Performance logging
perf_logger = get_performance_logger(__name__)
with perf_logger.track_operation("database_query", query="SELECT * FROM users"):
    # Your code here
    pass

# Security logging
security_logger = get_security_logger(__name__)
security_logger.log_access("users_api", "read", "user123", "success")
```

## Core Principles

### 1. Use Structured Logging

**DO:**
```python
logger.info("User login successful", extra={
    "structured_data": {
        "user_id": user_id,
        "ip_address": request.ip,
        "method": "oauth2"
    }
})
```

**DON'T:**
```python
logger.info(f"User {user_id} logged in from {request.ip} using oauth2")
```

### 2. Never Log Sensitive Data

**DO:**
```python
logger.info("API key validated", extra={
    "structured_data": {
        "key_id": api_key[:8] + "...",
        "valid": True
    }
})
```

**DON'T:**
```python
logger.info(f"API key {api_key} is valid")
```

### 3. Use Appropriate Log Levels

- **DEBUG**: Detailed information for diagnosing problems
- **INFO**: General informational messages
- **WARNING**: Something unexpected but handled
- **ERROR**: Error occurred but application continues
- **CRITICAL**: Serious error, application may not continue

```python
logger.debug("Calculating consensus scores", extra={"structured_data": {"responses": len(responses)}})
logger.info("Deployment started", extra={"structured_data": {"service": service_name}})
logger.warning("Rate limit approaching", extra={"structured_data": {"current": 90, "limit": 100}})
logger.error("Failed to connect to database", exc_info=True)
logger.critical("Configuration file missing", extra={"structured_data": {"path": config_path}})
```

### 4. Use Correlation IDs

```python
from src.core.logging_config import correlation_context

async def handle_request(request_id: str):
    with correlation_context(request_id):
        logger.info("Processing request")
        # All logs within this context will have the correlation ID
        await process_data()
```

### 5. Performance Logging

```python
from src.core.logging_config import performance_logged

@performance_logged("calculate_metrics")
def calculate_metrics(data):
    # Function execution time will be automatically logged
    return process(data)

# Or manually:
perf_logger = get_performance_logger(__name__)
with perf_logger.track_operation("api_call", endpoint="/users", method="GET"):
    response = await make_api_call()
```

## Module-Specific Guidelines

### MCP Operations

```python
from src.core.logging_config import mcp_logger

# Log tool calls
mcp_logger.log_tool_call("docker", "build", {"dockerfile": ".", "tag": "v1.0"})

# Log results
mcp_logger.log_tool_result("docker", "build", success=True, duration_ms=5000)
```

### AI Provider Requests

```python
from src.core.logging_config import ai_logger

# Log requests
ai_logger.log_request("openai", "gpt-4", prompt_tokens=1500)

# Log responses
ai_logger.log_response("openai", "gpt-4", response_tokens=500, 
                      duration_ms=2000, success=True, cost=0.05)
```

### Infrastructure Changes

```python
from src.core.logging_config import infra_logger

# Log deployments
infra_logger.log_deployment("api-service", "v2.1.0", "production", 
                           user="deploy-bot", success=True)
```

## Common Patterns

### Exception Logging

```python
try:
    result = risky_operation()
except SpecificError as e:
    logger.error("Operation failed", exc_info=True, extra={
        "structured_data": {
            "operation": "risky_operation",
            "error_type": type(e).__name__
        }
    })
    raise
```

### Conditional Logging

```python
if logger.isEnabledFor(logging.DEBUG):
    # Only compute expensive debug info if needed
    debug_info = compute_expensive_debug_info()
    logger.debug("Detailed state", extra={"structured_data": debug_info})
```

### Batch Operations

```python
logger.info("Batch processing started", extra={
    "structured_data": {
        "batch_id": batch_id,
        "total_items": len(items)
    }
})

for i, item in enumerate(items):
    if i % 100 == 0:  # Log progress every 100 items
        logger.info("Batch progress", extra={
            "structured_data": {
                "batch_id": batch_id,
                "processed": i,
                "total": len(items)
            }
        })
```

## Testing with Logs

```python
import logging
from unittest.mock import patch

def test_function_logs_correctly():
    with patch.object(logger, 'info') as mock_log:
        my_function()
        mock_log.assert_called_with(
            "Expected message",
            extra={"structured_data": {"key": "value"}}
        )
```

## Configuration

### Environment Variables

```bash
# Development
export ENVIRONMENT=development
export LOG_LEVEL=DEBUG

# Production
export ENVIRONMENT=production
export LOG_LEVEL=WARNING
```

### Initialization

```python
# In your main application entry point
from src.core.logging_config import setup_logging

setup_logging(
    log_level="INFO",
    log_dir=Path("/var/log/myapp"),
    enable_rotation=True,
    structured=True
)
```

## Anti-Patterns to Avoid

### 1. String Formatting in Log Calls
```python
# BAD - String is formatted even if log level is disabled
logger.debug(f"Processing {len(items)} items")

# GOOD - Lazy formatting
logger.debug("Processing %d items", len(items))
```

### 2. Logging in Tight Loops
```python
# BAD
for item in large_list:
    logger.info(f"Processing {item}")

# GOOD
logger.info("Processing batch", extra={
    "structured_data": {"count": len(large_list)}
})
```

### 3. Using Print Statements
```python
# BAD
print(f"Debug: {value}")

# GOOD
logger.debug("Debug value", extra={"structured_data": {"value": value}})
```

### 4. Catching and Suppressing Exceptions
```python
# BAD
try:
    risky_operation()
except Exception:
    pass  # Silent failure

# GOOD
try:
    risky_operation()
except Exception as e:
    logger.error("Operation failed", exc_info=True)
    # Handle appropriately
```

## Production Considerations

### Log Rotation

Logs are automatically rotated when they reach 10MB, keeping the last 5 files:
- `production.log` (current)
- `production.log.1` through `production.log.5` (rotated)

### Performance Impact

- Structured logging adds ~0.1ms overhead per log call
- Use appropriate log levels to minimize production overhead
- DEBUG logs are automatically disabled in production

### Security

- All sensitive fields are automatically redacted
- Authentication logs are marked for security audit
- Access logs include user and resource information

### Integration with Monitoring

Structured JSON logs can be parsed by:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- CloudWatch Logs
- Datadog
- New Relic

Example query for failed deployments:
```json
{
  "level": "ERROR",
  "logger": "infrastructure.changes",
  "data.service": "api-service",
  "data.success": false
}
```

## Troubleshooting

### Logs Not Appearing

1. Check log level: `echo $LOG_LEVEL`
2. Verify initialization: Ensure `setup_logging()` is called
3. Check file permissions on log directory

### Performance Issues

1. Reduce log level in production
2. Use conditional logging for expensive operations
3. Consider async logging for high-throughput scenarios

### Missing Correlation IDs

Ensure you're using correlation context:
```python
with correlation_context():
    # Your code here
    pass
```

## Migration Guide

To migrate existing code to use the new logging system:

1. Replace `print()` statements:
   ```python
   # Before
   print(f"Starting service on port {port}")
   
   # After
   logger.info("Starting service", extra={"structured_data": {"port": port}})
   ```

2. Update existing loggers:
   ```python
   # Before
   import logging
   logger = logging.getLogger(__name__)
   
   # After
   from src.core.logging_config import get_logger
   logger = get_logger(__name__)
   ```

3. Add structured data:
   ```python
   # Before
   logger.info(f"User {user_id} performed {action}")
   
   # After
   logger.info("User action", extra={
       "structured_data": {
           "user_id": user_id,
           "action": action
       }
   })
   ```

## Summary

Following these logging best practices ensures:
- **Consistency**: All logs follow the same format
- **Security**: Sensitive data is never logged
- **Performance**: Minimal overhead in production
- **Debuggability**: Rich context for troubleshooting
- **Compliance**: Audit trails for security events
- **Integration**: Works with standard monitoring tools

Remember: Good logging is essential for operating production systems. When in doubt, log with structure and context!