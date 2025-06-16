# Error Handling Integration Guide

## Overview

The Claude-Optimized Deployment Engine now features a comprehensive exception hierarchy that provides:
- Consistent error handling across all modules
- Rich context for debugging
- Proper exception chaining
- Easy serialization for APIs
- Production-ready error codes

## Exception Hierarchy Location

The complete exception hierarchy is defined in:
```
src/core/exceptions.py
```

## Key Exception Categories

### 1. Infrastructure Errors (1xxx)
- `InfrastructureError` - Base infrastructure exception
- `DockerError` - Docker-specific errors
- `KubernetesError` - Kubernetes-specific errors
- `CloudProviderError` - AWS/Azure/GCP errors
- `CommandExecutionError` - Command execution failures
- `ResourceError` - Resource limitations

### 2. AI/Expert Errors (2xxx)
- `AIError` - Base AI exception
- `AIAPIError` - API call failures
- `AIRateLimitError` - Rate limiting
- `AIResponseError` - Invalid responses
- `AITimeoutError` - Request timeouts
- `ConsensusError` - Expert consensus failures

### 3. MCP Errors (3xxx)
- `MCPError` - Base MCP exception
- `MCPServerNotFoundError` - Server not found
- `MCPToolNotFoundError` - Tool not found
- `MCPToolExecutionError` - Tool execution failures
- `MCPProtocolError` - Protocol violations
- `MCPInitializationError` - Initialization failures

### 4. Validation Errors (4xxx)
- `ValidationError` - Base validation exception
- `TypeValidationError` - Type mismatches
- `RangeValidationError` - Value out of range
- `FormatValidationError` - Format violations
- `RequiredFieldError` - Missing required fields
- `ConstraintValidationError` - Custom constraints

### 5. Network Errors (5xxx)
- `NetworkError` - Base network exception
- `ConnectionError` - Connection failures
- `TimeoutError` - Network timeouts
- `DNSError` - DNS resolution failures
- `SSLError` - SSL/TLS errors

### 6. Authentication Errors (6xxx)
- `AuthenticationError` - Base auth exception
- `InvalidCredentialsError` - Bad credentials
- `TokenExpiredError` - Expired tokens
- `PermissionDeniedError` - Insufficient permissions
- `MFARequiredError` - MFA required

### 7. Configuration Errors (7xxx)
- `ConfigurationError` - Base config exception
- `MissingConfigError` - Missing configuration
- `InvalidConfigError` - Invalid values
- `EnvironmentError` - Environment issues
- `ConfigFileError` - Config file problems

## Integration Status

### ✅ Already Integrated
1. **src/circle_of_experts/utils/validation.py** - Updated to use new validation exceptions
2. **src/mcp/manager.py** - MCP manager uses new MCP exceptions
3. **src/circle_of_experts/experts/expert_factory.py** - Expert factory uses configuration exceptions
4. **src/mcp/infrastructure_servers.py** - Infrastructure servers use specific error types

### 🔄 Pending Integration
1. **src/circle_of_experts/experts/** - Expert clients need AI exception updates
2. **src/mcp/devops_servers.py** - DevOps servers need error updates
3. **src/mcp/storage/** - Storage servers need error updates
4. **src/mcp/monitoring/** - Monitoring servers need error updates
5. **src/mcp/communication/** - Communication servers need error updates

## Quick Start Guide

### Basic Usage
```python
from src.core.exceptions import (
    DockerError,
    RequiredFieldError,
    handle_error
)
import logging

logger = logging.getLogger(__name__)

# Raise specific exceptions
if not container_id:
    raise RequiredFieldError("container_id")

# Handle with logging
try:
    docker_operation()
except DockerError as e:
    handle_error(e, logger)  # Logs and re-raises
```

### Best Practices

1. **Always use specific exceptions**
   ```python
   # Good
   raise DockerError("Container failed", container_id="abc123")
   
   # Bad
   raise Exception("Docker error")
   ```

2. **Preserve original exceptions**
   ```python
   try:
       external_call()
   except ExternalError as e:
       raise AIAPIError("API failed", cause=e)
   ```

3. **Add rich context**
   ```python
   raise CommandExecutionError(
       "Build failed",
       command="make build",
       exit_code=2,
       stderr=error_output
   )
   ```

4. **Use error codes for monitoring**
   ```python
   # In your monitoring system
   if error.error_code == ErrorCode.AI_RATE_LIMIT:
       alert_on_call_engineer()
   ```

## API Integration

The exception system is designed for easy API integration:

```python
from fastapi import Request
from fastapi.responses import JSONResponse
from src.core.exceptions import BaseDeploymentError

@app.exception_handler(BaseDeploymentError)
async def deployment_error_handler(request: Request, exc: BaseDeploymentError):
    return JSONResponse(
        status_code=get_http_status(exc),
        content=exc.to_dict()
    )
```

## Testing Error Handling

Run the test script to see examples:
```bash
python test_exception_handling.py
```

## Documentation

- **Best Practices**: `docs/ERROR_HANDLING_BEST_PRACTICES.md`
- **Migration Guide**: `docs/EXCEPTION_MIGRATION_GUIDE.md`
- **Exception Module**: `src/core/exceptions.py`

## Next Steps

1. Continue migrating remaining modules to use new exceptions
2. Add exception metrics to monitoring systems
3. Create error code documentation for operations team
4. Implement automatic error reporting to Sentry/similar
5. Add exception handling to API middleware

## Benefits

1. **Debugging**: Rich context makes debugging easier
2. **Monitoring**: Error codes enable better alerting
3. **Testing**: Specific types for better test assertions
4. **APIs**: Automatic serialization for responses
5. **Documentation**: Self-documenting error types