# Error Handling Best Practices Guide

## Overview

This guide outlines the error handling standards for the Claude-Optimized Deployment Engine. Following these practices ensures consistent, debuggable, and user-friendly error handling across the codebase.

## Exception Hierarchy

All exceptions inherit from `BaseDeploymentError` in `src.core.exceptions`:

```
BaseDeploymentError
├── InfrastructureError
│   ├── DockerError
│   ├── KubernetesError
│   ├── CloudProviderError
│   ├── CommandExecutionError
│   └── ResourceError
├── AIError
│   ├── AIAPIError
│   ├── AIRateLimitError
│   ├── AIResponseError
│   ├── AITimeoutError
│   └── ConsensusError
├── MCPError
│   ├── MCPServerNotFoundError
│   ├── MCPToolNotFoundError
│   ├── MCPToolExecutionError
│   ├── MCPProtocolError
│   └── MCPInitializationError
├── ValidationError
│   ├── TypeValidationError
│   ├── RangeValidationError
│   ├── FormatValidationError
│   ├── RequiredFieldError
│   └── ConstraintValidationError
├── NetworkError
│   ├── ConnectionError
│   ├── TimeoutError
│   ├── DNSError
│   └── SSLError
├── AuthenticationError
│   ├── InvalidCredentialsError
│   ├── TokenExpiredError
│   ├── PermissionDeniedError
│   └── MFARequiredError
└── ConfigurationError
    ├── MissingConfigError
    ├── InvalidConfigError
    ├── EnvironmentError
    └── ConfigFileError
```

## Basic Usage

### 1. Import the Exceptions

```python
from src.core.exceptions import (
    DockerError,
    AIAPIError,
    ValidationError,
    handle_error
)
```

### 2. Raise Specific Exceptions

Always use the most specific exception type:

```python
# Good - specific exception with context
raise DockerError(
    "Failed to start container",
    container_id="abc123",
    image="myapp:latest",
    cause=original_exception
)

# Bad - generic exception
raise Exception("Docker error")
```

### 3. Preserve Original Exceptions

Always preserve the original exception as the cause:

```python
try:
    docker_client.containers.run(image)
except docker.errors.APIError as e:
    raise DockerError(
        "Failed to run container",
        image=image,
        cause=e  # Preserve original exception
    )
```

### 4. Add Contextual Information

Include relevant context in exceptions:

```python
raise AIAPIError(
    "OpenAI API request failed",
    provider="openai",
    status_code=429,
    response_body=response.text,
    context={
        "model": "gpt-4",
        "prompt_tokens": 1000,
        "retry_count": 3
    }
)
```

## Error Handling Patterns

### Pattern 1: Try/Except with Logging

```python
from src.core.exceptions import handle_error
import logging

logger = logging.getLogger(__name__)

def process_deployment(config):
    try:
        # Deployment logic
        validate_config(config)
        deploy_infrastructure(config)
        
    except ValidationError as e:
        # Handle validation errors specifically
        handle_error(e, logger, reraise=False)
        return {"status": "failed", "error": e.to_dict()}
        
    except BaseDeploymentError as e:
        # Handle all deployment errors
        handle_error(e, logger)  # Will log and re-raise
        
    except Exception as e:
        # Wrap unexpected errors
        deployment_error = InfrastructureError(
            "Unexpected deployment failure",
            context={"config": config},
            cause=e
        )
        handle_error(deployment_error, logger)
```

### Pattern 2: Async Error Handling

```python
async def async_operation():
    try:
        result = await external_api_call()
        return result
        
    except asyncio.TimeoutError as e:
        raise TimeoutError(
            "API call timed out",
            timeout_seconds=30,
            operation="external_api_call",
            cause=e
        )
    except aiohttp.ClientError as e:
        raise NetworkError(
            "Network request failed",
            url=str(e.request_info.url),
            cause=e
        )
```

### Pattern 3: Validation with Early Returns

```python
def create_resource(name: str, size: int, tags: List[str]):
    # Validate inputs early
    if not name:
        raise RequiredFieldError("name")
        
    if not isinstance(size, int):
        raise TypeValidationError("size", size, int)
        
    if size < 1 or size > 1000:
        raise RangeValidationError("size", size, min_value=1, max_value=1000)
        
    if not isinstance(tags, list):
        raise TypeValidationError("tags", tags, list)
        
    # Proceed with valid inputs
    return Resource(name, size, tags)
```

### Pattern 4: Retry with Error Escalation

```python
from src.core.exceptions import AIRateLimitError
import time

async def call_ai_with_retry(prompt: str, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return await ai_client.complete(prompt)
            
        except AIRateLimitError as e:
            if attempt == max_retries - 1:
                # Last attempt, escalate error
                raise
                
            # Wait before retry
            retry_after = e.context.get('retry_after_seconds', 60)
            logger.warning(f"Rate limited, retrying after {retry_after}s")
            await asyncio.sleep(retry_after)
            
        except AIAPIError as e:
            # Don't retry on other API errors
            raise
```

### Pattern 5: Context Manager for Resource Cleanup

```python
from contextlib import contextmanager

@contextmanager
def managed_container(image: str):
    container = None
    try:
        container = docker_client.containers.run(image, detach=True)
        yield container
        
    except docker.errors.ImageNotFound as e:
        raise DockerError(
            f"Image '{image}' not found",
            image=image,
            cause=e
        )
    finally:
        if container:
            try:
                container.stop()
                container.remove()
            except Exception as e:
                logger.warning(f"Failed to cleanup container: {e}")
```

## API Error Responses

When returning errors in API responses, use the exception's `to_dict()` method:

```python
from fastapi import HTTPException
from fastapi.responses import JSONResponse

@app.exception_handler(BaseDeploymentError)
async def deployment_error_handler(request: Request, exc: BaseDeploymentError):
    # Log the error
    logger.error(f"API error: {exc}")
    
    # Return appropriate HTTP status based on error type
    status_map = {
        ValidationError: 400,
        AuthenticationError: 401,
        PermissionDeniedError: 403,
        MCPServerNotFoundError: 404,
        AIRateLimitError: 429,
        TimeoutError: 504,
    }
    
    status_code = 500  # Default to internal server error
    for error_class, code in status_map.items():
        if isinstance(exc, error_class):
            status_code = code
            break
    
    return JSONResponse(
        status_code=status_code,
        content=exc.to_dict()
    )
```

## Logging Best Practices

### 1. Use Structured Logging

```python
logger.error(
    "Operation failed",
    extra={
        "operation": "deploy_container",
        "error_code": error.error_code.value,
        "container_id": container_id,
        "duration_ms": duration
    }
)
```

### 2. Log at Appropriate Levels

- **ERROR**: Unrecoverable errors that prevent operation completion
- **WARNING**: Recoverable errors or degraded functionality
- **INFO**: Normal operation status
- **DEBUG**: Detailed diagnostic information

### 3. Include Correlation IDs

```python
from src.circle_of_experts.utils.logging import LogContext

with LogContext(operation="deployment", request_id=request_id):
    try:
        deploy_application()
    except BaseDeploymentError as e:
        logger.error(f"Deployment failed: {e}")
        raise
```

## Testing Error Handling

### 1. Test Expected Exceptions

```python
import pytest
from src.core.exceptions import DockerError

def test_container_start_failure():
    with pytest.raises(DockerError) as exc_info:
        start_container("invalid-image")
    
    error = exc_info.value
    assert error.error_code == ErrorCode.INFRASTRUCTURE_DOCKER
    assert "invalid-image" in error.context["image"]
```

### 2. Test Error Context

```python
def test_error_context_preservation():
    original = ValueError("Original error")
    
    error = InfrastructureError(
        "Wrapped error",
        context={"key": "value"},
        cause=original
    )
    
    assert error.cause == original
    assert error.context["cause_type"] == "ValueError"
    assert error.context["key"] == "value"
```

### 3. Test Error Serialization

```python
def test_error_serialization():
    error = ValidationError(
        "Invalid input",
        field="username",
        value="a"
    )
    
    error_dict = error.to_dict()
    assert error_dict["error_type"] == "ValidationError"
    assert error_dict["message"] == "Invalid input"
    assert error_dict["context"]["field"] == "username"
```

## Migration Guide

To migrate existing code to use the new exception hierarchy:

### 1. Replace Generic Exceptions

```python
# Before
raise Exception("Docker container failed to start")

# After
raise DockerError("Container failed to start", container_id=container_id)
```

### 2. Update Exception Imports

```python
# Before
from src.circle_of_experts.utils.validation import ValidationError

# After
from src.core.exceptions import ValidationError
```

### 3. Add Context to Existing Raises

```python
# Before
raise ValueError(f"Invalid API key for {provider}")

# After
raise InvalidCredentialsError(
    f"Invalid API key for {provider}",
    context={"provider": provider}
)
```

### 4. Update Exception Handlers

```python
# Before
except Exception as e:
    logger.error(f"Error: {e}")
    return None

# After
except BaseDeploymentError as e:
    handle_error(e, logger, reraise=False)
    return {"error": e.to_dict()}
except Exception as e:
    error = InfrastructureError("Unexpected error", cause=e)
    handle_error(error, logger, reraise=False)
    return {"error": error.to_dict()}
```

## Common Pitfalls to Avoid

### 1. Don't Swallow Exceptions

```python
# Bad - loses error information
try:
    risky_operation()
except:
    pass

# Good - handle or re-raise
try:
    risky_operation()
except SpecificError as e:
    logger.warning(f"Non-critical error: {e}")
    # Continue with fallback
```

### 2. Don't Log and Raise Generic Exceptions

```python
# Bad
logger.error("Something went wrong")
raise Exception("Error occurred")

# Good
error = InfrastructureError("Deployment failed", context={...})
handle_error(error, logger)  # Logs and re-raises
```

### 3. Don't Lose Stack Traces

```python
# Bad - loses original stack trace
except Exception as e:
    raise InfrastructureError(str(e))

# Good - preserves stack trace
except Exception as e:
    raise InfrastructureError("Operation failed", cause=e)
```

### 4. Don't Over-Catch

```python
# Bad - catches system exits, keyboard interrupts
except Exception:
    handle_error()

# Good - catch specific exceptions
except (ValueError, TypeError, ValidationError):
    handle_error()
```

## Environment-Specific Behavior

The exception system adapts to the environment:

### Development Environment
- Stack traces included in serialized errors
- Verbose error messages
- All context information exposed

### Production Environment
- Stack traces hidden from API responses
- User-friendly error messages
- Sensitive context information filtered

Configure via environment variable:
```bash
export ENVIRONMENT=production  # or development
```

## Summary

Following these error handling best practices ensures:

1. **Consistency**: All errors follow the same patterns
2. **Debuggability**: Rich context and stack traces
3. **User Experience**: Clear, actionable error messages
4. **Maintainability**: Easy to understand and modify error handling
5. **Observability**: Structured logging and monitoring

Remember: Good error handling is not about preventing errors, but about making them easy to understand, debug, and recover from.