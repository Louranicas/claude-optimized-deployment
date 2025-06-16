# Error Handling Best Practices Guide

## Overview

This guide outlines the error handling standards for the Claude-Optimized Deployment Engine. Following these practices ensures consistent, debuggable, and user-friendly error handling across the codebase.

**Last Updated**: December 2025
**Current Status**: Production-ready exception hierarchy with comprehensive mitigation matrices

### Key Achievements
- ✅ Complete exception hierarchy implemented
- ✅ Mitigation matrices for all error categories
- ✅ Integration with Circle of Experts for error analysis
- ✅ MCP server error handling patterns
- ✅ Security audit integration
- ✅ Performance monitoring integration

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
    handle_error,
    # MCP-specific exceptions
    MCPServerNotFoundError,
    MCPToolExecutionError,
    # Circle of Experts exceptions
    ConsensusError,
    AITimeoutError,
    # Security exceptions
    AuthenticationError,
    PermissionDeniedError
)
```

### 2. Raise Specific Exceptions

Always use the most specific exception type with comprehensive context:

```python
# Excellent - specific exception with comprehensive context
raise DockerError(
    "Failed to start container",
    container_id="abc123",
    image="myapp:latest",
    mcp_server="docker",
    operation="container_start",
    resource_usage={"memory": "512MB", "cpu": "0.5"},
    security_context={"user": "deploy", "network": "bridge"},
    cause=original_exception
)

# Good - basic specific exception
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

Include comprehensive context for debugging and monitoring:

```python
raise AIAPIError(
    "OpenAI API request failed",
    provider="openai",
    status_code=429,
    response_body=response.text,
    context={
        "model": "gpt-4",
        "prompt_tokens": 1000,
        "retry_count": 3,
        "expert_id": "openai-gpt4",
        "consultation_id": "cons-123",
        "circuit_breaker_state": "half_open",
        "memory_usage": "145MB",
        "performance_metrics": {
            "response_time": "2.3s",
            "queue_length": 5
        }
    }
)
```

## Error Handling Patterns

### Pattern 1: Enhanced Try/Except with Comprehensive Logging

```python
from src.core.exceptions import handle_error
from src.circle_of_experts import EnhancedExpertManager
from src.monitoring.metrics import deployment_metrics
from src.auth.audit import audit_action
import logging

logger = logging.getLogger(__name__)

async def process_deployment(config, user_context=None):
    deployment_id = generate_deployment_id()
    
    try:
        # Audit the deployment attempt
        await audit_action("deployment_start", {
            "deployment_id": deployment_id,
            "user": user_context,
            "config_hash": hash_config(config)
        })
        
        # Validate with Circle of Experts
        expert_manager = EnhancedExpertManager()
        validation_result = await expert_manager.quick_consult(
            f"Validate deployment configuration: {config}"
        )
        
        if not validation_result.get("consensus"):
            raise ValidationError(
                "Deployment configuration failed expert validation",
                validation_errors=validation_result.get("issues", []),
                expert_recommendations=validation_result.get("recommendations", []),
                deployment_id=deployment_id
            )
        
        # Execute deployment with monitoring
        with deployment_metrics.timer("deployment_duration"):
            result = await deploy_infrastructure(config, deployment_id)
            
        await audit_action("deployment_success", {"deployment_id": deployment_id})
        return result
        
    except ValidationError as e:
        # Handle validation errors with expert consultation
        await audit_action("deployment_validation_failed", {"deployment_id": deployment_id, "error": str(e)})
        
        # Get expert recommendations for fixing
        fix_recommendations = await expert_manager.quick_consult(
            f"How to fix this deployment validation error: {e}"
        )
        
        enhanced_error = ValidationError(
            e.message,
            **e.context,
            fix_recommendations=fix_recommendations.get("recommendations", []),
            deployment_id=deployment_id
        )
        
        handle_error(enhanced_error, logger, reraise=False)
        return {"status": "failed", "error": enhanced_error.to_dict()}
        
    except BaseDeploymentError as e:
        # Handle deployment errors with comprehensive context
        await audit_action("deployment_failed", {"deployment_id": deployment_id, "error_type": type(e).__name__})
        deployment_metrics.increment("deployment_failures", {"error_type": type(e).__name__})
        handle_error(e, logger)
        
    except Exception as e:
        # Wrap unexpected errors with full context
        await audit_action("deployment_unexpected_error", {"deployment_id": deployment_id})
        
        deployment_error = InfrastructureError(
            "Unexpected deployment failure",
            context={
                "config": sanitize_config(config),
                "deployment_id": deployment_id,
                "user_context": user_context,
                "system_state": await get_system_state()
            },
            cause=e
        )
        handle_error(deployment_error, logger)
```

### Pattern 2: Enhanced Async Error Handling with Circuit Breaker

```python
from src.core.circuit_breaker import CircuitBreaker
from src.core.retry import async_retry
from src.monitoring.metrics import api_metrics

@async_retry(max_attempts=3, exponential_backoff=True)
async def async_operation(operation_context=None):
    circuit_breaker = CircuitBreaker("external_api")
    
    try:
        async with circuit_breaker:
            with api_metrics.timer("external_api_duration"):
                result = await external_api_call()
                
            api_metrics.increment("external_api_success")
            return result
            
    except asyncio.TimeoutError as e:
        api_metrics.increment("external_api_timeout")
        raise TimeoutError(
            "API call timed out",
            timeout_seconds=30,
            operation="external_api_call",
            circuit_breaker_state=circuit_breaker.state,
            retry_context=operation_context,
            cause=e
        )
        
    except httpx.ConnectError as e:
        api_metrics.increment("external_api_connection_error")
        raise NetworkError(
            "Network connection failed",
            url=str(e.request.url),
            connection_type="httpx",
            circuit_breaker_state=circuit_breaker.state,
            network_diagnostics=await get_network_diagnostics(),
            cause=e
        )
        
    except httpx.HTTPStatusError as e:
        api_metrics.increment("external_api_http_error", {"status_code": e.response.status_code})
        
        if e.response.status_code == 429:
            raise AIRateLimitError(
                "API rate limit exceeded",
                provider="external_api",
                status_code=e.response.status_code,
                retry_after_seconds=e.response.headers.get("Retry-After", 60),
                circuit_breaker_state=circuit_breaker.state,
                cause=e
            )
        else:
            raise APIError(
                "HTTP error from external API",
                status_code=e.response.status_code,
                response_body=e.response.text,
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

### Pattern 4: Enhanced Retry with Circle of Experts Escalation

```python
from src.core.exceptions import AIRateLimitError
from src.core.retry import ExponentialBackoff
from src.circle_of_experts import EnhancedExpertManager
from src.monitoring.metrics import ai_metrics
import asyncio

async def call_ai_with_retry(prompt: str, expert_id: str = None, max_retries: int = 3, consultation_id: str = None):
    backoff = ExponentialBackoff(initial_delay=1.0, max_delay=60.0)
    expert_manager = EnhancedExpertManager()
    
    for attempt in range(max_retries):
        try:
            with ai_metrics.timer("ai_call_duration", {"expert_id": expert_id, "attempt": attempt + 1}):
                result = await ai_client.complete(prompt, expert_id=expert_id)
                
            ai_metrics.increment("ai_call_success", {"expert_id": expert_id})
            return result
            
        except AIRateLimitError as e:
            ai_metrics.increment("ai_rate_limit", {"expert_id": expert_id})
            
            if attempt == max_retries - 1:
                # Last attempt - try alternative experts
                logger.warning(f"Rate limit exhausted for {expert_id}, trying alternatives")
                
                try:
                    alternative_result = await expert_manager.quick_consult(
                        prompt,
                        exclude_experts=[expert_id],
                        expert_count=1,
                        consultation_id=consultation_id
                    )
                    return alternative_result
                except Exception as fallback_error:
                    # Escalate with comprehensive context
                    raise AIRateLimitError(
                        f"Rate limit exceeded and fallback failed for expert {expert_id}",
                        expert_id=expert_id,
                        retry_after_seconds=e.context.get('retry_after_seconds', 60),
                        attempts_made=max_retries,
                        fallback_error=str(fallback_error),
                        consultation_id=consultation_id,
                        alternative_experts_tried=True,
                        cause=e
                    )
                
            # Wait with exponential backoff
            retry_after = e.context.get('retry_after_seconds', backoff.next_delay())
            logger.warning(f"Rate limited on attempt {attempt + 1}, retrying after {retry_after}s")
            await asyncio.sleep(retry_after)
            
        except AIAPIError as e:
            ai_metrics.increment("ai_api_error", {"expert_id": expert_id, "error_type": type(e).__name__})
            
            # For non-rate-limit errors, try expert consultation for alternatives
            if attempt < max_retries - 1:
                logger.warning(f"API error on attempt {attempt + 1}, trying expert consultation")
                try:
                    alternative_result = await expert_manager.quick_consult(
                        f"The following prompt failed with {type(e).__name__}: {prompt}",
                        exclude_experts=[expert_id],
                        expert_count=1
                    )
                    return alternative_result
                except Exception:
                    pass  # Continue to next retry
            
            # Don't retry on final attempt
            if attempt == max_retries - 1:
                raise
                
        except Exception as e:
            ai_metrics.increment("ai_unexpected_error", {"expert_id": expert_id})
            # For unexpected errors, fail fast
            raise AIAPIError(
                f"Unexpected error calling AI expert {expert_id}",
                expert_id=expert_id,
                attempt=attempt + 1,
                consultation_id=consultation_id,
                cause=e
            )
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

### 1. Test Expected Exceptions with Comprehensive Validation

```python
import pytest
from src.core.exceptions import DockerError, ErrorCode
from src.mcp.client import MCPClient
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_container_start_failure():
    with patch('src.mcp.client.MCPClient.execute_tool') as mock_execute:
        mock_execute.side_effect = Exception("Container start failed")
        
        with pytest.raises(DockerError) as exc_info:
            await start_container("invalid-image")
        
        error = exc_info.value
        assert error.error_code == ErrorCode.INFRASTRUCTURE_DOCKER
        assert "invalid-image" in error.context["image"]
        assert "mcp_server" in error.context
        assert "operation" in error.context
        assert error.context["operation"] == "container_start"
        
        # Verify audit logging was called
        # Verify metrics were recorded
        # Verify circuit breaker state was updated

@pytest.mark.asyncio
async def test_ai_rate_limit_with_fallback():
    """Test AI rate limiting with Circle of Experts fallback"""
    with patch('src.circle_of_experts.EnhancedExpertManager.quick_consult') as mock_consult:
        mock_consult.return_value = {"consensus": True, "response": "Fallback response"}
        
        # Should succeed with fallback
        result = await call_ai_with_retry("test prompt", expert_id="rate-limited-expert")
        assert result is not None
        
        # Verify fallback was called
        mock_consult.assert_called_once()
```

### 2. Test Error Context and Integration

```python
def test_error_context_preservation():
    original = ValueError("Original error")
    
    error = InfrastructureError(
        "Wrapped error",
        context={
            "key": "value",
            "deployment_id": "deploy-123",
            "mcp_server": "docker",
            "user_context": {"user_id": "user-456"}
        },
        cause=original
    )
    
    assert error.cause == original
    assert error.context["cause_type"] == "ValueError"
    assert error.context["key"] == "value"
    assert error.context["deployment_id"] == "deploy-123"
    assert error.context["mcp_server"] == "docker"
    
    # Test serialization includes all context
    error_dict = error.to_dict()
    assert "deployment_id" in error_dict["context"]
    assert "mcp_server" in error_dict["context"]
    assert "user_context" in error_dict["context"]
    
@pytest.mark.asyncio
async def test_error_with_audit_and_metrics():
    """Test that errors properly trigger audit logging and metrics"""
    with patch('src.auth.audit.audit_action') as mock_audit, \
         patch('src.monitoring.metrics.deployment_metrics.increment') as mock_metrics:
        
        try:
            await process_deployment({"invalid": "config"})
        except ValidationError:
            pass  # Expected
        
        # Verify audit logging
        mock_audit.assert_called()
        audit_calls = mock_audit.call_args_list
        assert any("deployment_validation_failed" in str(call) for call in audit_calls)
        
        # Verify metrics
        mock_metrics.assert_called_with("deployment_failures", {"error_type": "ValidationError"})
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

To migrate existing code to use the enhanced exception hierarchy:

### 1. Replace Generic Exceptions with Context-Rich Alternatives

```python
# Before
raise Exception("Docker container failed to start")

# After (Basic)
raise DockerError("Container failed to start", container_id=container_id)

# After (Enhanced with full context)
raise DockerError(
    "Container failed to start",
    container_id=container_id,
    image=image_name,
    mcp_server="docker",
    operation="container_start",
    deployment_id=deployment_context.get("deployment_id"),
    resource_constraints={"memory": "512MB", "cpu": "0.5"},
    network_config={"network": "bridge", "ports": ["8080:80"]},
    security_context={"user": "deploy", "capabilities": []},
    cause=original_exception
)
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

### 4. Update Exception Handlers with Full Integration

```python
# Before
except Exception as e:
    logger.error(f"Error: {e}")
    return None

# After (Enhanced with full integration)
except BaseDeploymentError as e:
    # Comprehensive error handling with audit, metrics, and expert consultation
    await audit_action("error_handled", {
        "error_type": type(e).__name__,
        "error_context": e.context,
        "deployment_id": e.context.get("deployment_id")
    })
    
    # Record metrics
    error_metrics.increment("deployment_errors", {
        "error_type": type(e).__name__,
        "mcp_server": e.context.get("mcp_server"),
        "operation": e.context.get("operation")
    })
    
    # Get expert recommendations for resolution
    try:
        expert_manager = EnhancedExpertManager()
        resolution_advice = await expert_manager.quick_consult(
            f"How to resolve this {type(e).__name__}: {e.message}"
        )
        e.context["expert_recommendations"] = resolution_advice.get("recommendations", [])
    except Exception:
        pass  # Don't fail on expert consultation errors
    
    handle_error(e, logger, reraise=False)
    return {"error": e.to_dict(), "status": "failed"}
    
except Exception as e:
    # Wrap unexpected errors with comprehensive context
    error = InfrastructureError(
        "Unexpected system error",
        context={
            "system_state": await get_system_health(),
            "active_deployments": await get_active_deployments(),
            "circuit_breaker_states": get_circuit_breaker_states(),
            "memory_usage": get_memory_usage(),
            "mcp_server_health": await check_mcp_servers()
        },
        cause=e
    )
    
    await audit_action("unexpected_error", {"error_type": type(e).__name__})
    error_metrics.increment("unexpected_errors")
    
    handle_error(error, logger, reraise=False)
    return {"error": error.to_dict(), "status": "system_error"}
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

The exception system adapts to the environment with enhanced security and monitoring:

### Development Environment
- Full stack traces included in serialized errors
- Verbose error messages with all context
- All context information exposed
- Expert recommendations visible
- Performance metrics exposed
- Circuit breaker states visible

### Production Environment
- Stack traces hidden from API responses (logged separately)
- User-friendly error messages
- Sensitive context information filtered
- Expert recommendations sanitized
- Performance metrics aggregated
- Circuit breaker states monitored

### Security Considerations
- API keys and credentials never logged
- User data sanitized in error contexts
- Audit trails maintained for all errors
- Security events trigger immediate alerts

Configure via environment variable:
```bash
export ENVIRONMENT=production  # or development
export ERROR_DETAIL_LEVEL=user  # user, admin, debug
export ENABLE_EXPERT_RECOMMENDATIONS=true
export AUDIT_ALL_ERRORS=true
```

## Summary

Following these enhanced error handling best practices ensures:

1. **Consistency**: All errors follow established patterns across MCP, Circle of Experts, and core systems
2. **Debuggability**: Rich context with deployment IDs, expert recommendations, and system state
3. **User Experience**: Clear, actionable error messages with expert-driven resolution advice
4. **Maintainability**: Easy to understand and modify error handling with comprehensive testing
5. **Observability**: Structured logging, metrics, audit trails, and performance monitoring
6. **Security**: Proper audit logging and security context preservation
7. **Resilience**: Circuit breaker integration and graceful degradation
8. **Intelligence**: Expert system integration for error analysis and resolution
9. **Performance**: Memory-conscious error handling with optimization hooks
10. **Production-Ready**: Comprehensive error matrices and mitigation strategies

### Integration Points

- **Circle of Experts**: Error analysis and resolution recommendations
- **MCP Servers**: Consistent error handling across all 27+ servers
- **Security System**: Audit logging and access control validation
- **Monitoring Stack**: Metrics, alerting, and performance tracking
- **Database Layer**: State persistence and audit trails
- **Circuit Breakers**: Failure detection and resilience patterns

Remember: Good error handling in our system is about creating an intelligent, self-healing infrastructure that learns from failures and provides actionable insights for both users and systems.