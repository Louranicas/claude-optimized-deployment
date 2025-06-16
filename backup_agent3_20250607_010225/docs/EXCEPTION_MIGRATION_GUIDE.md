# Exception Migration Guide

This guide helps migrate existing code to use the new comprehensive exception hierarchy.

## Quick Reference

### Import Statement
```python
from src.core.exceptions import (
    # Infrastructure
    InfrastructureError, DockerError, KubernetesError, 
    CommandExecutionError, ResourceError,
    
    # AI/Expert
    AIError, AIAPIError, AIRateLimitError, 
    AIResponseError, AITimeoutError, ConsensusError,
    
    # MCP
    MCPError, MCPServerNotFoundError, MCPToolNotFoundError,
    MCPToolExecutionError, MCPProtocolError, MCPInitializationError,
    
    # Validation
    ValidationError, TypeValidationError, RangeValidationError,
    FormatValidationError, RequiredFieldError, ConstraintValidationError,
    
    # Network
    NetworkError, ConnectionError, TimeoutError, DNSError, SSLError,
    
    # Authentication
    AuthenticationError, InvalidCredentialsError, TokenExpiredError,
    PermissionDeniedError, MFARequiredError,
    
    # Configuration
    ConfigurationError, MissingConfigError, InvalidConfigError,
    EnvironmentError, ConfigFileError,
    
    # Helpers
    handle_error, wrap_exception
)
```

## Migration Examples

### 1. Circle of Experts Validation

**Before:**
```python
# In src/circle_of_experts/utils/validation.py
class ValidationError(ValueError):
    def __init__(self, field: str, value: Any, message: str):
        self.field = field
        self.value = value
        self.message = message
        super().__init__(f"Validation failed for '{field}': {message}")

# Usage
raise ValidationError(field_name, value, "Value cannot be None")
```

**After:**
```python
from src.core.exceptions import RequiredFieldError, ValidationError

# Usage
raise RequiredFieldError(field_name)
```

### 2. MCP Server Errors

**Before:**
```python
# In MCP servers
raise MCPError(-32601, f"Tool not found: {tool_name}")
raise MCPError(-32000, "Docker is not available on this system")
```

**After:**
```python
from src.core.exceptions import MCPToolNotFoundError, DockerError

# Tool not found
raise MCPToolNotFoundError(
    tool_name, 
    server_name,
    available_tools=["tool1", "tool2"]
)

# Docker not available
raise DockerError(
    "Docker is not available on this system",
    context={"tool_name": tool_name}
)
```

### 3. Expert Factory Errors

**Before:**
```python
# In expert_factory.py
if not config:
    logger.error(f"Unknown expert: {expert_name}")
    return None

if not api_key:
    raise ValueError(f"No API key found for {expert_name}")
```

**After:**
```python
from src.core.exceptions import ConfigurationError, MissingConfigError, handle_error

if not config:
    error = ConfigurationError(
        f"Unknown expert: {expert_name}",
        config_key=expert_name,
        context={"available_experts": list(EXPERT_REGISTRY.keys())}
    )
    handle_error(error, logger, reraise=False)
    return None

if not api_key:
    raise MissingConfigError(
        config.env_var_name,
        config_source="environment",
        context={"expert": expert_name}
    )
```

### 4. Infrastructure Command Execution

**Before:**
```python
# In infrastructure_servers.py
except asyncio.TimeoutError:
    raise MCPError(-32000, f"Command timed out after {timeout} seconds")
except Exception as e:
    raise MCPError(-32000, f"Command execution failed: {str(e)}")
```

**After:**
```python
from src.core.exceptions import TimeoutError, CommandExecutionError

except asyncio.TimeoutError:
    raise TimeoutError(
        f"Command timed out after {timeout} seconds",
        timeout_seconds=timeout,
        operation="execute_command",
        context={"command": command, "working_directory": str(work_dir)}
    )
except Exception as e:
    raise CommandExecutionError(
        f"Command execution failed: {str(e)}",
        command=command,
        exit_code=process.returncode if 'process' in locals() else None,
        stderr=stderr.decode('utf-8') if 'stderr' in locals() else None,
        cause=e
    )
```

### 5. AI Expert API Calls

**Before:**
```python
# In expert clients
except Exception as e:
    logger.error(f"Claude generation failed: {e}")
    response.mark_failed(str(e))
```

**After:**
```python
from src.core.exceptions import AIAPIError, AIRateLimitError, handle_error

except anthropic.RateLimitError as e:
    error = AIRateLimitError(
        "Claude API rate limit exceeded",
        provider="anthropic",
        retry_after=getattr(e, 'retry_after', 60)
    )
    handle_error(error, logger, reraise=False)
    response.mark_failed(str(error))
except Exception as e:
    error = AIAPIError(
        "Claude generation failed",
        provider="anthropic",
        status_code=getattr(e, 'status_code', None),
        cause=e
    )
    handle_error(error, logger, reraise=False)
    response.mark_failed(str(error))
```

## Migration Checklist

### Step 1: Update Imports
- [ ] Add import for `src.core.exceptions`
- [ ] Remove old exception class definitions
- [ ] Import specific exceptions you need

### Step 2: Replace Exception Raises
- [ ] Replace generic `Exception` with specific types
- [ ] Replace `ValueError` with `ValidationError` subtypes
- [ ] Replace `RuntimeError` with appropriate infrastructure errors
- [ ] Replace custom exceptions with standard ones

### Step 3: Add Context
- [ ] Add relevant context to all exceptions
- [ ] Preserve original exceptions with `cause=`
- [ ] Include debugging information (IDs, names, etc.)

### Step 4: Update Exception Handlers
- [ ] Use `handle_error()` for consistent logging
- [ ] Update `except` clauses to catch specific types
- [ ] Preserve exception chains with proper re-raising

### Step 5: Update Tests
- [ ] Update test assertions for new exception types
- [ ] Test exception context and error codes
- [ ] Verify error serialization works

## Common Patterns

### Pattern 1: Wrapping External Exceptions
```python
try:
    # External API call
    result = await external_api.call()
except ExternalAPIError as e:
    # Wrap in our exception type
    raise AIAPIError(
        "External API call failed",
        provider="external",
        status_code=e.status_code,
        response_body=str(e),
        cause=e
    )
```

### Pattern 2: Validation with Multiple Checks
```python
# Check required
if not value:
    raise RequiredFieldError(field_name)

# Check type
if not isinstance(value, expected_type):
    raise TypeValidationError(field_name, value, expected_type)

# Check range
if value < min_val or value > max_val:
    raise RangeValidationError(
        field_name, value, 
        min_value=min_val, 
        max_value=max_val
    )
```

### Pattern 3: Async Timeout Handling
```python
try:
    result = await asyncio.wait_for(operation(), timeout=30)
except asyncio.TimeoutError:
    raise TimeoutError(
        "Operation timed out",
        timeout_seconds=30,
        operation="operation_name"
    )
```

### Pattern 4: Configuration Validation
```python
# Check environment variable
api_key = os.getenv("API_KEY")
if not api_key:
    raise MissingConfigError(
        "API_KEY",
        config_source="environment"
    )

# Validate format
if not api_key.startswith("sk-"):
    raise InvalidConfigError(
        "API_KEY",
        api_key[:10] + "...",  # Don't log full key
        "API key must start with 'sk-'"
    )
```

## Benefits After Migration

1. **Consistent Error Messages**: All errors follow the same format
2. **Better Debugging**: Rich context in every exception
3. **Easier Testing**: Specific exception types to assert against
4. **API Ready**: Automatic serialization for REST/GraphQL APIs
5. **Monitoring**: Error codes enable better alerting and metrics
6. **Documentation**: Self-documenting error types and contexts

## Need Help?

If you encounter issues during migration:

1. Check the comprehensive exception module: `src/core/exceptions.py`
2. Review the best practices guide: `docs/ERROR_HANDLING_BEST_PRACTICES.md`
3. Run the test script: `python test_exception_handling.py`
4. Look for examples in already-migrated modules