# Test Utilities Documentation

This directory contains comprehensive test utilities to make writing and maintaining tests easier and more consistent across the Claude Optimized Deployment project.

## Overview

The test utilities are organized into four main modules:

1. **Mock Factory** (`mock_factory.py`) - Create consistent mock objects
2. **Test Data** (`test_data.py`) - Generate realistic test data
3. **Assertions** (`assertions.py`) - Custom assertions for better test expressiveness
4. **Helpers** (`helpers.py`) - Common test operations and utilities

## Mock Factory

The `MockFactory` class provides methods to create various mock objects:

### Creating Mock Experts
```python
from tests.utils import MockFactory

# Create a basic mock expert
expert = MockFactory.create_mock_expert()

# Create a specific type of expert
claude_expert = MockFactory.create_mock_expert(expert_type=ExpertType.CLAUDE)

# Create with custom behavior
custom_expert = MockFactory.create_mock_expert(
    expert_id="custom-expert",
    health_check=AsyncMock(return_value={"status": "degraded"})
)
```

### Creating Mock MCP Servers
```python
# Create a mock MCP server
server = MockFactory.create_mock_mcp_server("docker")

# Use the mock server
info = await server.get_server_info()
result = await server.call_tool("docker_build", {"image": "test"})
```

### Special Mock Types
```python
# Mock that always fails
failing_mock = create_failing_mock(Exception("Always fails"))

# Mock that simulates slow operations
slow_mock = create_slow_mock(delay=2.0)

# Mock that fails randomly
flaky_mock = create_flaky_mock(success_rate=0.7)

# Mock with different responses on each call
progressive_mock = create_progressive_mock([
    {"status": "pending"},
    {"status": "running"},
    {"status": "completed"}
])
```

## Test Data Generators

The `TestDataGenerator` class provides methods to generate realistic test data:

### Query and Response Data
```python
from tests.utils import TestDataGenerator

# Generate query content
content = TestDataGenerator.generate_query_content("infrastructure")

# Generate expert response
response = TestDataGenerator.generate_expert_response(
    query_content="How to optimize Kubernetes?",
    expert_type=ExpertType.CLAUDE
)
```

### Infrastructure Data
```python
# Generate Kubernetes manifest
manifest = TestDataGenerator.generate_deployment_manifest("my-app")

# Generate Docker Compose config
compose = TestDataGenerator.generate_docker_compose()

# Generate Prometheus metrics
metrics = TestDataGenerator.generate_prometheus_metrics()
```

### Security and Performance Data
```python
# Generate security scan results
scan_results = TestDataGenerator.generate_security_scan_results()

# Generate performance data
perf_data = TestDataGenerator.generate_performance_data(duration_minutes=60)
```

## Custom Assertions

The `AssertionHelpers` class provides expressive assertions:

### Basic Assertions
```python
from tests.utils import AssertionHelpers

# Assert valid UUID
AssertionHelpers.assert_valid_uuid("123e4567-e89b-12d3-a456-426614174000")

# Assert value in range
AssertionHelpers.assert_in_range(value=75, min_value=0, max_value=100)

# Assert datetime is close
AssertionHelpers.assert_datetime_close(
    actual=datetime.now(),
    expected=datetime.now() + timedelta(seconds=2),
    delta=timedelta(seconds=5)
)
```

### Structure Assertions
```python
# Assert JSON structure
AssertionHelpers.assert_json_structure(
    actual={"name": "test", "value": 42},
    expected_structure={"name": str, "value": int}
)

# Assert API response success
AssertionHelpers.assert_api_response_success(
    response={"status": "success", "data": {...}}
)
```

### Domain-Specific Assertions
```python
# Assert expert response is valid
AssertionHelpers.assert_expert_response_valid(response)

# Assert deployment was successful
AssertionHelpers.assert_deployment_successful(
    deployment_result,
    expected_resources=["service", "deployment", "configmap"]
)

# Assert security scan passed
AssertionHelpers.assert_security_scan_passed(
    scan_result,
    max_critical=0,
    max_high=5
)
```

### Async Assertions
```python
# Assert async function raises exception
await assert_async_raises(
    ValueError,
    some_async_function,
    "invalid_arg"
)

# Assert async function times out
await assert_async_timeout(
    slow_async_function,
    timeout=1.0
)
```

## Test Helpers

The `TestHelpers` class provides utilities for common test operations:

### File and Directory Management
```python
from tests.utils import TestHelpers

# Create temporary directory
with TestHelpers.temporary_directory() as temp_dir:
    # Use temp_dir
    pass  # Automatically cleaned up

# Create temporary file
with TestHelpers.temporary_file(content="test data") as temp_file:
    # Use temp_file
    pass  # Automatically cleaned up
```

### Timing and Performance
```python
# Time a code block
with TestHelpers.timer() as timer:
    # Do something
    pass
print(f"Elapsed: {timer['elapsed']}s")

# Time async code
async with TestHelpers.async_timer() as timer:
    await some_async_operation()
```

### Log Capture
```python
# Capture logs during test
with TestHelpers.capture_logs("my_logger") as logs:
    logger.info("Test message")
    
assert len(logs) == 1
assert logs[0].message == "Test message"
```

### Async Utilities
```python
# Wait for condition
await TestHelpers.wait_for_condition(
    lambda: some_value > 10,
    timeout=5.0,
    message="Value did not exceed 10"
)

# Run with timeout
result = await TestHelpers.run_with_timeout(
    slow_async_function,
    timeout=10.0,
    arg1="value"
)
```

## Using Fixtures from conftest.py

The `conftest.py` file provides numerous fixtures that can be used in any test:

### Basic Fixtures
```python
def test_with_fixtures(
    test_data_dir,          # Temporary directory for test data
    sample_query_data,      # Sample query data dict
    sample_expert_response, # Sample response data dict
    test_env_vars          # Test environment variables
):
    # Use fixtures in test
    pass
```

### Mock Fixtures
```python
async def test_with_mocks(
    mock_expert_manager,    # Mock ExpertManager
    mock_query_handler,     # Mock QueryHandler
    mock_response_collector,# Mock ResponseCollector
    mock_mcp_manager       # Mock MCPManager
):
    # Use mocks in test
    pass
```

### AI Provider Mocks
```python
async def test_with_ai_mocks(
    mock_claude_api,    # Mock Anthropic API
    mock_openai_api,    # Mock OpenAI API
    mock_gemini_api     # Mock Google Gemini API
):
    # Use AI mocks in test
    pass
```

## Best Practices

1. **Use Factory Methods**: Prefer `MockFactory` methods over creating mocks manually
2. **Generate Realistic Data**: Use `TestDataGenerator` for realistic test scenarios
3. **Express Intent**: Use custom assertions to make test intent clear
4. **Leverage Fixtures**: Use fixtures from `conftest.py` to reduce boilerplate
5. **Test Isolation**: Use temporary directories and clean environment fixtures
6. **Async Testing**: Use async utilities for testing async code properly

## Example Test File

See `test_example_with_utilities.py` for a comprehensive example of using all these utilities together.

## Adding New Utilities

When adding new utilities:

1. Add to the appropriate module based on functionality
2. Include docstrings with usage examples
3. Export from `__init__.py` for easy imports
4. Add tests for the utility itself
5. Update this README with examples