# Testing Strategies Guide

**Version**: 2.0.0  
**Date**: December 08, 2025  
**For**: CODE Project Development Team

## Overview

This guide outlines comprehensive testing strategies for the Claude-Optimized Deployment Engine (CODE) project. Our testing framework covers unit tests, integration tests, security tests, performance tests, and specialized testing for AI systems and MCP servers.

## Testing Philosophy

### Principles
1. **Test-Driven Development (TDD)**: Write tests before implementation
2. **Comprehensive Coverage**: Unit, integration, security, performance
3. **AI-First Testing**: Special considerations for AI system testing
4. **Security-First**: Security testing integrated throughout
5. **Performance-Aware**: Performance testing as a first-class citizen
6. **MCP-Aware**: Specialized testing for MCP server interactions

### Testing Pyramid
```
                🔺 E2E Tests (Few)
              🔺🔺🔺 Integration Tests (Some)
          🔺🔺🔺🔺🔺🔺 Unit Tests (Many)
      🔺🔺🔺🔺🔺🔺🔺🔺🔺 Security Tests (Throughout)
```

## Test Categories

### 1. Unit Tests

#### Location: `tests/unit/`

**Purpose**: Test individual functions and classes in isolation

**Coverage Requirements**: 90%+ for core modules

#### Example: Circle of Experts Unit Test
```python
# tests/unit/test_expert_manager.py
import pytest
from unittest.mock import AsyncMock, patch
from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
from src.core.exceptions import AIAPIError

@pytest.mark.asyncio
async def test_expert_manager_initialization():
    """Test expert manager initializes with correct configuration"""
    manager = EnhancedExpertManager(
        preferred_experts=["ollama-mixtral"],
        max_cost_per_query=0.10
    )
    
    assert manager.preferred_experts == ["ollama-mixtral"]
    assert manager.max_cost_per_query == 0.10
    assert manager.expert_count == 1  # Default when preferred_experts provided

@pytest.mark.asyncio
async def test_quick_consult_success():
    """Test successful expert consultation"""
    with patch('src.circle_of_experts.experts.ollama_expert.OllamaExpert.query') as mock_query:
        mock_query.return_value = {
            "response": "This is a test response",
            "confidence": 0.9,
            "cost": 0.0
        }
        
        manager = EnhancedExpertManager(preferred_experts=["ollama-mixtral"])
        result = await manager.quick_consult("Test query")
        
        assert result["consensus"] == True
        assert "This is a test response" in result["recommendations"]
        assert result["cost_breakdown"]["total"] == 0.0
        
        mock_query.assert_called_once()

@pytest.mark.asyncio
async def test_expert_failure_handling():
    """Test handling of expert failures with fallback"""
    with patch('src.circle_of_experts.experts.openai_expert.OpenAIExpert.query') as mock_openai, \
         patch('src.circle_of_experts.experts.ollama_expert.OllamaExpert.query') as mock_ollama:
        
        # First expert fails
        mock_openai.side_effect = AIAPIError("Rate limit exceeded")
        
        # Second expert succeeds
        mock_ollama.return_value = {
            "response": "Fallback response",
            "confidence": 0.8,
            "cost": 0.0
        }
        
        manager = EnhancedExpertManager(
            preferred_experts=["openai-gpt4", "ollama-mixtral"],
            fallback_enabled=True
        )
        
        result = await manager.quick_consult("Test query")
        
        assert result["consensus"] == True
        assert "Fallback response" in result["recommendations"]
        assert len(result["failed_experts"]) == 1
        assert result["failed_experts"][0]["expert"] == "openai-gpt4"
```

#### Example: MCP Client Unit Test
```python
# tests/unit/test_mcp_client.py
import pytest
from unittest.mock import AsyncMock, patch
from src.mcp.client import MCPClient
from src.core.exceptions import MCPServerNotFoundError, MCPToolExecutionError

@pytest.mark.asyncio
async def test_mcp_client_execute_tool_success():
    """Test successful MCP tool execution"""
    with patch('src.mcp.client.MCPClient._connect_to_server') as mock_connect:
        mock_server = AsyncMock()
        mock_server.execute_tool.return_value = {"status": "success", "result": {"containers": []}}
        mock_connect.return_value = mock_server
        
        client = MCPClient()
        result = await client.execute_tool("docker", "ps", {})
        
        assert result["status"] == "success"
        assert "containers" in result["result"]
        mock_server.execute_tool.assert_called_once_with("ps", {})

@pytest.mark.asyncio
async def test_mcp_client_server_not_found():
    """Test handling of unknown MCP server"""
    client = MCPClient()
    
    with pytest.raises(MCPServerNotFoundError) as exc_info:
        await client.execute_tool("nonexistent-server", "test", {})
    
    assert "nonexistent-server" in str(exc_info.value)
    assert exc_info.value.context["requested_server"] == "nonexistent-server"
```

### 2. Integration Tests

#### Location: `tests/integration/`

**Purpose**: Test interactions between components

**Focus Areas**:
- Circle of Experts with real AI providers
- MCP server integration
- Database operations
- Authentication flows
- Error handling across components

#### Example: Circle of Experts Integration Test
```python
# tests/integration/test_circle_of_experts_integration.py
import pytest
from src.circle_of_experts import EnhancedExpertManager
from src.auth.models import UserContext
from src.database.repositories import QueryRepository

@pytest.mark.integration
@pytest.mark.asyncio
async def test_expert_consultation_with_database_logging():
    """Test expert consultation with database persistence"""
    manager = EnhancedExpertManager()
    user_context = UserContext(user_id="test-user", role="developer")
    query_repo = QueryRepository()
    
    # Perform consultation
    result = await manager.quick_consult(
        "What is the best way to optimize Python performance?",
        user_context=user_context,
        audit_trail=True
    )
    
    # Verify consultation succeeded
    assert result["consensus"] == True
    assert len(result["recommendations"]) > 0
    
    # Verify database logging
    consultation_id = result["consultation_id"]
    saved_query = await query_repo.get_by_consultation_id(consultation_id)
    
    assert saved_query is not None
    assert saved_query.user_id == "test-user"
    assert "optimize Python performance" in saved_query.query_text
    assert saved_query.status == "completed"

@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcp_server_real_execution():
    """Test real MCP server execution (requires docker)"""
    from src.mcp.client import MCPClient
    
    client = MCPClient()
    
    # Test docker server (if available)
    try:
        result = await client.execute_tool("docker", "version", {})
        assert "version" in result or "error" in result
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")

@pytest.mark.integration
@pytest.mark.asyncio
async def test_security_integration():
    """Test security features integration"""
    from src.auth.rbac import check_permission
    from src.auth.audit import audit_action
    from src.circle_of_experts import EnhancedExpertManager
    
    user_context = UserContext(user_id="test-user", role="developer")
    
    # Check permissions
    can_consult = await check_permission(user_context, "expert_consultation")
    assert can_consult == True
    
    # Perform consultation with audit
    manager = EnhancedExpertManager()
    result = await manager.quick_consult(
        "Test security integration",
        user_context=user_context,
        audit_trail=True
    )
    
    # Verify audit log was created
    # This would check the audit repository for the logged action
    assert result["audit_logged"] == True
```

### 3. End-to-End Tests

#### Location: `tests/e2e/`

**Purpose**: Test complete user workflows

#### Example: Complete Deployment Workflow Test
```python
# tests/e2e/test_deployment_workflow.py
import pytest
from src.api.main import app
from httpx import AsyncClient

@pytest.mark.e2e
@pytest.mark.asyncio
async def test_complete_deployment_workflow():
    """Test complete deployment workflow from API to execution"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # 1. Authenticate
        auth_response = await client.post("/auth/login", json={
            "username": "test_user",
            "password": "test_password"
        })
        assert auth_response.status_code == 200
        token = auth_response.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Check system health
        health_response = await client.get("/health", headers=headers)
        assert health_response.status_code == 200
        
        # 3. Get expert consultation for deployment strategy
        consultation_response = await client.post("/experts/consult", json={
            "query": "Best strategy for deploying a Python web application",
            "expert_count": 2,
            "include_security_analysis": True
        }, headers=headers)
        assert consultation_response.status_code == 200
        consultation_result = consultation_response.json()
        assert consultation_result["consensus"] == True
        
        # 4. Execute MCP tool based on recommendation
        if "docker" in consultation_result["recommendations"][0].lower():
            mcp_response = await client.post("/mcp/execute", json={
                "server": "docker",
                "tool": "ps",
                "arguments": {"all": False}
            }, headers=headers)
            assert mcp_response.status_code == 200
```

### 4. Security Tests

#### Location: `tests/security/`

**Purpose**: Test security vulnerabilities and mitigations

#### Example: Security Vulnerability Tests
```python
# tests/security/test_security_vulnerabilities.py
import pytest
from src.core.path_validation import validate_path
from src.core.log_sanitization import sanitize_log_input
from src.core.exceptions import PathValidationError

def test_path_traversal_prevention():
    """Test path traversal vulnerability prevention"""
    # Valid paths should pass
    assert validate_path("/valid/path/file.txt") == "/valid/path/file.txt"
    assert validate_path("./relative/path.txt") == "./relative/path.txt"
    
    # Path traversal attempts should fail
    with pytest.raises(PathValidationError):
        validate_path("../../../etc/passwd")
    
    with pytest.raises(PathValidationError):
        validate_path("/valid/path/../../../etc/passwd")
    
    with pytest.raises(PathValidationError):
        validate_path("..\\..\\windows\\system32\\config\\sam")

def test_log_injection_prevention():
    """Test log injection vulnerability prevention"""
    # Safe inputs should pass through
    safe_input = "Normal log message"
    assert sanitize_log_input(safe_input) == safe_input
    
    # Malicious inputs should be sanitized
    malicious_inputs = [
        "User input\nFAKE LOG ENTRY: Admin access granted",
        "Input\rCarriage return injection",
        "Input with \x00 null byte",
        "ANSI escape codes \x1b[31mRED TEXT\x1b[0m"
    ]
    
    for malicious_input in malicious_inputs:
        sanitized = sanitize_log_input(malicious_input)
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "\x00" not in sanitized
        assert "\x1b" not in sanitized

@pytest.mark.asyncio
async def test_sql_injection_prevention():
    """Test SQL injection vulnerability prevention"""
    from src.database.repositories import UserRepository
    
    repo = UserRepository()
    
    # These should not cause SQL injection
    malicious_usernames = [
        "'; DROP TABLE users; --",
        "admin' OR '1'='1",
        "user'; UPDATE users SET role='admin' WHERE username='user'; --"
    ]
    
    for username in malicious_usernames:
        # Should either find no user or handle safely
        user = await repo.get_by_username(username)
        # The query should execute safely without causing injection
        assert user is None or isinstance(user, dict)

@pytest.mark.asyncio
async def test_authentication_bypass_prevention():
    """Test authentication bypass vulnerability prevention"""
    from src.auth.tokens import verify_token
    from src.core.exceptions import AuthenticationError
    
    # Invalid tokens should be rejected
    invalid_tokens = [
        "invalid.token.format",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid",
        None,
        "",
        "Bearer invalid-token"
    ]
    
    for token in invalid_tokens:
        with pytest.raises(AuthenticationError):
            await verify_token(token)
```

### 5. Performance Tests

#### Location: `tests/performance/`

**Purpose**: Test performance characteristics and identify bottlenecks

#### Example: Performance Tests
```python
# tests/performance/test_performance.py
import pytest
import asyncio
import time
from src.circle_of_experts import EnhancedExpertManager
from src.mcp.client import MCPClient

@pytest.mark.performance
@pytest.mark.asyncio
async def test_expert_consultation_performance():
    """Test expert consultation performance under load"""
    manager = EnhancedExpertManager(preferred_experts=["ollama-mixtral"])
    
    # Warm up
    await manager.quick_consult("Warm up query")
    
    # Performance test
    start_time = time.time()
    
    # Run 10 concurrent consultations
    tasks = [
        manager.quick_consult(f"Performance test query {i}")
        for i in range(10)
    ]
    
    results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Performance assertions
    assert total_time < 30.0  # Should complete in under 30 seconds
    assert len(results) == 10
    assert all(result["consensus"] for result in results)
    
    # Average response time should be reasonable
    avg_time = total_time / 10
    assert avg_time < 5.0  # Average under 5 seconds per query

@pytest.mark.performance
@pytest.mark.asyncio
async def test_mcp_client_performance():
    """Test MCP client performance"""
    client = MCPClient()
    
    start_time = time.time()
    
    # Run multiple MCP operations
    tasks = [
        client.execute_tool("filesystem", "list", {"path": "."})
        for _ in range(5)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Should complete quickly
    assert total_time < 10.0
    
    # Check for any exceptions
    successful_results = [r for r in results if not isinstance(r, Exception)]
    assert len(successful_results) > 0

@pytest.mark.performance
def test_memory_usage():
    """Test memory usage of core components"""
    import psutil
    import gc
    
    # Get initial memory usage
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Import and use heavy components
    from src.circle_of_experts import EnhancedExpertManager
    
    manager = EnhancedExpertManager()
    
    # Force garbage collection
    gc.collect()
    
    # Check memory after import
    after_import_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = after_import_memory - initial_memory
    
    # Memory increase should be reasonable (less than 100MB for imports)
    assert memory_increase < 100, f"Memory increase: {memory_increase}MB"
```

### 6. AI System Testing

#### Location: `tests/ai/`

**Purpose**: Test AI-specific functionality

#### Example: AI System Tests
```python
# tests/ai/test_ai_systems.py
import pytest
from src.circle_of_experts import EnhancedExpertManager

@pytest.mark.ai
@pytest.mark.asyncio
async def test_expert_consensus_mechanism():
    """Test expert consensus mechanism"""
    manager = EnhancedExpertManager(
        preferred_experts=["ollama-mixtral", "ollama-codellama"],
        min_consensus=0.8
    )
    
    # Test with a clear technical question
    result = await manager.quick_consult(
        "What is the time complexity of binary search?",
        expert_count=2
    )
    
    # Should reach consensus on this clear technical question
    assert result["consensus"] == True
    assert "O(log n)" in result["recommendations"][0]
    assert result["consensus_score"] >= 0.8

@pytest.mark.ai
@pytest.mark.asyncio
async def test_expert_cost_estimation():
    """Test expert cost estimation accuracy"""
    manager = EnhancedExpertManager()
    
    # Estimate cost
    estimated_cost = await manager.estimate_query_cost(
        "Short query",
        expert_count=1
    )
    
    # Actual consultation
    result = await manager.quick_consult(
        "Short query",
        expert_count=1
    )
    
    actual_cost = result["cost_breakdown"]["total"]
    
    # Estimation should be reasonably accurate (within 50%)
    cost_diff = abs(estimated_cost["total_estimated"] - actual_cost)
    cost_accuracy = cost_diff / max(estimated_cost["total_estimated"], actual_cost)
    
    assert cost_accuracy < 0.5, f"Cost estimation accuracy: {cost_accuracy}"

@pytest.mark.ai
@pytest.mark.asyncio
async def test_ai_fallback_mechanism():
    """Test AI fallback when preferred experts fail"""
    manager = EnhancedExpertManager(
        preferred_experts=["nonexistent-expert"],
        fallback_enabled=True
    )
    
    # Should fall back to available experts
    result = await manager.quick_consult("Test fallback query")
    
    assert result["consensus"] == True
    assert len(result["failed_experts"]) == 1
    assert result["failed_experts"][0]["expert"] == "nonexistent-expert"
    assert len(result["successful_experts"]) > 0
```

## Testing Infrastructure

### Test Configuration

#### conftest.py Setup
```python
# tests/conftest.py
import pytest
import asyncio
import os
from pathlib import Path
from src.database.connection import get_engine, get_session
from src.database.models import Base
from sqlalchemy_utils import database_exists, create_database, drop_database

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_database():
    """Create test database"""
    test_db_url = "sqlite:///test.db"
    os.environ["DATABASE_URL"] = test_db_url
    
    engine = get_engine()
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    if os.path.exists("test.db"):
        os.remove("test.db")

@pytest.fixture
async def db_session(test_database):
    """Create database session for test"""
    async with get_session() as session:
        yield session

@pytest.fixture
def mock_ai_response():
    """Mock AI response for testing"""
    return {
        "response": "Mock AI response",
        "confidence": 0.9,
        "cost": 0.001,
        "tokens_used": 100
    }
```

### Test Utilities

#### Test Helpers
```python
# tests/utils/helpers.py
import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock

class MockExpert:
    """Mock expert for testing"""
    
    def __init__(self, name: str, response: str = "Mock response", confidence: float = 0.9):
        self.name = name
        self.response = response
        self.confidence = confidence
    
    async def query(self, prompt: str, **kwargs) -> Dict[str, Any]:
        return {
            "response": self.response,
            "confidence": self.confidence,
            "cost": 0.0,
            "tokens_used": len(prompt.split())
        }

class MockMCPServer:
    """Mock MCP server for testing"""
    
    def __init__(self, name: str):
        self.name = name
        self.tools = {}
    
    def add_tool(self, tool_name: str, response: Any):
        self.tools[tool_name] = response
    
    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name in self.tools:
            return self.tools[tool_name]
        raise ValueError(f"Tool {tool_name} not found")

def async_test(coro):
    """Decorator to run async tests"""
    def wrapper():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro())
        finally:
            loop.close()
    return wrapper
```

## Test Execution

### Running Tests

#### Basic Test Commands
```bash
# Run all tests
make test

# Run specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-e2e          # End-to-end tests only
make test-security     # Security tests only
make test-performance  # Performance tests only
make test-ai           # AI-specific tests only

# Run with coverage
make test-all          # All tests with coverage report

# Run specific test file
pytest tests/unit/test_expert_manager.py -v

# Run specific test function
pytest tests/unit/test_expert_manager.py::test_expert_manager_initialization -v

# Run tests with specific marker
pytest -m "unit" -v
pytest -m "integration and not slow" -v
pytest -m "security" -v
```

#### Advanced Test Options
```bash
# Run tests in parallel
pytest -n auto

# Run tests with debugging
pytest --pdb

# Run tests with verbose output
pytest -vv --tb=long

# Run only failed tests from last run
pytest --lf

# Run tests with coverage and HTML report
pytest --cov=src --cov-report=html

# Run tests with profiling
pytest --profile

# Run tests with specific log level
pytest --log-level=DEBUG
```

### Continuous Integration

#### GitHub Actions Test Configuration
```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.10, 3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -e ".[dev]"
    
    - name: Run unit tests
      run: |
        pytest tests/unit -v --cov=src
    
    - name: Run integration tests
      run: |
        pytest tests/integration -v
    
    - name: Run security tests
      run: |
        pytest tests/security -v
        bandit -r src/
        safety check
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## Test Data Management

### Test Fixtures
```python
# tests/fixtures/data.py
import pytest

@pytest.fixture
def sample_deployment_config():
    return {
        "name": "test-app",
        "image": "nginx:latest",
        "replicas": 3,
        "ports": [{"containerPort": 80}],
        "environment": {
            "ENV": "test"
        }
    }

@pytest.fixture
def sample_user_context():
    from src.auth.models import UserContext
    return UserContext(
        user_id="test-user-123",
        username="testuser",
        role="developer",
        permissions=["expert_consultation", "mcp_execution"]
    )

@pytest.fixture
def expert_consultation_response():
    return {
        "consensus": True,
        "consensus_score": 0.95,
        "recommendations": [
            "Use Docker for containerization",
            "Implement health checks",
            "Use resource limits"
        ],
        "cost_breakdown": {
            "total": 0.05,
            "by_expert": {
                "claude-opus": 0.03,
                "gpt-4": 0.02
            }
        },
        "consultation_id": "consult-test-123",
        "expert_responses": [
            {
                "expert": "claude-opus",
                "response": "Detailed recommendation 1",
                "confidence": 0.95,
                "cost": 0.03
            }
        ]
    }
```

## Test Monitoring and Reporting

### Coverage Requirements
- **Unit Tests**: 90%+ coverage for core modules
- **Integration Tests**: 80%+ coverage for API endpoints
- **Security Tests**: 100% coverage for security-critical functions
- **Overall**: 85%+ total coverage

### Performance Benchmarks
- **Expert Consultation**: < 5 seconds average response time
- **MCP Tool Execution**: < 2 seconds for simple operations
- **Database Operations**: < 100ms for queries
- **Memory Usage**: < 500MB for full test suite

### Quality Gates
All tests must pass before merging:
- [ ] Unit tests: 100% pass rate
- [ ] Integration tests: 100% pass rate
- [ ] Security tests: 100% pass rate
- [ ] Performance tests: Meet benchmarks
- [ ] Coverage: Meet minimum requirements
- [ ] Linting: Zero violations
- [ ] Type checking: Zero errors

## Best Practices

### Writing Good Tests

1. **Descriptive Names**: Use clear, descriptive test names
2. **Arrange-Act-Assert**: Structure tests clearly
3. **Independent Tests**: Each test should be independent
4. **Mock External Dependencies**: Use mocks for external services
5. **Test Edge Cases**: Include boundary conditions and error cases
6. **Performance Aware**: Monitor test execution time

### Test Maintenance

1. **Regular Updates**: Keep tests updated with code changes
2. **Refactor Tests**: Refactor tests when refactoring code
3. **Remove Obsolete Tests**: Clean up tests for removed features
4. **Documentation**: Document complex test scenarios
5. **Review Test Coverage**: Regularly review and improve coverage

## Future Testing Enhancements

### Planned Improvements
1. **Chaos Engineering**: Implement chaos testing for resilience
2. **Load Testing**: Add comprehensive load testing
3. **Contract Testing**: Add API contract testing
4. **Visual Testing**: Add visual regression testing for UIs
5. **Property-Based Testing**: Add property-based testing with Hypothesis

### Advanced Testing Tools
- **Locust**: For load testing
- **Hypothesis**: For property-based testing
- **Chaos Monkey**: For chaos engineering
- **Wiremock**: For API mocking
- **Docker Compose**: For integration test environments

---

*Remember: Good tests are investments in code quality, reliability, and maintainability. Our comprehensive testing strategy ensures the CODE project meets the highest standards for AI-powered infrastructure deployment.*