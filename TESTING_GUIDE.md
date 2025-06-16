# 🧪 Comprehensive Testing Framework Guide

This guide provides complete documentation for the comprehensive testing framework created for the CODE platform, including the deploy-code module, MCP servers, and all components. Includes unit tests, integration tests, end-to-end tests, performance tests, and security tests.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Testing Framework Overview](#testing-framework-overview)
- [Test Categories](#test-categories)
- [Running Tests](#running-tests)
- [Configuration](#configuration)
- [Writing Tests](#writing-tests)
- [Quality Gates](#quality-gates)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** with pip
- **Node.js 18+** with npm
- **Rust 1.70+** with cargo
- **Docker** (for integration tests)
- **Git** (for CI/CD)

### Installation

```bash
# Install Python dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install Node.js dependencies
npm install

# Install Rust dependencies
cargo fetch

# Verify installation
python -m pytest --version
npm test -- --version
cargo test --version
```

### Running All Tests

```bash
# Run comprehensive test suite
make test-all

# Test deploy-code module specifically
cd deploy-code-module
make test
cd ..

# Or run individually by language
make test-python
make test-typescript  
make test-rust
```

## 🏗️ Testing Framework Overview

The testing framework provides:

- **Multi-language support**: Python (pytest), TypeScript (Jest), Rust (cargo test)
- **Comprehensive coverage**: Unit, integration, E2E, performance, security tests
- **Mock implementations**: Realistic test doubles for all MCP servers
- **Quality gates**: Automated quality validation with coverage and performance thresholds
- **CI/CD integration**: GitHub Actions workflows with parallel execution
- **Test data management**: Fixtures, scenarios, and mock data generation

### Architecture

```
tests/
├── unit/                    # Unit tests by language
│   ├── python/             # Python unit tests
│   ├── typescript/         # TypeScript unit tests
│   └── rust/               # Rust unit tests
├── integration/            # Integration tests
├── e2e/                    # End-to-end tests
├── performance/            # Performance and load tests
├── security/               # Security tests
├── mocks/                  # Mock implementations
├── fixtures/               # Test data and fixtures
├── quality_gates/          # Quality validation
└── utils/                  # Test utilities
```

## 🎯 Test Categories

### 1. Unit Tests

Test individual MCP server components in isolation.

**Scope:**
- Individual tool functionality
- Parameter validation
- Error handling
- Response formatting
- Security validations

**Languages:**
- **Python**: `pytest tests/unit/python/`
- **TypeScript**: `npm test tests/unit/typescript/`
- **Rust**: `cargo test --lib`

**Example:**
```python
# tests/unit/python/test_mcp_servers.py
async def test_execute_command_security(mock_server):
    """Test command execution blocks dangerous commands"""
    with pytest.raises(MCPException, match="Dangerous command blocked"):
        await mock_server.call_tool("execute_command", {
            "command": "rm -rf /"
        })
```

### 2. Integration Tests

Test interactions between multiple MCP servers and components.

**Scope:**
- Multi-server workflows
- Context management
- Data flow between tools
- State consistency
- Cross-server dependencies

**Example:**
```python
# tests/integration/test_multi_server_workflows.py
async def test_build_deploy_monitor_workflow(orchestrator):
    """Test complete DevOps workflow"""
    workflow = {
        "steps": [
            {"server": "docker", "tool": "docker_build", ...},
            {"server": "kubernetes", "tool": "kubectl_apply", ...},
            {"server": "prometheus-monitoring", "tool": "prometheus_query", ...}
        ]
    }
    result = await orchestrator.execute_workflow(workflow)
    assert result["success"] is True
```

### 3. End-to-End Tests

Test complete real-world scenarios from start to finish.

**Scope:**
- Complete user journeys
- Production-like workflows
- External service integration
- Disaster recovery scenarios
- Security incident response

**Example:**
```python
# tests/e2e/test_real_world_scenarios.py
async def test_full_cicd_pipeline(test_environment, orchestrator):
    """Test complete CI/CD pipeline"""
    pipeline = create_cicd_pipeline()
    result = await orchestrator.execute_workflow(pipeline)
    
    # Verify critical steps
    assert_deployment_successful(result)
    assert_monitoring_enabled(result)
    assert_security_scans_passed(result)
```

### 4. Performance Tests

Test performance characteristics and scalability.

**Scope:**
- Response time benchmarks
- Throughput testing
- Concurrent execution
- Memory usage
- Load testing scenarios

**Example:**
```python
# Pytest benchmark
def test_tool_performance(benchmark, mock_server):
    """Benchmark tool execution time"""
    result = benchmark(
        mock_server.call_tool,
        "execute_command",
        {"command": "echo test"}
    )
    assert result["success"] is True
```

### 5. Security Tests

Test security measures and vulnerability detection.

**Scope:**
- Input validation
- SQL injection prevention
- XSS protection
- Path traversal protection
- Command injection prevention
- Authentication/authorization

**Example:**
```python
# tests/unit/python/test_mcp_servers.py
@pytest.mark.security
async def test_path_traversal_protection(mock_server):
    """Test path traversal attack prevention"""
    malicious_paths = ["../../../etc/passwd", "..\\..\\windows\\system32"]
    
    for path in malicious_paths:
        with pytest.raises(MCPException):
            await mock_server.call_tool("read_file", {"path": path})
```

## 🏃 Running Tests

### Command Line Options

#### Python (pytest)

```bash
# Run all Python tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests only
pytest -m security          # Security tests only
pytest -m "not slow"        # Skip slow tests

# Run specific test files
pytest tests/unit/python/test_mcp_servers.py

# Run with parallel execution
pytest -n auto

# Run with verbose output
pytest -v --tb=short
```

#### TypeScript (Jest)

```bash
# Run all TypeScript tests
npm test

# Run with coverage
npm test -- --coverage

# Run specific test patterns
npm test -- --testNamePattern="MCP Server"
npm test -- --testPathPattern="unit"

# Run in watch mode
npm test -- --watch

# Run with verbose output
npm test -- --verbose
```

#### Rust (cargo)

```bash
# Run all Rust tests
cargo test

# Run with coverage
cargo tarpaulin --out html

# Run specific test modules
cargo test integration_tests

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Test Execution Scripts

```bash
# Run comprehensive test suite
./scripts/run_all_tests.sh

# Run tests by category
./scripts/run_unit_tests.sh
./scripts/run_integration_tests.sh
./scripts/run_e2e_tests.sh
./scripts/run_security_tests.sh
./scripts/run_performance_tests.sh
```

### Environment Variables

```bash
# Test configuration
export TEST_ENVIRONMENT=local
export LOG_LEVEL=ERROR
export COVERAGE_THRESHOLD=80

# Skip expensive tests in development
export SKIP_SLOW_TESTS=true
export SKIP_E2E_TESTS=true

# External service URLs for integration tests
export REDIS_URL=redis://localhost:6379
export POSTGRES_URL=postgresql://test:test@localhost:5432/test
```

## ⚙️ Configuration

### pytest.ini

```ini
[tool:pytest]
testpaths = tests
addopts = 
    -v
    --cov=src
    --cov-report=html:coverage/html
    --cov-report=xml:coverage/coverage.xml
    --cov-fail-under=80
    --junitxml=test-results/pytest-results.xml

markers =
    unit: Unit tests
    integration: Integration tests
    e2e: End-to-end tests
    performance: Performance tests
    security: Security tests
    slow: Tests that take longer than 10 seconds
```

### jest.config.js

```javascript
module.exports = {
  testEnvironment: 'node',
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  testMatch: [
    '**/__tests__/**/*.(js|ts)',
    '**/*.(test|spec).(js|ts)'
  ]
};
```

### Cargo.toml

```toml
[package.metadata.testing]
timeout = 300
parallel = true
coverage = true

[[test]]
name = "integration_tests"
path = "tests/integration_tests.rs"
```

## ✍️ Writing Tests

### Test Structure Guidelines

#### 1. Arrange-Act-Assert Pattern

```python
async def test_docker_build():
    # Arrange
    server = MockDockerServer()
    build_params = {
        "dockerfile_path": "./Dockerfile",
        "tag": "test:latest"
    }
    
    # Act
    result = await server.call_tool("docker_build", build_params)
    
    # Assert
    assert result["success"] is True
    assert result["image_id"].startswith("sha256:")
    assert result["tag"] == "test:latest"
```

#### 2. Test Naming Conventions

```python
def test_[component]_[action]_[expected_outcome]():
    """Test that [component] [action] results in [expected_outcome]"""
    pass

# Examples:
def test_docker_server_build_creates_image():
def test_kubernetes_server_apply_deploys_manifest():
def test_security_scanner_scan_detects_vulnerabilities():
```

#### 3. Fixture Usage

```python
@pytest.fixture
def mock_server():
    """Create mock MCP server for testing"""
    server = MockMCPServer("test-server")
    server.add_tool(create_test_tool())
    yield server
    server.cleanup()

def test_with_fixture(mock_server):
    """Test using fixture"""
    result = mock_server.call_tool("test_tool", {})
    assert result["success"] is True
```

### Mock Implementation Guidelines

#### 1. Realistic Behavior

```python
class MockDockerServer(BaseMockMCPServer):
    async def docker_build(self, params):
        # Validate inputs like real Docker
        if not params.get("dockerfile_path"):
            raise Exception("Dockerfile path required")
        
        # Simulate build time
        await asyncio.sleep(0.1)  # Simulate build delay
        
        # Return realistic response
        return {
            "image_id": f"sha256:{uuid.uuid4().hex}",
            "tag": params.get("tag", "latest"),
            "build_time": 45.2,
            "size_bytes": 128 * 1024 * 1024
        }
```

#### 2. Security Validation

```python
async def _execute_command(self, params):
    """Mock command execution with security checks"""
    command = params["command"]
    
    # Block dangerous commands
    dangerous_commands = ["rm -rf", "format", "shutdown"]
    if any(dangerous in command.lower() for dangerous in dangerous_commands):
        raise MCPException(f"Dangerous command blocked: {command}")
    
    return {"stdout": f"Mock output: {command}", "exit_code": 0}
```

### Test Data Management

#### 1. Using Test Data Manager

```python
from tests.fixtures.test_data_manager import get_test_data_manager

def test_with_fixtures():
    """Test using managed test data"""
    manager = get_test_data_manager()
    
    # Load fixture data
    docker_data = manager.load_fixture("docker")
    users = manager.load_fixture("users")
    
    # Use in tests
    assert len(docker_data["containers"]) > 0
    assert users[0]["role"] == "admin"
```

#### 2. Generating Test Scenarios

```python
def test_security_scenarios():
    """Test multiple security scenarios"""
    manager = get_test_data_manager()
    scenarios = manager.generate_test_scenarios("security")
    
    for scenario in scenarios:
        # Run test with scenario data
        result = run_security_test(scenario.input_data)
        assert result == scenario.expected_outputs
```

## 🚪 Quality Gates

Quality gates automatically validate code quality, coverage, performance, and security metrics.

### Coverage Requirements

- **Line Coverage**: ≥ 80%
- **Branch Coverage**: ≥ 75%
- **Function Coverage**: ≥ 85%

### Performance Requirements

- **Average Response Time**: ≤ 2.0 seconds
- **Maximum Response Time**: ≤ 10.0 seconds
- **Minimum Throughput**: ≥ 50 requests/second

### Security Requirements

- **Critical Vulnerabilities**: 0
- **High Vulnerabilities**: ≤ 2
- **Medium Vulnerabilities**: ≤ 10

### Running Quality Gates

```bash
# Validate quality gates
python tests/quality_gates/quality_gate_validator.py \
    --results-path ./test-results \
    --output quality-report.json \
    --fail-on-error

# View quality report
cat quality-report.json | jq '.summary'
```

### Custom Quality Gates

```python
# Add custom quality gate
gate = QualityGate(
    name="custom_metric",
    description="Custom quality metric",
    category="custom",
    threshold=90.0,
    operator="gte",
    severity="warning"
)

validator = QualityGateValidator()
validator.gates.append(gate)
```

## 🔄 CI/CD Integration

The framework includes comprehensive GitHub Actions workflows for automated testing.

### Workflow Triggers

- **Push to main/develop**: Full test suite
- **Pull requests**: Core test suite
- **Scheduled (nightly)**: Extended test suite with performance and E2E tests
- **Manual dispatch**: Configurable test scope

### Workflow Features

- **Parallel execution**: Tests run in parallel across multiple workers
- **Matrix testing**: Tests across Python 3.11+, Node.js 18+, Rust stable
- **Conditional execution**: Skip expensive tests on feature branches
- **Artifact collection**: Test reports, coverage data, security scans
- **Quality gates**: Automatic validation of coverage and performance
- **Notifications**: PR comments with test results

### Configuration

```yaml
# .github/workflows/comprehensive-testing.yml
env:
  COVERAGE_THRESHOLD: '80'
  PERFORMANCE_THRESHOLD: '95'

jobs:
  unit-tests:
    strategy:
      matrix:
        include:
          - name: python-unit
            language: python
          - name: typescript-unit  
            language: typescript
          - name: rust-unit
            language: rust
```

### Local CI Simulation

```bash
# Simulate CI environment locally
docker run --rm -v $(pwd):/workspace \
  -e GITHUB_ACTIONS=true \
  -e CI=true \
  python:3.11 \
  bash -c "cd /workspace && pip install -r requirements-dev.txt && pytest"
```

## 📊 Test Reporting

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=src --cov-report=html
open coverage/html/index.html

# Generate XML coverage report for CI
pytest --cov=src --cov-report=xml

# Coverage badge generation
coverage-badge -o coverage-badge.svg
```

### Performance Reports

```bash
# Generate performance benchmarks
pytest --benchmark-only --benchmark-json=benchmark.json

# View performance trends
python scripts/analyze_performance.py benchmark.json
```

### Security Reports

```bash
# Run security scans
safety check --json --output safety-report.json
bandit -r src/ -f json -o bandit-report.json
semgrep --config=auto src/ --json --output=semgrep-report.json
```

### Consolidated Reporting

```bash
# Generate comprehensive test report
python tests/generate_test_report.py \
    --test-results ./test-results \
    --coverage ./coverage \
    --benchmarks ./benchmark.json \
    --security ./security-reports \
    --output ./consolidated-report.html
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Import Errors

```bash
# Issue: Module not found
ModuleNotFoundError: No module named 'src.mcp'

# Solution: Add src to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
# Or use pytest-pythonpath plugin
pip install pytest-pythonpath
```

#### 2. Async Test Issues

```python
# Issue: RuntimeError: Event loop is closed
# Solution: Use pytest-asyncio
@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result is not None
```

#### 3. Mock Server Issues

```python
# Issue: Mock server not responding correctly
# Solution: Check server initialization
@pytest.fixture
async def mock_server():
    server = MockMCPServer("test")
    await server.initialize()  # Ensure proper initialization
    yield server
    await server.cleanup()
```

#### 4. Performance Test Flakiness

```python
# Issue: Performance tests failing intermittently
# Solution: Use statistical analysis
def test_performance_stable():
    times = []
    for _ in range(10):  # Multiple samples
        start = time.time()
        execute_operation()
        times.append(time.time() - start)
    
    avg_time = statistics.mean(times)
    std_dev = statistics.stdev(times)
    
    # Allow for some variance
    assert avg_time < 2.0
    assert std_dev < 0.5  # Low variance
```

### Debug Configuration

```python
# pytest.ini - Debug configuration
[tool:pytest]
log_cli = true
log_cli_level = DEBUG
log_cli_format = %(asctime)s [%(levelname)8s] %(name)s: %(message)s
```

### Test Isolation Issues

```python
# Issue: Tests affecting each other
# Solution: Proper cleanup and isolation
@pytest.fixture(autouse=True)
def isolate_test():
    """Ensure test isolation"""
    # Setup
    original_state = get_global_state()
    
    yield
    
    # Cleanup
    restore_global_state(original_state)
    clear_caches()
    reset_mocks()
```

## 📚 Additional Resources

### Documentation

- [MCP Protocol Specification](https://docs.mcp.com)
- [pytest Documentation](https://docs.pytest.org)
- [Jest Documentation](https://jestjs.io/docs)
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)

### Best Practices

- **Test Naming**: Use descriptive, action-oriented test names
- **Test Structure**: Follow Arrange-Act-Assert pattern
- **Test Data**: Use fixtures and factories for consistent test data
- **Mocking**: Mock external dependencies, not internal logic
- **Coverage**: Aim for high coverage but focus on meaningful tests
- **Performance**: Include performance tests for critical paths
- **Security**: Test all input validation and security measures

### Tools and Libraries

- **Python**: pytest, pytest-cov, pytest-asyncio, pytest-benchmark, pytest-mock
- **TypeScript**: Jest, @jest/globals, @types/jest
- **Rust**: cargo test, criterion (benchmarks), tarpaulin (coverage)
- **Security**: safety, bandit, semgrep, grype
- **CI/CD**: GitHub Actions, codecov, dependabot

---

## 🎉 Conclusion

This comprehensive testing framework provides everything needed to ensure MCP server quality and reliability:

✅ **Complete Coverage**: Unit, integration, E2E, performance, and security tests  
✅ **Multi-language Support**: Python, TypeScript, and Rust  
✅ **Quality Gates**: Automated validation of coverage and performance  
✅ **CI/CD Integration**: GitHub Actions workflows with parallel execution  
✅ **Mock Implementations**: Realistic test doubles for all servers  
✅ **Test Data Management**: Fixtures and scenarios for consistent testing  

The framework is designed to scale with your MCP server ecosystem while maintaining high quality standards and developer productivity.

**Happy Testing! 🧪**