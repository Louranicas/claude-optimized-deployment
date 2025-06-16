# MCP Servers Comprehensive Integration Test Suite

This directory contains comprehensive integration tests for all 11 MCP servers identified in the CODE project. The test suite covers integration testing, tool execution, authentication, error handling, security scenarios, performance testing, and failure resilience.

## 🎯 Tested MCP Servers

1. **BraveMCPServer** - Web search capabilities
2. **DesktopCommanderMCPServer** - Command execution and file management
3. **DockerMCPServer** - Container management
4. **KubernetesMCPServer** - Kubernetes operations
5. **AzureDevOpsMCPServer** - DevOps integration
6. **WindowsSystemMCPServer** - Windows operations
7. **SlackNotificationMCPServer** - Communication and notifications
8. **PrometheusMonitoringMCP** - Monitoring and metrics
9. **SecurityScannerMCPServer** - Security scanning
10. **S3StorageMCPServer** - AWS S3 cloud storage
11. **CloudStorageMCP** - Multi-cloud storage

## 📁 Test Suite Organization

### Core Integration Tests
- **`test_mcp_servers_comprehensive.py`** - Main integration tests covering basic functionality, tool execution, and cross-server workflows

### Security Testing
- **`test_mcp_security_scenarios.py`** - Security-focused tests including:
  - Command injection prevention
  - Path traversal protection
  - Input sanitization
  - SSRF protection
  - Secret detection
  - SQL injection prevention
  - Authentication bypass attempts
  - Privilege escalation prevention

### Failure and Resilience Testing
- **`test_mcp_failure_scenarios.py`** - Failure scenario tests including:
  - Network failures and timeouts
  - Service unavailability
  - Data corruption and malformed responses
  - Resource exhaustion
  - Circuit breaker functionality
  - Graceful degradation
  - Cascading failure prevention

### Performance and Load Testing
- **`test_mcp_performance_load.py`** - Performance tests including:
  - Response time measurements
  - Concurrent request handling
  - Stress testing with high loads
  - Memory usage and leak detection
  - Scalability limits
  - Resource utilization monitoring

### Authentication and Authorization
- **`test_mcp_authentication_authorization.py`** - Auth tests including:
  - User authentication validation
  - Role-based access control (RBAC)
  - Permission enforcement
  - Security context isolation
  - Audit logging
  - Multi-tenant isolation

## 🚀 Running the Tests

### Prerequisites

```bash
# Install Python dependencies
pip install pytest pytest-asyncio pytest-mock pytest-xdist pytest-cov psutil aiohttp

# Ensure project dependencies are installed
pip install -r requirements.txt
```

### Quick Start

```bash
# Run all integration tests
python run_mcp_integration_tests.py

# Run specific test suite
python run_mcp_integration_tests.py --test-suite security

# Run tests for specific servers
python run_mcp_integration_tests.py --servers BraveMCPServer,DockerMCPServer

# Run with verbose output and coverage
python run_mcp_integration_tests.py --verbose --coverage

# Generate HTML report
python run_mcp_integration_tests.py --report-format html --output-file test_report.html
```

### Individual Test Files

```bash
# Run individual test files
pytest tests/integration/test_mcp_servers_comprehensive.py -v
pytest tests/integration/test_mcp_security_scenarios.py -v
pytest tests/integration/test_mcp_failure_scenarios.py -v
pytest tests/integration/test_mcp_performance_load.py -v
pytest tests/integration/test_mcp_authentication_authorization.py -v

# Run with specific markers
pytest tests/integration/ -m "asyncio" -v
pytest tests/integration/ -k "test_authentication" -v
```

## 📊 Test Categories and Coverage

### Functional Testing
- ✅ Tool execution and parameter validation
- ✅ Server initialization and configuration
- ✅ API integration and external service calls
- ✅ File operations and data handling
- ✅ Cross-server workflow integration

### Security Testing
- ✅ Input validation and sanitization
- ✅ Command injection prevention
- ✅ Path traversal protection
- ✅ SSRF (Server-Side Request Forgery) protection
- ✅ Authentication and authorization
- ✅ Secret detection and handling
- ✅ Vulnerability scanning

### Resilience Testing
- ✅ Network failure handling
- ✅ Service degradation scenarios
- ✅ Circuit breaker functionality
- ✅ Rate limiting enforcement
- ✅ Timeout and retry mechanisms
- ✅ Resource exhaustion protection

### Performance Testing
- ✅ Response time benchmarks
- ✅ Concurrent request handling
- ✅ Memory usage optimization
- ✅ CPU utilization monitoring
- ✅ Scalability limits testing
- ✅ Load balancing verification

## 🎨 Test Patterns and Best Practices

### Mock Usage
Tests use comprehensive mocking to isolate MCP servers from external dependencies:

```python
# Example: Mocking external API calls
with patch.object(server, 'session') as mock_session:
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"results": []}
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    result = await server.call_tool("search", {"query": "test"}, user)
```

### Error Simulation
Tests simulate various error conditions:

```python
# Network timeout simulation
mock_session.get.side_effect = asyncio.TimeoutError("Network timeout")

# Service unavailability
mock_response.status = 503

# Data corruption
mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
```

### Performance Metrics
Tests collect detailed performance metrics:

```python
class PerformanceMetrics:
    def __init__(self):
        self.response_times = []
        self.success_count = 0
        self.error_count = 0
    
    def get_statistics(self):
        return {
            "avg_response_time": statistics.mean(self.response_times),
            "p95_response_time": self._percentile(self.response_times, 95),
            "success_rate": self.success_count / (self.success_count + self.error_count)
        }
```

## 🔧 Configuration and Environment

### Environment Variables
Tests can be configured using environment variables:

```bash
# API Keys (for external service tests)
export BRAVE_API_KEY="your_brave_api_key"
export AZURE_DEVOPS_TOKEN="your_azure_token"
export SLACK_BOT_TOKEN="your_slack_token"
export AWS_ACCESS_KEY_ID="your_aws_key"
export AWS_SECRET_ACCESS_KEY="your_aws_secret"

# Test Configuration
export TEST_TIMEOUT=300
export TEST_PARALLEL_WORKERS=4
export TEST_LOG_LEVEL=INFO
```

### Test Data
Tests use mock data and temporary files:

```python
@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)
```

## 📈 Continuous Integration

### GitHub Actions Integration
Tests are designed to run in CI/CD pipelines:

```yaml
name: MCP Integration Tests
on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt
      - name: Run integration tests
        run: |
          python run_mcp_integration_tests.py --report-format junit --output-file test-results.xml
      - name: Upload test results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results.xml
```

### Performance Benchmarks
Set performance thresholds for CI:

```python
# Performance assertions in tests
assert stats["avg_response_time"] < 1.0  # Max 1 second average
assert stats["p95_response_time"] < 2.0  # Max 2 seconds 95th percentile
assert stats["success_rate"] >= 0.95     # Min 95% success rate
```

## 🐛 Debugging and Troubleshooting

### Verbose Logging
Enable detailed logging for debugging:

```bash
# Run with verbose output
python run_mcp_integration_tests.py --verbose

# Set log level
export PYTHONPATH=. python -m pytest tests/integration/ -v -s --log-cli-level=DEBUG
```

### Test Isolation
Tests are designed to be isolated and can run independently:

```bash
# Run single test
pytest tests/integration/test_mcp_servers_comprehensive.py::TestBraveMCPServer::test_web_search_success -v

# Run tests matching pattern
pytest tests/integration/ -k "test_authentication" -v
```

### Common Issues

1. **Import Errors**: Ensure PYTHONPATH includes project root
2. **Permission Errors**: Check file permissions for temporary directories
3. **Network Timeouts**: Increase timeout values for slow environments
4. **Memory Issues**: Run tests with reduced concurrency on limited systems

## 📋 Test Reports

### Available Report Formats

1. **Console** (default) - Human-readable terminal output
2. **JSON** - Machine-readable structured data
3. **HTML** - Visual web-based report
4. **JUnit XML** - Compatible with CI systems

### Sample Report Output

```
================================================================================
MCP SERVERS INTEGRATION TEST REPORT
================================================================================
Generated: 2024-01-15 14:30:00
Total Duration: 45.23s
Success Rate: 95.5%

basic                    ✅ PASS      12.34s
security                 ✅ PASS      15.67s
failure                  ✅ PASS      8.90s
performance              ❌ FAIL      7.32s
auth                     ✅ PASS      1.00s

================================================================================
```

## 🤝 Contributing

When adding new tests:

1. Follow existing naming conventions
2. Include both success and failure scenarios
3. Add appropriate mocking for external dependencies
4. Include performance assertions where relevant
5. Document any new test categories or patterns

### Test Naming Convention
```python
class TestServerName:
    def test_functionality_success(self):
        """Test successful functionality."""
        pass
    
    def test_functionality_failure(self):
        """Test failure scenario."""
        pass
    
    @pytest.mark.asyncio
    async def test_async_functionality(self):
        """Test async functionality."""
        pass
```

## 📚 Documentation Links

- [MCP Protocol Specification](../src/mcp/protocols.py)
- [Security Guidelines](../../SECURITY.md)
- [Performance Benchmarks](../../docs/performance/)
- [Deployment Guide](../../docs/deployment/)

---

This comprehensive test suite ensures the reliability, security, and performance of all MCP servers in the CODE project, providing confidence for production deployments and ongoing development.