# CODE Testing Infrastructure

## Overview

This directory contains the comprehensive testing infrastructure for the Claude-Optimized Deployment Engine (CODE) project. The testing framework is designed to leverage the full capabilities of the development hardware (16 threads, 32GB RAM, NVMe SSD) and ensure robust code quality, performance, and security.

## Quick Start

### Running All Tests

```bash
# Run comprehensive test suite
python run_comprehensive_tests.py --all

# Run specific test types
python run_comprehensive_tests.py --unit-tests --integration-tests

# Run with parallel execution (recommended)
python run_comprehensive_tests.py --all --parallel --max-workers 12
```

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Rust dependencies and build
cd rust_core && cargo build --features testing

# Install development tools
pip install pytest pytest-asyncio coverage bandit mypy black
```

## Testing Architecture

```
tests/
├── framework/                    # Core testing frameworks
│   ├── test_orchestrator.py     # Main test coordination
│   ├── ffi_integration_tester.py # Python-Rust FFI testing
│   ├── performance_testing.py   # Performance benchmarks
│   └── test_automation.py       # Automated test execution
├── unit/                        # Unit tests
│   ├── mcp/                     # MCP-specific unit tests
│   └── test_*.py               # Python unit tests
├── integration/                 # Integration tests
│   ├── test_mcp_*.py           # MCP integration tests
│   └── test_system_*.py        # System integration tests
├── e2e/                        # End-to-end tests
├── performance/                # Performance tests
├── security/                   # Security tests
├── fixtures/                   # Test data and fixtures
├── utils/                      # Testing utilities
└── results/                    # Test results and reports
```

## Test Categories

### 1. Unit Tests

**Location**: `tests/unit/`
**Purpose**: Test individual components in isolation
**Coverage Target**: 90% for critical components, 85% minimum

```bash
# Run Python unit tests
python -m pytest tests/unit/ -v

# Run Rust unit tests
cd rust_core && cargo test

# Run with coverage
python -m pytest tests/unit/ --cov=src --cov-report=html
```

### 2. Integration Tests

**Location**: `tests/integration/`
**Purpose**: Test component interactions and system integration

```bash
# Run integration tests
python -m pytest tests/integration/ -v

# Run MCP integration tests specifically
python -m pytest tests/integration/test_mcp_*.py -v
```

### 3. FFI Integration Tests

**Purpose**: Validate Python-Rust interoperability
**Framework**: Custom FFI testing framework

```bash
# Run FFI tests
python tests/framework/ffi_integration_tester.py

# Run specific FFI test categories
python -c "
import asyncio
from tests.framework.ffi_integration_tester import FFIIntegrationTester
tester = FFIIntegrationTester()
asyncio.run(tester.run_comprehensive_test_suite())
"
```

### 4. Performance Tests

**Purpose**: Benchmark system performance and detect regressions
**Hardware Optimization**: Utilizes all 16 threads and 32GB RAM

```bash
# Run performance benchmarks
python tests/framework/performance_testing.py

# Run Rust benchmarks
cd rust_core && cargo bench
```

### 5. Security Tests

**Purpose**: Identify vulnerabilities and security issues

```bash
# Run security scans
bandit -r src/ -f json -o security_report.json

# Run comprehensive security tests
python run_comprehensive_tests.py --security-tests
```

### 6. End-to-End Tests

**Location**: `tests/e2e/`
**Purpose**: Validate complete user workflows

```bash
# Run E2E tests
python -m pytest tests/e2e/ -v --tb=short
```

## Hardware Optimization

### CPU Utilization (16 Threads)

The testing framework is optimized for 16-thread systems:

- **12 threads**: Parallel test execution
- **2 threads**: System monitoring
- **2 threads**: Test coordination

```python
# Example configuration
TEST_CONFIG = {
    'max_workers': 12,
    'monitoring_threads': 2,
    'coordination_threads': 2
}
```

### Memory Management (32GB RAM)

Memory allocation strategy:

- **16GB**: Test process execution
- **8GB**: Test data and fixtures
- **8GB**: System buffer and overhead

### Storage Optimization (NVMe SSD)

- Fast test artifact storage
- Efficient temporary file handling
- Parallel I/O operations
- Optimized database operations

## Testing Frameworks

### Test Orchestrator

**File**: `tests/framework/test_orchestrator.py`
**Purpose**: Central coordination of all test types

Key features:
- Parallel test execution
- Resource monitoring
- Comprehensive reporting
- Timeout handling
- Error recovery

### FFI Integration Tester

**File**: `tests/framework/ffi_integration_tester.py`
**Purpose**: Python-Rust FFI validation

Test categories:
- Data type compatibility
- Memory safety
- Performance characteristics
- Error handling
- Thread safety

### Performance Testing

**File**: `tests/framework/performance_testing.py`
**Purpose**: Hardware-optimized performance benchmarking

Benchmark types:
- CPU-intensive tests
- Memory-intensive tests
- I/O-intensive tests
- Concurrent operations
- Mixed workloads

### Test Automation

**File**: `tests/framework/test_automation.py`
**Purpose**: Automated test execution and CI/CD integration

Features:
- Job scheduling
- Resource management
- Continuous testing
- Artifact management
- Pipeline integration

## Configuration

### Test Configuration Files

```yaml
# tests/config/test_config.yaml
test_execution:
  max_workers: 12
  timeout_seconds: 1800
  memory_limit_mb: 16384
  
performance_thresholds:
  avg_response_time_ms: 100
  p95_response_time_ms: 200
  throughput_ops_per_sec: 1000
  memory_usage_mb: 512

security_settings:
  vulnerability_threshold: "medium"
  dependency_check: true
  static_analysis: true
```

### Environment Variables

```bash
# Test execution
export TEST_ENV=development
export TEST_PARALLEL=true
export TEST_MAX_WORKERS=12

# Performance testing
export PERF_BENCHMARK_ITERATIONS=1000
export PERF_WARMUP_ITERATIONS=100

# Security testing
export SECURITY_SCAN_LEVEL=comprehensive
export BANDIT_CONFIG=.bandit
```

## Test Data Management

### Test Fixtures

**Location**: `tests/fixtures/`
**Purpose**: Standardized test data

```python
# Example fixture usage
@pytest.fixture
def sample_deployment_config():
    return {
        "name": "test-deployment",
        "replicas": 3,
        "image": "test:latest"
    }
```

### Data Generation

```python
# Dynamic test data generation
from tests.utils.test_data import TestDataFactory

def test_with_generated_data():
    users = TestDataFactory.create_users(count=100)
    # Use generated test data
```

### Cleanup

All tests automatically clean up resources:

```python
@pytest.fixture(autouse=True)
def cleanup_test_resources():
    yield
    # Automatic cleanup after each test
    TestResourceManager.cleanup_all()
```

## Monitoring and Reporting

### Real-time Monitoring

The testing framework provides real-time monitoring of:

- CPU usage
- Memory consumption
- Disk I/O
- Network I/O
- Test execution progress

### Test Reports

Comprehensive reports are generated for:

- Test execution results
- Performance metrics
- Security findings
- Coverage analysis
- Resource utilization

### Report Formats

- **JSON**: Machine-readable detailed reports
- **HTML**: Interactive web reports
- **Markdown**: Human-readable summaries
- **JUnit XML**: CI/CD integration

## Continuous Integration

### GitHub Actions Integration

```yaml
# .github/workflows/comprehensive-tests.yml
name: Comprehensive Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run comprehensive tests
      run: |
        python run_comprehensive_tests.py --all --ci-mode --parallel
    
    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results
        path: tests/results/
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: unit-tests
        name: Run unit tests
        entry: python -m pytest tests/unit/ --tb=short
        language: system
        pass_filenames: false
        
      - id: security-scan
        name: Security scan
        entry: bandit -r src/
        language: system
        pass_filenames: false
```

## Troubleshooting

### Common Issues

1. **Test Timeouts**
   ```bash
   # Increase timeout for long-running tests
   python run_comprehensive_tests.py --timeout-minutes 60
   ```

2. **Memory Issues**
   ```bash
   # Reduce parallel workers
   python run_comprehensive_tests.py --max-workers 4
   ```

3. **Rust Build Issues**
   ```bash
   cd rust_core
   cargo clean
   cargo build --features testing
   ```

### Debug Mode

```bash
# Enable verbose logging
python run_comprehensive_tests.py --verbose --all

# Run specific failing test
python -m pytest tests/unit/test_specific.py::test_function -v -s
```

### Resource Monitoring

```bash
# Monitor system resources during testing
htop
iotop
nethogs
```

## Contributing

### Adding New Tests

1. Follow the testing standards in `TESTING_STANDARDS.md`
2. Use appropriate test fixtures from `tests/fixtures/`
3. Ensure tests clean up resources
4. Add performance benchmarks for critical paths
5. Include security considerations

### Test Review Checklist

- [ ] Tests follow naming conventions
- [ ] Appropriate test isolation
- [ ] Resource cleanup implemented
- [ ] Performance implications considered
- [ ] Security aspects validated
- [ ] Documentation updated

## Performance Benchmarks

### Current Benchmarks

- **Unit Tests**: ~0.5ms average per test
- **Integration Tests**: ~2-5 seconds per test
- **FFI Tests**: ~10-50ms per operation
- **Performance Tests**: Variable based on benchmark
- **Security Tests**: ~1-2 minutes for full scan

### Hardware Utilization

- **CPU**: Typically 60-80% during parallel execution
- **Memory**: Peak usage around 8-12GB
- **Disk**: High throughput during I/O tests
- **Network**: Minimal usage (mostly local testing)

## Security Considerations

### Test Security

- No hardcoded credentials in tests
- Sensitive data properly mocked
- Test environments isolated
- Security scans integrated
- Vulnerability monitoring enabled

### Data Protection

- Synthetic test data only
- No production data in tests
- Automatic data cleanup
- Secure test environments
- Audit trails maintained

## Future Enhancements

### Planned Features

- [ ] Distributed testing across multiple machines
- [ ] GPU-accelerated testing
- [ ] Advanced performance profiling
- [ ] Machine learning-based test optimization
- [ ] Enhanced security testing
- [ ] Better test parallelization
- [ ] Improved reporting dashboards

### Integration Roadmap

- [ ] Jenkins pipeline integration
- [ ] SonarQube integration
- [ ] Kubernetes testing environments
- [ ] Cloud-based testing
- [ ] Advanced monitoring integration

## Support

For questions or issues with the testing infrastructure:

1. Check the troubleshooting section above
2. Review the testing standards document
3. Search existing issues
4. Create a detailed bug report with logs

## Resources

- **Testing Standards**: `TESTING_STANDARDS.md`
- **Performance Reports**: `tests/results/performance_*.json`
- **Security Reports**: `tests/results/security_*.json`
- **Coverage Reports**: `tests/results/coverage/`
- **Benchmark Results**: `tests/results/benchmarks/`