# MCP Manager Test Suite

Comprehensive test suite for the Rust MCP Manager implementation, following best practices from "Zero to Production in Rust" and other Rust testing resources.

## Test Structure

```
tests/
├── mod.rs                    # Test module declarations
├── test_utils.rs            # Shared test utilities and helpers
│
├── unit_tests.rs            # Core unit tests
├── distributed_tests.rs     # Distributed systems tests
├── resilience_tests.rs      # Fault tolerance and resilience tests
├── optimization_tests.rs    # Performance optimization tests
├── security_tests.rs        # Security feature tests
│
├── integration_tests.rs     # Integration tests
├── stress_tests.rs         # Stress and load tests
└── property_tests.rs       # Property-based tests
```

## Running Tests

### Quick Start

```bash
# Run all tests
cargo test

# Run specific test module
cargo test mcp_manager::tests::distributed_tests

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run tests in release mode (for stress tests)
cargo test --release
```

### Using the Test Runner Script

```bash
# Run all tests with comprehensive reporting
./scripts/run_mcp_tests.sh all

# Run specific test categories
./scripts/run_mcp_tests.sh unit
./scripts/run_mcp_tests.sh integration
./scripts/run_mcp_tests.sh stress
./scripts/run_mcp_tests.sh property

# Run benchmarks
./scripts/run_mcp_tests.sh bench

# Generate coverage report
./scripts/run_mcp_tests.sh coverage

# CI pipeline (all tests + security + coverage)
./scripts/run_mcp_tests.sh ci
```

## Test Categories

### Unit Tests

Fast, isolated tests for individual components:

- **Core Components**: Config, errors, server, protocol
- **Registry**: Server registration and lookup
- **Metrics**: Performance metrics collection
- **Load Balancer**: Various load balancing strategies
- **Health Checks**: Server health monitoring

### Module-Specific Tests

#### Distributed Tests
- Consensus algorithms (Raft, PBFT)
- Leader election
- Sharding and consistent hashing
- Failover mechanisms
- Distributed load balancing

#### Resilience Tests
- Circuit breakers
- Bulkhead isolation
- Retry policies with backoff
- Chaos engineering
- Fallback strategies

#### Optimization Tests
- Adaptive caching
- Request prefetching
- Request batching
- Optimized load balancing

#### Security Tests
- Authentication (tokens, mTLS, API keys)
- Authorization (RBAC, ABAC)
- Encryption (at-rest, field-level)
- Threat detection
- Audit logging

### Integration Tests

End-to-end tests with multiple components:

- Server registration and discovery
- Request routing with load balancing
- Connection pooling
- Health check integration
- Circuit breaker integration
- Retry mechanisms
- Timeout handling
- Concurrent operations
- Graceful shutdown

### Stress Tests

High-load scenarios to test limits:

- High concurrency (100-10,000 concurrent requests)
- Sustained load
- Connection churn
- Memory pressure
- Cascade failures
- Extreme concurrency bursts

### Property-Based Tests

Using `proptest` for generative testing:

- Configuration validation
- Server registration idempotency
- Load balancer distribution
- Concurrent operation consistency
- Metrics accuracy
- Connection pool limits

## Benchmarks

Performance benchmarks using `criterion`:

### Standard Benchmarks (`mcp_manager_bench.rs`)
- Server registration
- Request routing
- Concurrent requests
- Load balancing strategies
- Connection pool operations
- Metrics collection
- Server registry operations
- Request serialization
- End-to-end scenarios

### Enhanced Benchmarks (`mcp_manager_enhanced_bench.rs`)
- Consensus operations
- Sharding operations
- Circuit breaker performance
- Retry mechanisms
- Adaptive caching
- Request batching
- Security operations
- Real-world scenarios (microservices, HFT)
- Python integration overhead

## Performance Comparison

Compare Rust vs Python implementations:

```bash
cd rust_core/tests
python performance_comparison_test.py
```

This generates:
- Performance metrics comparison
- Throughput measurements
- Memory usage analysis
- Visual plots (if matplotlib available)
- JSON results file

## Test Utilities

The `test_utils.rs` module provides:

- `create_test_config()` - Test configuration
- `create_mock_server()` - Mock MCP servers
- `MockMCPConnection` - Simulated connections with configurable behavior
- `TestMetricsCollector` - Metrics collection for assertions
- `generate_load()` - Load generation for stress tests
- `ChaosInjector` - Fault injection for resilience testing

## Coverage

Generate test coverage reports:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate HTML coverage report
cargo tarpaulin --out Html --output-dir target/coverage
```

## Security Audits

Run security checks:

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

## Best Practices

1. **Test Organization**
   - Unit tests in the same file as the code
   - Integration tests in separate files
   - Use descriptive test names

2. **Async Testing**
   - Use `#[tokio::test]` for async tests
   - Consider test timeouts for long-running tests

3. **Test Data**
   - Use builders for complex test data
   - Keep test data minimal but representative

4. **Assertions**
   - Use specific assertions (`assert_eq!` vs `assert!`)
   - Include helpful error messages

5. **Performance**
   - Run stress tests in release mode
   - Use benchmarks for performance-critical code
   - Profile tests that seem slow

## Continuous Integration

The test suite is designed for CI/CD:

```yaml
# Example GitHub Actions workflow
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - uses: actions-rs/toolchain@v1
    - run: ./rust_core/scripts/run_mcp_tests.sh ci
```

## Troubleshooting

### Out of Memory
- Reduce `TEST_THREADS` for memory-intensive tests
- Run stress tests separately

### Flaky Tests
- Check for timing dependencies
- Use proper synchronization
- Increase timeouts if needed

### Slow Tests
- Run in release mode
- Use `cargo test --lib` to skip doc tests
- Profile with `cargo test -- --test-threads=1`