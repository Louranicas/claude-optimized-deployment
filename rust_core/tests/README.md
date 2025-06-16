# MCP Manager Test Suite

This directory contains comprehensive tests for the MCP Manager following best practices from "Zero to Production in Rust". The test suite ensures thread safety, error handling correctness, performance characteristics, and PyO3 binding integrity.

## Test Organization

### Unit Tests
Located in `src/mcp_manager/tests/`:
- `unit_tests.rs` - Individual component tests
- `property_tests.rs` - Property-based testing with proptest
- `security_tests.rs` - Security-focused tests
- `stress_tests.rs` - Load and stress testing

### Integration Tests
Located in `tests/`:
- `mcp_manager_comprehensive_tests.rs` - Full system integration tests
- `mcp_property_tests.rs` - Property-based integration tests
- `integration_test_suite.rs` - End-to-end test scenarios

### Benchmarks
Located in `benches/`:
- `mcp_manager_bench.rs` - Performance benchmarks with Criterion
- `circle_of_experts_bench.rs` - Existing benchmark for Circle of Experts

## Running Tests

### All Tests
```bash
# Run all tests with cargo
cargo test --all-features

# Run tests with specific number of threads
cargo test --all-features -- --test-threads=4

# Run tests with output
cargo test --all-features -- --nocapture

# Run tests in release mode (faster)
cargo test --release --all-features
```

### Specific Test Categories

#### Unit Tests Only
```bash
cargo test --lib
```

#### Integration Tests Only
```bash
cargo test --test '*'
```

#### Property Tests
```bash
# Run with more test cases
PROPTEST_CASES=1000 cargo test property

# Run with specific seed for reproducibility
PROPTEST_RNG_SEED=42 cargo test property
```

#### Thread Safety Tests
```bash
cargo test thread_safety -- --test-threads=1
```

#### Error Handling Tests
```bash
cargo test error_handling
```

#### Performance Tests
```bash
cargo test performance -- --release
```

#### PyO3 Binding Tests
```bash
cargo test pyo3_binding
```

### Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench mcp_manager

# Run benchmarks and save baseline
cargo bench -- --save-baseline my_baseline

# Compare against baseline
cargo bench -- --baseline my_baseline

# Generate HTML report
cargo bench -- --output-format=bencher | tee bench_results.txt
```

## Test Coverage

### Measuring Coverage

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Run with coverage
cargo tarpaulin --all-features --timeout 300 --out Html

# Generate lcov report
cargo tarpaulin --all-features --timeout 300 --out Lcov

# With specific test filter
cargo tarpaulin --all-features --timeout 300 --test-threads 4 --run-types Tests
```

### Coverage Goals
- Unit tests: >90% coverage
- Integration tests: >80% coverage
- Critical paths: 100% coverage

## Test Patterns

### 1. Thread Safety Testing
Tests verify concurrent operations don't cause:
- Data races
- Deadlocks
- Inconsistent state
- Memory corruption

Example:
```rust
#[tokio::test]
async fn test_concurrent_operations() {
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    // ... concurrent operations with barrier synchronization
}
```

### 2. Error Handling Testing
Tests verify all error paths:
- Proper error types returned
- Error messages are helpful
- No panics in error conditions
- Graceful degradation

Example:
```rust
match result {
    Err(McpError::ServerNotFound(id)) => {
        assert_eq!(id, expected_id);
    }
    _ => panic!("Expected specific error"),
}
```

### 3. Performance Testing
Tests verify:
- Operations complete within time bounds
- Memory usage stays reasonable
- Throughput meets requirements
- No performance regressions

Example:
```rust
let start = Instant::now();
// ... operation
assert!(start.elapsed() < Duration::from_millis(100));
```

### 4. PyO3 Binding Testing
Tests verify:
- Correct type conversions
- GIL handling
- Memory safety across FFI
- Async integration

Example:
```rust
Python::with_gil(|py| {
    pyo3_asyncio::tokio::run(py, async move {
        // ... test async Python integration
    })
});
```

## Test Utilities

### Fixtures
Located in test modules under `fixtures`:
- `test_config()` - Standard test configuration
- `test_manager()` - Pre-configured manager
- `test_servers()` - Sample server instances

### Mocks
Located in test modules under `mocks`:
- `MockServer` - Simulates server behaviors
- `MockConnection` - Simulates network conditions
- `MockMetrics` - Controlled metrics generation

### Helpers
- `get_process_memory()` - Memory usage tracking
- `wait_for_condition()` - Async condition waiting
- `assert_eventually()` - Eventually consistent assertions

## Continuous Integration

### GitHub Actions
```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - uses: actions-rs/toolchain@v1
    - name: Run tests
      run: |
        cargo test --all-features
        cargo bench --no-run
```

### Pre-commit Hooks
```bash
#!/bin/bash
# .git/hooks/pre-commit
cargo test --lib --release
cargo clippy -- -D warnings
```

## Debugging Failed Tests

### Verbose Output
```bash
RUST_LOG=debug cargo test failing_test -- --nocapture
```

### Single Test
```bash
cargo test test_name -- --exact
```

### With Backtrace
```bash
RUST_BACKTRACE=1 cargo test
```

### With Sanitizers
```bash
RUSTFLAGS="-Z sanitizer=address" cargo test --target x86_64-unknown-linux-gnu
```

## Performance Profiling

### CPU Profiling
```bash
cargo install flamegraph
cargo flamegraph --test integration_test_suite
```

### Memory Profiling
```bash
cargo install cargo-instruments
cargo instruments --test memory_test -t Allocations
```

### Heap Profiling
```bash
DHAT_HEAP=1 cargo test --release
```

## Test Maintenance

### Adding New Tests
1. Identify the test category (unit/integration/property)
2. Use appropriate test patterns
3. Add documentation
4. Ensure thread safety
5. Verify error handling
6. Check performance impact

### Updating Existing Tests
1. Run tests before changes
2. Update test logic
3. Verify coverage maintained
4. Update documentation
5. Run benchmarks to check performance

### Test Review Checklist
- [ ] Tests are deterministic
- [ ] Tests are independent
- [ ] Tests cover edge cases
- [ ] Tests verify error conditions
- [ ] Tests check performance bounds
- [ ] Tests are documented
- [ ] Tests follow naming conventions

## Known Issues

### Flaky Tests
- `test_distributed_consensus` - Timing sensitive, increase delays if failing
- `test_memory_safety_under_load` - May fail on memory-constrained systems

### Platform-Specific
- Windows: Some network tests may fail due to different socket behavior
- macOS: File descriptor limits may affect stress tests

## Resources

- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Proptest Documentation](https://proptest-rs.github.io/proptest/)
- [Criterion.rs Guide](https://bheisler.github.io/criterion.rs/book/)
- [Zero to Production in Rust](https://www.zero2prod.com/)