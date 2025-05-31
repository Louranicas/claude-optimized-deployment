# Performance Testing Suite

This directory contains comprehensive performance and load tests for the Claude-Optimized Deployment Engine.

## Test Categories

### 1. Rust vs Python Performance Comparison (`test_rust_acceleration.py`)
- Benchmarks Rust modules against pure Python implementations
- Tests response analysis, consensus calculation, and aggregation
- Measures performance gains from Rust acceleration
- Includes memory efficiency comparisons

### 2. Load Testing Scenarios (`test_load_scenarios.py`)
- **100 Concurrent AI Queries**: Tests Circle of Experts under load
- **1000 MCP Tool Calls**: Stress tests MCP infrastructure
- **Connection Pool Stress**: Tests connection handling limits
- **Mixed Workload**: Combined AI and MCP operations
- **Burst Traffic**: Simulates sudden load spikes
- **Sustained Load**: Tests long-running performance

### 3. Memory Usage Profiling (`test_memory_usage.py`)
- Tracks memory usage across components
- Detects memory leaks
- Profiles Rust module memory efficiency
- Line-by-line memory profiling with `memory_profiler`
- Concurrent operation memory analysis

### 4. MCP Performance Benchmarks (`mcp_performance_benchmarks.py`)
- Benchmarks all MCP server operations
- Tests concurrent MCP tool execution
- Measures I/O and CPU usage
- Identifies performance bottlenecks

## Running Tests

### Individual Test Suites

```bash
# Rust vs Python benchmarks
pytest tests/performance/test_rust_acceleration.py -v --benchmark-only

# Load testing (async)
python tests/performance/test_load_scenarios.py

# Memory profiling
python tests/performance/test_memory_usage.py

# MCP benchmarks
python tests/performance/mcp_performance_benchmarks.py
```

### Run All Tests

```bash
# Run comprehensive performance test suite
python tests/performance/run_all_performance_tests.py
```

## Performance Targets

### Response Time Benchmarks
- Single AI query: < 2s average
- Batch processing: > 20 queries/second
- MCP tool calls: < 100ms average

### Memory Usage
- Peak memory: < 500MB under normal load
- Memory leaks: < 1MB per 100 operations
- Rust modules: 40-60% memory reduction vs Python

### Concurrent Operations
- Support 100+ concurrent AI queries
- Handle 1000+ MCP tool calls
- Connection pool: 200+ concurrent connections

### Load Scenarios
- Sustained throughput: > 50 requests/second
- Error rate: < 5% under load
- P95 response time: < 2s

## Output Files

Each test run generates:
- Markdown reports with analysis
- JSON files with raw metrics
- Benchmark comparison data
- Memory snapshots and timelines

## Requirements

```bash
# Install performance testing dependencies
pip install pytest-benchmark memory-profiler psutil
```

## Interpreting Results

### Rust Performance Gains
- Look for 2-20x speedup in benchmark results
- Check memory reduction percentages
- Verify scaling efficiency with data size

### Load Test Metrics
- **Throughput**: Requests processed per second
- **Response Times**: P50, P95, P99 percentiles
- **Error Rate**: Percentage of failed requests
- **Resource Usage**: Memory and CPU utilization

### Memory Analysis
- **RSS (Resident Set Size)**: Actual memory used
- **Memory Delta**: Change during operations
- **GC Collections**: Garbage collection frequency
- **Leak Detection**: Consistent memory growth

## CI/CD Integration

```yaml
# Example GitHub Actions workflow
- name: Run Performance Tests
  run: |
    python tests/performance/run_all_performance_tests.py
    
- name: Upload Performance Report
  uses: actions/upload-artifact@v3
  with:
    name: performance-report
    path: tests/performance/performance_test_report_*.md
```

## Performance Optimization Tips

1. **Enable Rust Acceleration**: Ensure Rust modules are built
2. **Connection Pooling**: Configure appropriate pool sizes
3. **Async Operations**: Use async/await for I/O operations
4. **Batch Processing**: Group operations when possible
5. **Resource Limits**: Set memory and CPU limits for stability