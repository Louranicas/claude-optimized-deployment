# Memory Optimization Testing Suite

This directory contains comprehensive memory optimization testing and validation tools for the Claude-Optimized Deployment Engine.

## Overview

The memory testing suite provides four main categories of testing:

1. **Memory Leak Detection** - Identifies and analyzes memory leaks
2. **Performance Regression Testing** - Tracks memory performance over time
3. **Memory Stress Testing** - Tests system behavior under memory pressure
4. **Garbage Collection Performance** - Validates GC efficiency and behavior

## Test Files

### Core Test Modules

- **`test_memory_leaks.py`** - Advanced memory leak detection with statistical analysis
- **`test_memory_performance_regression.py`** - Performance regression tracking and baseline comparison
- **`test_memory_stress.py`** - Memory stress testing under various scenarios
- **`test_gc_performance.py`** - Garbage collection performance validation

### Supporting Files

- **`__init__.py`** - Package initialization
- **`conftest.py`** - Shared test fixtures and configuration
- **`README.md`** - This documentation file

## Running Tests

### Individual Test Suites

```bash
# Memory leak detection
python tests/memory/test_memory_leaks.py

# Performance regression testing
python tests/memory/test_memory_performance_regression.py

# Memory stress testing
python tests/memory/test_memory_stress.py

# GC performance testing
python tests/memory/test_gc_performance.py
```

### Using pytest

```bash
# Run all memory tests
pytest tests/memory/ -v

# Run specific test categories
pytest tests/memory/ -m memory -v
pytest tests/memory/ -m memory_regression -v
pytest tests/memory/ -m memory_stress -v
pytest tests/memory/ -m memory_gc -v

# Run comprehensive tests (longer duration)
pytest tests/memory/ -m memory_comprehensive -v
```

### Complete Validation Suite

```bash
# Quick validation (5-10 minutes)
python scripts/memory_validation_suite.py --level quick

# Comprehensive validation (15-30 minutes)
python scripts/memory_validation_suite.py --level comprehensive

# Nightly validation (30-60 minutes)
python scripts/memory_validation_suite.py --level nightly
```

## Test Categories and Markers

### Test Markers

- `@pytest.mark.memory` - Basic memory tests
- `@pytest.mark.memory_regression` - Performance regression tests
- `@pytest.mark.memory_stress` - Memory stress tests
- `@pytest.mark.memory_gc` - GC performance tests
- `@pytest.mark.memory_comprehensive` - Comprehensive test suites
- `@pytest.mark.memory_long` - Long-running tests (>10 minutes)

### Test Levels

1. **Quick Tests** (5-10 minutes)
   - Basic leak detection
   - Performance regression checks
   - Essential GC validation

2. **Comprehensive Tests** (15-30 minutes)
   - Full leak detection suite
   - Complete regression analysis
   - Memory stress scenarios
   - Detailed GC performance analysis

3. **Extended Tests** (30-60 minutes)
   - Long-running leak detection
   - Historical performance comparison
   - Advanced stress testing
   - Comprehensive GC optimization

## Memory Leak Detection

### Features

- **Statistical Analysis**: Uses linear regression and confidence intervals
- **Component Isolation**: Tests individual components separately
- **Trend Detection**: Identifies memory growth patterns
- **Severity Classification**: Critical, major, minor, or no leaks
- **Detailed Reporting**: Comprehensive analysis with recommendations

### Key Metrics

- Memory growth per iteration
- Total memory increase
- Statistical confidence level
- Garbage collection frequency
- Object lifecycle analysis

### Example Usage

```python
from tests.memory.test_memory_leaks import MemoryLeakDetector

detector = MemoryLeakDetector()
result = await detector.detect_leaks_in_component(
    component_factory=lambda: ExpertManager(),
    operation_func=my_operation,
    iterations=100
)

print(f"Leak detected: {result.leak_detected}")
print(f"Severity: {result.leak_severity}")
print(f"Memory growth: {result.memory_growth_mb:.2f}MB")
```

## Performance Regression Testing

### Features

- **Baseline Comparison**: Compares current performance with established baselines
- **Automatic Baseline Updates**: Updates baselines when improvements are validated
- **Environment Consistency**: Accounts for environment differences
- **Confidence Scoring**: Statistical confidence in regression detection
- **Historical Tracking**: Maintains performance history over time

### Key Metrics

- Memory usage changes
- Execution time variations
- Throughput improvements/regressions
- Garbage collection impact
- Rust vs Python performance

### Example Usage

```python
from tests.memory.test_memory_performance_regression import MemoryPerformanceRegression

tester = MemoryPerformanceRegression()
metrics = await tester.benchmark_memory_performance(
    component_name="ExpertManager",
    test_name="query_processing",
    test_function=my_benchmark_function
)

result = tester.compare_with_baseline(metrics, baseline_metrics)
print(f"Regression detected: {result.regression_detected}")
```

## Memory Stress Testing

### Features

- **Multiple Stress Scenarios**: Memory pressure, concurrency, fragmentation
- **Breaking Point Detection**: Identifies system limits
- **Recovery Analysis**: Tests memory recovery patterns
- **Stability Scoring**: Quantifies system stability under stress
- **Resource Monitoring**: Continuous memory and CPU monitoring

### Stress Scenarios

1. **Memory Pressure** - Gradually increases memory usage
2. **Concurrent Operations** - High-concurrency memory operations
3. **Memory Fragmentation** - Allocation/deallocation patterns
4. **Recovery Testing** - Memory cleanup and recovery

### Example Usage

```python
from tests.memory.test_memory_stress import MemoryStressTester

tester = MemoryStressTester()
result = await tester.test_memory_pressure_scenarios()

print(f"Breaking point reached: {result.breaking_point_reached}")
print(f"Stability score: {result.stability_score:.2f}")
```

## GC Performance Testing

### Features

- **GC Frequency Analysis**: Monitors garbage collection frequency
- **Pause Time Measurement**: Measures GC pause times
- **Efficiency Scoring**: Calculates GC efficiency metrics
- **Generation Analysis**: Tracks object promotions between generations
- **Threshold Validation**: Validates against performance thresholds

### Key Metrics

- GC collections per operation
- Average and maximum pause times
- GC efficiency score
- Object lifecycle statistics
- Memory reclamation effectiveness

### Example Usage

```python
from tests.memory.test_gc_performance import GCPerformanceValidator

validator = GCPerformanceValidator()
metrics = await validator.test_gc_frequency(
    operation_func=my_operation,
    iterations=1000,
    component_name="ExpertManager"
)

is_efficient = validator.validate_gc_efficiency(metrics)
print(f"GC efficiency: {metrics.gc_efficiency_score:.2f}")
```

## Configuration

### Validation Configuration

The memory validation suite uses configuration from `config/memory_validation.yaml`:

```yaml
validation_levels:
  quick:
    leak_detection:
      iterations: 50
      components: ["ExpertManager", "RustModules"]
    regression_testing:
      enabled: true
    stress_testing:
      enabled: false
    gc_performance:
      iterations: 100
```

### Thresholds

Performance and quality thresholds are configurable:

```yaml
thresholds:
  memory_leak:
    critical_mb: 50.0
    major_mb: 20.0
    minor_mb: 5.0
  performance_regression:
    critical_percent: 50.0
    major_percent: 30.0
    minor_percent: 15.0
```

## Output and Reporting

### Report Types

1. **JSON Reports** - Machine-readable detailed results
2. **HTML Reports** - Human-readable formatted reports
3. **Markdown Summaries** - Concise status summaries
4. **Console Output** - Real-time progress and results

### Report Locations

- `tests/memory/` - Individual test reports
- `reports/memory_validation/` - Comprehensive validation reports
- `benchmarks/` - Baseline metrics and historical data

### Example Report Structure

```
reports/memory_validation/
├── memory_validation_quick_20250606_120000.html
├── memory_validation_quick_20250606_120000.json
├── memory_validation_summary_20250606_120000.md
├── leak_detection_report_20250606_120000.md
├── performance_regression_report_20250606_120000.md
└── memory_stress_report_20250606_120000.md
```

## CI/CD Integration

### GitHub Actions

The memory validation suite integrates with GitHub Actions:

```yaml
# .github/workflows/memory-validation.yml
- name: Run Memory Validation
  run: |
    python scripts/memory_validation_suite.py --level quick
```

### Validation Levels by Context

- **Pull Requests**: Quick validation (5-10 minutes)
- **Main Branch**: Comprehensive validation (15-30 minutes)
- **Nightly Builds**: Extended validation (30-60 minutes)

### Failure Handling

- **Critical Leaks**: Fail the build
- **Performance Regressions**: Fail on critical regressions
- **Warnings**: Pass but notify
- **Improvements**: Update baselines automatically

## Dependencies

### Required Packages

```txt
memory-profiler>=0.60.0
psutil>=5.9.0
pytest-benchmark>=4.0.0
objgraph>=3.5.0
pympler>=0.9
```

### Optional Advanced Tools

```txt
py-spy>=0.3.14
memray>=1.0.0
heaptrack-parser>=0.1.0
```

## Best Practices

### Memory Optimization

1. **Object Pooling** - Reuse objects instead of frequent allocation
2. **Lazy Initialization** - Create objects only when needed
3. **Weak References** - Use for caches and observers
4. **Batch Processing** - Process data in batches
5. **Memory Profiling** - Regular profiling to identify hotspots

### Testing Guidelines

1. **Isolation** - Test components in isolation
2. **Reproducibility** - Ensure tests are reproducible
3. **Statistical Rigor** - Use proper statistical analysis
4. **Baseline Management** - Maintain accurate baselines
5. **Continuous Monitoring** - Regular validation in CI/CD

### Performance Targets

- **Memory Leaks**: < 1MB per 1000 operations
- **Peak Memory**: < 500MB under normal load
- **GC Pause Time**: < 100ms P95
- **Memory Recovery**: > 95% after stress events
- **Rust Efficiency**: 40-60% memory reduction vs Python

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check for object accumulation
   - Review caching strategies
   - Investigate circular references

2. **Long GC Pauses**
   - Reduce large object allocation
   - Implement object pooling
   - Tune GC settings

3. **Performance Regressions**
   - Review recent changes
   - Check algorithm complexity
   - Validate optimization implementations

4. **Test Failures**
   - Check environment consistency
   - Verify baseline accuracy
   - Review threshold settings

### Debug Mode

Enable debug mode for detailed analysis:

```bash
python scripts/memory_validation_suite.py --level quick --debug
```

### Memory Profiling

For detailed memory profiling:

```bash
# Line-by-line profiling
python -m memory_profiler tests/memory/test_memory_leaks.py

# Object tracking
python -c "
import objgraph
objgraph.show_most_common_types()
"
```

## Contributing

### Adding New Tests

1. Follow the existing test structure
2. Use appropriate pytest markers
3. Include comprehensive documentation
4. Add configuration options
5. Update this README

### Test Development Guidelines

1. **Statistical Rigor** - Use proper statistical methods
2. **Error Handling** - Handle failures gracefully
3. **Resource Cleanup** - Ensure proper cleanup
4. **Performance** - Optimize test execution time
5. **Documentation** - Document test purpose and usage

### Code Review Checklist

- [ ] Tests are properly isolated
- [ ] Statistical analysis is correct
- [ ] Error handling is comprehensive
- [ ] Resource cleanup is implemented
- [ ] Documentation is complete
- [ ] Configuration is added
- [ ] CI/CD integration is tested

## Support

For questions or issues with memory testing:

1. Check this documentation
2. Review existing test reports
3. Examine configuration settings
4. Run validation in debug mode
5. Create an issue with detailed information

## Future Enhancements

### Planned Features

1. **Machine Learning** - Anomaly detection for memory patterns
2. **Real-time Monitoring** - Production memory monitoring
3. **Advanced Profiling** - Integration with specialized profiling tools
4. **Cross-platform Testing** - Windows and macOS validation
5. **Performance Prediction** - Predictive performance modeling

### Research Areas

1. **Memory Pattern Analysis** - Advanced pattern recognition
2. **Optimization Automation** - Automated optimization suggestions
3. **Adaptive Thresholds** - Dynamic threshold adjustment
4. **Comparative Analysis** - Cross-language performance comparison
5. **Production Integration** - Real-time production validation