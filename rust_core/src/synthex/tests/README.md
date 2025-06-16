# SYNTHEX Test Suite

Comprehensive test suite for the SYNTHEX (Synthetic Experience Search Engine) module.

## Test Coverage

### 1. Agent Tests (`agent_tests.rs`)
- **Initialization**: Tests for all agent types (API, Database, File, Web, Knowledge Base)
- **Query Execution**: Validates agent query handling and result generation
- **Error Handling**: Tests agent failure scenarios and error propagation
- **Timeout Handling**: Ensures agents respect timeout constraints
- **Coordination**: Tests multiple agents working together
- **Resource Limits**: Validates memory and resource constraints

### 2. Engine Tests (`engine_tests.rs`)
- **Initialization**: Engine creation and configuration
- **Agent Registration**: Dynamic agent management
- **Search Execution**: Core search functionality
- **Parallel Search**: Concurrent agent execution
- **Caching**: Result caching and performance optimization
- **Error Aggregation**: Handling partial failures
- **Resource Management**: Concurrent request batching
- **Shutdown**: Graceful shutdown procedures
- **Metrics**: Performance tracking and reporting

### 3. Query Tests (`query_tests.rs`)
- **Query Building**: Fluent API for query construction
- **Query Parsing**: Complex query syntax parsing
- **Operators**: AND, OR, NOT boolean operators
- **Field Search**: Structured field queries
- **Wildcards**: Pattern matching with * and ?
- **Validation**: Query input validation
- **Optimization**: Query simplification and optimization
- **Expansion**: Synonym and stemming expansion
- **Scoring**: Relevance scoring algorithms

### 4. Performance Tests (`performance_tests.rs`)
- **Throughput**: Single and multi-agent QPS benchmarks
- **Scaling**: Parallel scaling efficiency (up to 16 agents)
- **Cache Performance**: Cache hit rate and speedup metrics
- **Memory Efficiency**: Memory usage under load
- **Latency Percentiles**: P50, P90, P99 latency tracking
- **Concurrent Load**: Simulates 100+ concurrent users
- **Resource Usage**: CPU and memory monitoring
- **Stress Testing**: Behavior under extreme load

### 5. Integration Tests (`integration_tests.rs`)
- **Full Pipeline**: End-to-end search workflow
- **Multi-Agent Coordination**: Complex query routing
- **Result Aggregation**: Deduplication and ranking
- **Parallel Execution**: Task parallelization
- **Error Recovery**: Resilience to partial failures
- **Configuration Updates**: Hot configuration reloading
- **Graceful Shutdown**: Clean resource cleanup
- **Distributed Search**: Multi-node coordination
- **Circuit Breaker**: Automatic failure detection and recovery

### 6. BashGod Tests (`bashgod_tests.rs`)
- **Pattern Detection**: Command sequence recognition
- **Command Prediction**: ML-based next command prediction
- **Optimization Strategies**: Speed, Memory, Accuracy modes
- **ML Optimization**: Neural network training and prediction
- **Adaptive Learning**: Dynamic pattern adaptation
- **Resource Prediction**: CPU/memory usage forecasting
- **Anomaly Detection**: Performance anomaly identification
- **Auto-Tuning**: Configuration optimization
- **Workload Classification**: Automatic workload type detection

### 7. Knowledge Graph Tests (`knowledge_graph_tests.rs`)
- **Graph Creation**: Node and edge management
- **Traversal**: BFS and DFS algorithms
- **Queries**: Path finding and connectivity
- **Semantic Search**: Embedding-based similarity
- **Clustering**: Community detection algorithms
- **Analytics**: Centrality and PageRank
- **Updates**: Dynamic graph modifications
- **Persistence**: Save/load functionality
- **Merging**: Graph combination operations
- **Reasoning**: Inference rule application

### 8. MCP v2 Tests (`mcp_v2_tests.rs`)
- **Manager Initialization**: MCP v2 setup
- **Server Registration**: Dynamic server management
- **Tool Discovery**: Automatic tool detection
- **Resource Management**: Resource registration and querying
- **Tool Execution**: Remote tool invocation
- **Health Monitoring**: Server health checks
- **Capability Matching**: Server capability queries
- **Query Routing**: Intelligent request routing
- **Load Balancing**: Request distribution
- **Error Handling**: Failure scenarios
- **Performance Metrics**: Operation tracking

## Running the Tests

### Run all tests:
```bash
cargo test --manifest-path rust_core/Cargo.toml synthex
```

### Run specific test module:
```bash
cargo test --manifest-path rust_core/Cargo.toml synthex::tests::agent_tests
```

### Run with verbose output:
```bash
cargo test --manifest-path rust_core/Cargo.toml synthex -- --nocapture
```

### Run performance benchmarks:
```bash
cargo test --manifest-path rust_core/Cargo.toml synthex::tests::performance_tests -- --ignored
```

## Test Utilities

The `test_utils.rs` module provides:
- `test_config()`: Default test configuration
- `test_engine()`: Pre-configured engine instance
- `MockTestAgent`: Configurable mock agent for testing
- `PerfMeasure`: Performance measurement helper
- `assert_completes_within()`: Timeout assertion helper
- `generate_test_dataset()`: Large dataset generation

## Performance Expectations

Based on the test suite, SYNTHEX should achieve:
- **Single Agent QPS**: > 50 queries/second
- **Scaling Efficiency**: > 70% at 8 agents
- **Cache Speedup**: > 10x for repeated queries
- **P50 Latency**: < 20ms
- **P90 Latency**: < 50ms
- **P99 Latency**: < 150ms
- **Concurrent Users**: > 100 with > 100 QPS

## Coverage Goals

- Unit test coverage: > 80%
- Integration test coverage: > 70%
- Performance regression detection
- Error scenario coverage: > 90%

## Continuous Testing

Tests are designed to run in CI/CD pipelines with:
- Parallel test execution
- Flaky test detection
- Performance regression alerts
- Memory leak detection
- Coverage reporting