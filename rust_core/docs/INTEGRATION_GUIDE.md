# Rust Core Integration Guide

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Python Integration](#python-integration)
4. [MCP Server Integration](#mcp-server-integration)
5. [Performance Tuning](#performance-tuning)
6. [Error Handling](#error-handling)
7. [Testing](#testing)
8. [Deployment](#deployment)
9. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Python 3.8 or higher
- Rust 1.70 or higher
- Linux kernel 4.9+ (for io_uring support)
- At least 2GB RAM
- x86_64 or ARM64 architecture

### From PyPI

```bash
pip install claude-optimized-deployment-rust
```

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/claude-optimized-deployment.git
cd claude-optimized-deployment

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and install the Rust module
cd rust_core
pip install maturin
maturin develop --release

# Or build a wheel
maturin build --release
pip install target/wheels/*.whl
```

## Basic Usage

### Quick Start

```python
import asyncio
from claude_optimized_deployment_rust import (
    InfrastructureScanner,
    MCPManager,
    MetricsCollector
)

async def main():
    # Initialize components
    scanner = InfrastructureScanner()
    mcp_manager = MCPManager({"max_concurrent": 100})
    metrics = MetricsCollector()
    
    # Scan infrastructure
    open_ports = await scanner.scan_ports("localhost", range(8000, 9000))
    print(f"Open ports: {open_ports}")
    
    # Deploy MCP server
    server_id = await mcp_manager.deploy_server({
        "name": "docker",
        "type": "docker",
        "port": 8001
    })
    
    # Check server health
    status = await mcp_manager.get_server_status(server_id)
    print(f"Server status: {status}")
    
    # Record metrics
    metrics.record_timing("deployment", 1.5)
    print(metrics.export_prometheus())

asyncio.run(main())
```

### Configuration

Create a configuration file `rust_core_config.toml`:

```toml
[infrastructure]
scanner_threads = 16
timeout_ms = 5000
batch_size = 100

[mcp]
max_concurrent_connections = 100
connection_timeout_ms = 30000
retry_attempts = 3
retry_delay_ms = 1000

[performance]
enable_simd = true
cache_size_mb = 512
prefetch_distance = 64

[security]
enable_tls_validation = true
min_tls_version = "1.2"
allowed_ciphers = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
```

Load configuration in Python:

```python
from claude_optimized_deployment_rust import load_config

config = load_config("rust_core_config.toml")
scanner = InfrastructureScanner.with_config(config["infrastructure"])
mcp_manager = MCPManager(config["mcp"])
```

## Python Integration

### Async/Await Support

All I/O operations support Python's async/await:

```python
import asyncio
from claude_optimized_deployment_rust import MCPManager

async def deploy_multiple_servers():
    manager = MCPManager({"max_concurrent": 100})
    
    # Deploy servers concurrently
    tasks = []
    for server_type in ["docker", "kubernetes", "prometheus"]:
        task = manager.deploy_server({
            "name": server_type,
            "type": server_type,
            "port": 8000 + len(tasks)
        })
        tasks.append(task)
    
    server_ids = await asyncio.gather(*tasks)
    return server_ids
```

### Context Managers

Use context managers for automatic cleanup:

```python
from claude_optimized_deployment_rust import MCPManager

async def with_mcp_manager():
    async with MCPManager({"max_concurrent": 50}) as manager:
        # Manager is automatically initialized
        servers = await manager.list_servers()
        
        # Execute tools
        for server in servers:
            result = await manager.execute_tool(
                server.id,
                "health_check",
                {}
            )
            print(f"{server.name}: {result}")
    # Manager is automatically cleaned up
```

### Streaming Operations

Handle streaming data efficiently:

```python
from claude_optimized_deployment_rust import ZeroCopySocket

async def stream_logs():
    socket = ZeroCopySocket("127.0.0.1:9000")
    
    async for chunk in socket.stream():
        # Process log chunk without copying
        process_log_chunk(chunk)
```

## MCP Server Integration

### Creating Custom MCP Servers

Implement the Plugin trait in Rust:

```rust
use claude_optimized_deployment_rust::mcp_manager::{Plugin, PluginMetadata};

pub struct CustomPlugin {
    name: String,
}

#[async_trait]
impl Plugin for CustomPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name.clone(),
            version: "1.0.0".to_string(),
            capabilities: vec!["custom_tool".to_string()],
        }
    }
    
    async fn initialize(&mut self) -> Result<(), PluginError> {
        // Initialize plugin
        Ok(())
    }
    
    async fn handle_request(
        &self,
        request: PluginRequest
    ) -> Result<PluginResponse, PluginError> {
        // Handle requests
        Ok(PluginResponse::Success(json!({"status": "ok"})))
    }
}
```

Register in Python:

```python
from claude_optimized_deployment_rust import MCPManager

async def register_custom_plugin():
    manager = MCPManager({})
    
    # Load custom plugin
    await manager.load_plugin("path/to/custom_plugin.so")
    
    # Use the plugin
    result = await manager.execute_tool(
        "custom_plugin",
        "custom_tool",
        {"param": "value"}
    )
```

### Hot Reloading

Enable hot reloading for development:

```python
from claude_optimized_deployment_rust import MCPManager

async def setup_hot_reload():
    manager = MCPManager({
        "enable_hot_reload": True,
        "watch_paths": ["./plugins"]
    })
    
    # Plugins will automatically reload when changed
    manager.on_plugin_reload(lambda plugin: 
        print(f"Reloaded: {plugin.name}")
    )
```

## Performance Tuning

### Memory Pool Configuration

```python
from claude_optimized_deployment_rust import configure_memory_pools

# Configure memory pools for optimal performance
configure_memory_pools({
    "small_pool_size": 1024 * 1024,      # 1MB
    "medium_pool_size": 16 * 1024 * 1024, # 16MB
    "large_pool_size": 256 * 1024 * 1024, # 256MB
    "pool_count": 4
})
```

### Thread Pool Tuning

```python
from claude_optimized_deployment_rust import configure_thread_pools

# Configure thread pools
configure_thread_pools({
    "cpu_threads": 16,          # For CPU-bound work
    "io_threads": 64,           # For I/O-bound work
    "blocking_threads": 128,    # For blocking operations
    "stack_size": 2 * 1024 * 1024  # 2MB stack per thread
})
```

### SIMD Optimization

```python
from claude_optimized_deployment_rust import SimdProcessor

# Enable SIMD optimizations
processor = SimdProcessor()

# Process large arrays efficiently
data = np.random.rand(1_000_000).astype(np.float32)
result = processor.process_f32_array(
    data,
    "multiply",  # Operation
    2.0          # Factor
)
```

## Error Handling

### Exception Mapping

Rust errors are automatically mapped to Python exceptions:

```python
from claude_optimized_deployment_rust import MCPManager, MCPError

async def safe_deployment():
    manager = MCPManager({})
    
    try:
        server_id = await manager.deploy_server({
            "name": "test",
            "type": "invalid_type",  # This will fail
            "port": 8000
        })
    except MCPError as e:
        print(f"Deployment failed: {e}")
        
        # Check specific error type
        if e.is_connection_error():
            # Handle connection errors
            pass
        elif e.is_validation_error():
            # Handle validation errors
            pass
```

### Graceful Degradation

```python
from claude_optimized_deployment_rust import MCPManager, CircuitBreaker

async def resilient_operations():
    manager = MCPManager({
        "circuit_breaker": {
            "failure_threshold": 5,
            "reset_timeout": 60,
            "half_open_requests": 3
        }
    })
    
    # Operations will automatically fail fast if circuit opens
    for i in range(10):
        try:
            result = await manager.execute_tool(
                "flaky_server",
                "unreliable_operation",
                {}
            )
        except MCPError as e:
            if e.is_circuit_open():
                print("Circuit breaker open, using fallback")
                result = use_fallback_method()
```

## Testing

### Unit Testing

```python
import pytest
from claude_optimized_deployment_rust import InfrastructureScanner

@pytest.mark.asyncio
async def test_port_scanning():
    scanner = InfrastructureScanner()
    
    # Mock network responses
    with scanner.mock_mode():
        scanner.mock_port(8080, open=True)
        scanner.mock_port(8081, open=False)
        
        ports = await scanner.scan_ports("localhost", range(8080, 8082))
        assert ports == [8080]
```

### Integration Testing

```python
import pytest
from claude_optimized_deployment_rust import MCPManager

@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcp_integration():
    async with MCPManager.test_instance() as manager:
        # Test instance provides isolated environment
        server_id = await manager.deploy_server({
            "name": "test",
            "type": "docker",
            "port": 0  # Auto-assign port
        })
        
        # Verify deployment
        status = await manager.get_server_status(server_id)
        assert status["state"] == "running"
```

### Performance Testing

```python
import pytest
from claude_optimized_deployment_rust import benchmark

@pytest.mark.benchmark
def test_scanning_performance(benchmark):
    scanner = InfrastructureScanner()
    
    # Benchmark port scanning
    result = benchmark(
        scanner.scan_ports_sync,
        "localhost",
        range(1, 1024)
    )
    
    # Assert performance requirements
    assert benchmark.stats["mean"] < 0.1  # Less than 100ms
```

## Deployment

### Docker

```dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy and build
WORKDIR /app
COPY . .
RUN pip install maturin
RUN cd rust_core && maturin build --release
RUN pip install rust_core/target/wheels/*.whl

# Run application
CMD ["python", "-m", "your_app"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: claude-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: claude
  template:
    metadata:
      labels:
        app: claude
    spec:
      containers:
      - name: claude
        image: your-registry/claude:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "2"
          limits:
            memory: "4Gi"
            cpu: "4"
        env:
        - name: RUST_LOG
          value: "info"
        - name: RUST_BACKTRACE
          value: "1"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

### Environment Variables

```bash
# Rust logging
export RUST_LOG=claude_optimized_deployment_rust=debug

# Performance tuning
export RUST_THREADS=16
export RUST_SIMD=true

# Memory settings
export RUST_MIN_STACK=2097152  # 2MB

# Security
export RUST_TLS_VERIFY=true
export RUST_TLS_MIN_VERSION=1.2
```

## Troubleshooting

### Common Issues

#### 1. Import Error

```python
ImportError: cannot import name 'MCPManager' from 'claude_optimized_deployment_rust'
```

**Solution**: Ensure the Rust module is properly built and installed:
```bash
cd rust_core
maturin develop --release
```

#### 2. Async Runtime Error

```python
RuntimeError: no running event loop
```

**Solution**: Ensure you're running async code properly:
```python
import asyncio
asyncio.run(your_async_function())
```

#### 3. Memory Issues

```python
MemoryError: Unable to allocate buffer
```

**Solution**: Increase memory limits or reduce batch sizes:
```python
configure_memory_pools({
    "large_pool_size": 128 * 1024 * 1024  # Reduce from 256MB
})
```

### Debug Mode

Enable debug logging:

```python
import logging
from claude_optimized_deployment_rust import enable_debug_mode

# Enable Rust debug logs
enable_debug_mode()

# Python logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Profiling

```python
from claude_optimized_deployment_rust import Profiler

profiler = Profiler()
profiler.start_cpu_profile()

# Run your code
await expensive_operation()

profiler.stop_cpu_profile("profile.pb")
# Analyze with pprof or similar tools
```

### Memory Leak Detection

```python
from claude_optimized_deployment_rust import MemoryTracker

tracker = MemoryTracker()
tracker.start()

# Run operations
for i in range(1000):
    await some_operation()
    
    if i % 100 == 0:
        snapshot = tracker.snapshot()
        print(f"Memory usage: {snapshot.rss_mb}MB")

leaks = tracker.detect_leaks()
if leaks:
    print(f"Potential memory leaks detected: {leaks}")
```