# MCP Manager Python Bindings Documentation

## Overview

The MCP Manager Python bindings provide a high-performance interface to the Rust-based MCP (Model Context Protocol) Manager. These bindings leverage PyO3 to expose Rust functionality to Python with minimal overhead.

## Installation

### Prerequisites

- Python 3.8+
- Rust 1.70+
- `maturin` (install with `pip install maturin`)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/claude-optimized-deployment.git
cd claude-optimized-deployment

# Build the bindings
./scripts/build_rust_bindings.sh

# Or manually with maturin
maturin develop --manifest-path rust_core/Cargo.toml --release
```

## Quick Start

```python
from claude_optimized_deployment_rust import mcp_manager
import json

# Create a manager instance
manager = mcp_manager.PyMcpManager()

# Start the manager
manager.start()

# Deploy a server
config = {
    "name": "docker-server",
    "server_type": "infrastructure",
    "url": "http://localhost:8001",
    "auth": {"type": "api_key", "key": "secret"},
    "priority": 10,
    "tags": ["docker", "production"]
}
manager.deploy_server("docker-1", json.dumps(config))

# Execute a request
request = {"method": "list_containers"}
response = manager.execute("docker-1", json.dumps(request))
print(f"Response: {response}")

# Get health status
health = manager.get_health_status()
print(f"Healthy servers: {health.healthy_servers}/{health.total_servers}")

# Stop the manager
manager.stop()
```

## API Reference

### PyMcpManager

The main class for interacting with the MCP Manager.

#### Constructor

```python
PyMcpManager(config_path: Optional[str] = None) -> PyMcpManager
```

Creates a new MCP Manager instance.

- `config_path`: Optional path to a configuration file. If not provided, uses default configuration.

#### Methods

##### start()
```python
start() -> None
```
Starts the MCP Manager. Must be called before deploying servers.

##### stop()
```python
stop() -> None
```
Stops the MCP Manager gracefully, cleaning up all resources.

##### deploy_server()
```python
deploy_server(server_id: str, config_json: str) -> None
```
Deploys a new MCP server.

- `server_id`: Unique identifier for the server
- `config_json`: JSON string containing server configuration

Server configuration schema:
```json
{
    "name": "string",
    "server_type": "string",
    "url": "string",
    "auth": {
        "type": "none|api_key|bearer",
        "key": "string (for api_key)",
        "token": "string (for bearer)"
    },
    "priority": 0-255,
    "tags": ["string"]
}
```

##### undeploy_server()
```python
undeploy_server(server_id: str) -> None
```
Removes a deployed server.

##### execute()
```python
execute(server_id: str, request_json: str) -> str
```
Executes a request on a specific server.

- `server_id`: ID of the server to execute on
- `request_json`: JSON string containing the request
- Returns: JSON string containing the response

##### get_server_state()
```python
get_server_state(server_id: str) -> str
```
Gets the current state of a server.

##### get_health_status()
```python
get_health_status() -> PyHealthStatus
```
Gets the overall health status of all managed servers.

##### list_servers()
```python
list_servers() -> List[PyServerInfo]
```
Lists all deployed servers.

##### scale_server()
```python
scale_server(server_id: str, instances: int) -> None
```
Scales a server to the specified number of instances.

##### export_prometheus_metrics()
```python
export_prometheus_metrics() -> str
```
Exports metrics in Prometheus format.

### Async Methods

The following methods support Python's asyncio:

##### start_async()
```python
async start_async() -> None
```
Asynchronous version of `start()`.

##### execute_async()
```python
async execute_async(server_id: str, request_json: str) -> str
```
Asynchronous version of `execute()`.

##### deploy_server_async()
```python
async deploy_server_async(server_id: str, config_json: str) -> None
```
Asynchronous version of `deploy_server()`.

### Data Classes

#### PyHealthStatus
```python
class PyHealthStatus:
    total_servers: int
    healthy_servers: int
    degraded_servers: int
    unhealthy_servers: int
    avg_response_time_ms: int
```

#### PyServerInfo
```python
class PyServerInfo:
    id: str
    name: str
    server_type: str
    state: str
    priority: int
```

### Constants

The module provides the following constants:

- `SERVER_STATE_HEALTHY`: "Healthy"
- `SERVER_STATE_DEGRADED`: "Degraded"
- `SERVER_STATE_UNHEALTHY`: "Unhealthy"
- `CIRCUIT_STATE_CLOSED`: "Closed"
- `CIRCUIT_STATE_OPEN`: "Open"
- `CIRCUIT_STATE_HALF_OPEN`: "HalfOpen"

## Advanced Usage

### Asynchronous Operations

```python
import asyncio
from claude_optimized_deployment_rust import mcp_manager

async def main():
    manager = mcp_manager.PyMcpManager()
    
    # Start asynchronously
    await manager.start_async()
    
    # Deploy multiple servers concurrently
    tasks = []
    for i in range(5):
        config = {
            "name": f"server-{i}",
            "server_type": "test",
            "url": f"http://localhost:{8000+i}",
            "auth": {"type": "none"},
            "priority": 5,
            "tags": ["test"]
        }
        task = manager.deploy_server_async(f"server-{i}", json.dumps(config))
        tasks.append(task)
    
    await asyncio.gather(*tasks)
    
    # Execute requests concurrently
    request_tasks = []
    for i in range(5):
        request = {"method": "ping"}
        task = manager.execute_async(f"server-{i}", json.dumps(request))
        request_tasks.append(task)
    
    responses = await asyncio.gather(*request_tasks)
    for i, response in enumerate(responses):
        print(f"Server {i} response: {response}")
    
    await manager.stop()

asyncio.run(main())
```

### Error Handling

```python
from claude_optimized_deployment_rust import mcp_manager

manager = mcp_manager.PyMcpManager()

try:
    manager.start()
    
    # Deploy server with invalid config
    try:
        manager.deploy_server("bad-server", "{invalid json}")
    except ValueError as e:
        print(f"Config error: {e}")
    
    # Execute on non-existent server
    try:
        response = manager.execute("non-existent", '{"method": "test"}')
    except ValueError as e:
        print(f"Server not found: {e}")
    
finally:
    manager.stop()
```

### Monitoring and Metrics

```python
import time
from claude_optimized_deployment_rust import mcp_manager

manager = mcp_manager.PyMcpManager()
manager.start()

# Deploy some servers
# ... deployment code ...

# Monitor health over time
for _ in range(10):
    health = manager.get_health_status()
    healthy_pct = (health.healthy_servers / health.total_servers) * 100
    print(f"Health: {healthy_pct:.1f}% ({health.healthy_servers}/{health.total_servers})")
    print(f"Avg response time: {health.avg_response_time_ms}ms")
    
    # Export metrics
    metrics = manager.export_prometheus_metrics()
    # Write to file or push to monitoring system
    with open("metrics.prom", "w") as f:
        f.write(metrics)
    
    time.sleep(10)

manager.stop()
```

## Performance Considerations

1. **Zero-Copy Operations**: The bindings use zero-copy techniques where possible to minimize data transfer overhead between Python and Rust.

2. **Async Support**: Use async methods when dealing with multiple servers or high-throughput scenarios for better performance.

3. **Connection Pooling**: The underlying Rust implementation uses connection pooling for efficient resource usage.

4. **Circuit Breakers**: Built-in circuit breakers prevent cascading failures and improve resilience.

## Troubleshooting

### Import Error

If you get an import error:
```
ImportError: No module named 'claude_optimized_deployment_rust'
```

Solution:
1. Ensure you've built the bindings: `maturin develop --manifest-path rust_core/Cargo.toml`
2. Check that you're in the correct Python environment
3. Verify the build succeeded without errors

### Runtime Errors

Common runtime errors and solutions:

1. **"Failed to start manager"**: Check that no other instance is running on the same ports
2. **"Server not found"**: Ensure the server ID exists (use `list_servers()` to check)
3. **"Invalid config"**: Validate your JSON configuration against the schema

### Performance Issues

If experiencing performance issues:

1. Use async methods for concurrent operations
2. Monitor metrics to identify bottlenecks
3. Check circuit breaker states for failing servers
4. Scale servers appropriately based on load

## Examples

See the `examples/` directory for complete examples:

- `mcp_manager_python_example.py`: Comprehensive sync and async examples
- `mcp_deployment_automation.py`: Automated deployment scenarios

## Contributing

When contributing to the Python bindings:

1. Update both Rust and Python code as needed
2. Add tests for new functionality
3. Update this documentation
4. Run `cargo clippy` and `cargo test` before submitting

## License

MIT License - see LICENSE file for details.