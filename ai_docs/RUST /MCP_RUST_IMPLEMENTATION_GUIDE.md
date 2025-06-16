# MCP Rust Module Implementation Guide

## Quick Start Implementation

This guide provides concrete implementation patterns for building a high-performance MCP (Model Context Protocol) module in Rust, based on best practices from key Rust literature.

## 1. Project Structure and Dependencies

### Cargo.toml
```toml
[package]
name = "mcp-rust-core"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
futures = "0.3"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Python bindings
pyo3 = { version = "0.20", features = ["extension-module", "abi3-py38"] }
pyo3-asyncio = { version = "0.20", features = ["tokio-runtime"] }
pythonize = "0.20"

# Performance
crossbeam = "0.8"
dashmap = "5.5"
parking_lot = "0.12"
rayon = "1.8"

# Networking
hyper = { version = "1.0", features = ["full"] }
tokio-tungstenite = "0.21"
tower = "0.4"

# Observability
tracing = "0.1"
tracing-subscriber = "0.3"
prometheus = "0.13"

# Security
rustls = "0.22"
tokio-rustls = "0.25"
ring = "0.17"

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1.4"
wiremock = "0.5"

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
```

## 2. Core MCP Server Implementation

### src/lib.rs
```rust
pub mod client;
pub mod error;
pub mod protocol;
pub mod server;
pub mod tools;
pub mod transport;

#[cfg(feature = "python")]
pub mod python;

pub use error::{MCPError, MCPResult};
pub use protocol::{MCPMessage, MCPRequest, MCPResponse};
pub use server::MCPServer;
pub use client::MCPClient;

// Re-export commonly used types
pub mod prelude {
    pub use crate::{MCPError, MCPResult, MCPServer, MCPClient};
    pub use crate::tools::{Tool, ToolRegistry};
    pub use crate::protocol::{MCPMessage, MCPRequest, MCPResponse};
}
```

### src/server/mod.rs
```rust
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, error, instrument};
use dashmap::DashMap;

use crate::{MCPResult, MCPError};
use crate::tools::ToolRegistry;
use crate::transport::Transport;
use crate::protocol::{MCPRequest, MCPResponse};

pub struct MCPServer {
    config: ServerConfig,
    tool_registry: Arc<ToolRegistry>,
    connections: Arc<DashMap<String, Connection>>,
    semaphore: Arc<Semaphore>,
    shutdown_signal: tokio::sync::broadcast::Sender<()>,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub request_timeout: std::time::Duration,
    pub tls_config: Option<TlsConfig>,
}

impl MCPServer {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    #[instrument(skip(self))]
    pub async fn start(self: Arc<Self>) -> MCPResult<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        
        info!("MCP server listening on {}", addr);
        
        // Spawn metrics endpoint
        let metrics_server = self.clone();
        tokio::spawn(async move {
            metrics_server.serve_metrics().await;
        });
        
        // Main accept loop
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_connection(stream, addr).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => error!("Accept error: {}", e),
                    }
                }
                _ = self.shutdown_signal.subscribe().recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }
        
        self.shutdown().await
    }

    async fn handle_connection(
        &self,
        stream: tokio::net::TcpStream,
        addr: std::net::SocketAddr,
    ) -> MCPResult<()> {
        // Rate limiting
        let _permit = self.semaphore.acquire().await?;
        
        let transport = Transport::new(stream, self.config.tls_config.clone()).await?;
        let connection = Connection::new(addr, transport);
        let conn_id = connection.id.clone();
        
        self.connections.insert(conn_id.clone(), connection);
        
        // Handle requests
        let result = self.serve_connection(&conn_id).await;
        
        // Cleanup
        self.connections.remove(&conn_id);
        
        result
    }

    async fn serve_connection(&self, conn_id: &str) -> MCPResult<()> {
        let connection = self.connections.get(conn_id)
            .ok_or_else(|| MCPError::ConnectionNotFound)?;
        
        loop {
            match connection.transport.receive_message().await {
                Ok(request) => {
                    let response = self.handle_request(request).await;
                    connection.transport.send_message(response).await?;
                }
                Err(MCPError::ConnectionClosed) => break,
                Err(e) => return Err(e),
            }
        }
        
        Ok(())
    }

    #[instrument(skip(self, request), fields(method = %request.method))]
    async fn handle_request(&self, request: MCPRequest) -> MCPResponse {
        match request.method.as_str() {
            "tools/list" => self.handle_list_tools().await,
            "tools/call" => self.handle_tool_call(request).await,
            "ping" => MCPResponse::success(serde_json::json!({"pong": true})),
            _ => MCPResponse::error("Method not found"),
        }
    }

    async fn handle_list_tools(&self) -> MCPResponse {
        let tools = self.tool_registry.list_tools();
        MCPResponse::success(serde_json::json!({ "tools": tools }))
    }

    async fn handle_tool_call(&self, request: MCPRequest) -> MCPResponse {
        let tool_name = match request.params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => return MCPResponse::error("Tool name required"),
        };
        
        let tool_params = request.params.get("arguments").cloned().unwrap_or_default();
        
        match self.tool_registry.execute(tool_name, tool_params).await {
            Ok(result) => MCPResponse::success(result),
            Err(e) => MCPResponse::error(&e.to_string()),
        }
    }
}
```

## 3. High-Performance Tool Registry

### src/tools/registry.rs
```rust
use std::sync::Arc;
use dashmap::DashMap;
use async_trait::async_trait;
use serde_json::Value;
use tracing::instrument;

use crate::{MCPResult, MCPError};

#[async_trait]
pub trait Tool: Send + Sync {
    async fn execute(&self, params: Value) -> MCPResult<Value>;
    fn schema(&self) -> &ToolSchema;
    fn name(&self) -> &str;
}

pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

pub struct ToolRegistry {
    tools: DashMap<String, Arc<dyn Tool>>,
    execution_stats: DashMap<String, ToolStats>,
}

#[derive(Default)]
struct ToolStats {
    total_calls: AtomicU64,
    total_duration_ms: AtomicU64,
    error_count: AtomicU64,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: DashMap::new(),
            execution_stats: DashMap::new(),
        }
    }

    pub fn register(&self, tool: Arc<dyn Tool>) {
        let name = tool.name().to_string();
        self.tools.insert(name.clone(), tool);
        self.execution_stats.insert(name, ToolStats::default());
    }

    #[instrument(skip(self, params))]
    pub async fn execute(&self, name: &str, params: Value) -> MCPResult<Value> {
        let tool = self.tools.get(name)
            .ok_or_else(|| MCPError::ToolNotFound(name.to_string()))?;
        
        let start = std::time::Instant::now();
        let result = tool.execute(params).await;
        let duration = start.elapsed();
        
        // Update stats
        if let Some(stats) = self.execution_stats.get(name) {
            stats.total_calls.fetch_add(1, Ordering::Relaxed);
            stats.total_duration_ms.fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
            
            if result.is_err() {
                stats.error_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        result
    }

    pub fn list_tools(&self) -> Vec<ToolInfo> {
        self.tools.iter()
            .map(|entry| {
                let tool = entry.value();
                let schema = tool.schema();
                ToolInfo {
                    name: schema.name.clone(),
                    description: schema.description.clone(),
                    inputSchema: schema.parameters.clone(),
                }
            })
            .collect()
    }
}
```

## 4. PyO3 Python Bindings

### src/python/mod.rs
```rust
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Arc;
use std::collections::HashMap;

use crate::{MCPServer, MCPClient, ToolRegistry};

#[pyclass]
pub struct PyMCPServer {
    server: Arc<MCPServer>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyMCPServer {
    #[new]
    #[pyo3(signature = (host="127.0.0.1", port=8080, **kwargs))]
    fn new(host: &str, port: u16, kwargs: Option<&PyDict>) -> PyResult<Self> {
        let config = parse_server_config(host, port, kwargs)?;
        
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        let server = runtime.block_on(async {
            MCPServer::builder()
                .config(config)
                .build()
                .await
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        Ok(Self {
            server: Arc::new(server),
            runtime: Arc::new(runtime),
        })
    }

    fn start<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let server = self.server.clone();
        
        future_into_py(py, async move {
            server.start().await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    fn register_tool(&self, tool: &PyAny) -> PyResult<()> {
        let py_tool = PyToolWrapper::new(tool)?;
        self.server.tool_registry.register(Arc::new(py_tool));
        Ok(())
    }

    fn get_metrics<'p>(&self, py: Python<'p>) -> PyResult<&'p PyDict> {
        let metrics = self.runtime.block_on(async {
            self.server.collect_metrics().await
        });
        
        let dict = PyDict::new(py);
        for (key, value) in metrics {
            dict.set_item(key, value)?;
        }
        
        Ok(dict)
    }
}

#[pyclass]
pub struct PyMCPClient {
    client: Arc<MCPClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyMCPClient {
    #[new]
    fn new(url: &str) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        let client = runtime.block_on(async {
            MCPClient::connect(url).await
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        Ok(Self {
            client: Arc::new(client),
            runtime: Arc::new(runtime),
        })
    }

    fn call_tool<'p>(&self, py: Python<'p>, name: &str, args: &PyDict) -> PyResult<&'p PyAny> {
        let client = self.client.clone();
        let name = name.to_string();
        let args = pythonize::depythonize(args)?;
        
        future_into_py(py, async move {
            let result = client.call_tool(&name, args).await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            
            Python::with_gil(|py| pythonize::pythonize(py, &result))
        })
    }

    fn list_tools<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let client = self.client.clone();
        
        future_into_py(py, async move {
            let tools = client.list_tools().await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            
            Python::with_gil(|py| {
                let list = PyList::empty(py);
                for tool in tools {
                    let dict = PyDict::new(py);
                    dict.set_item("name", tool.name)?;
                    dict.set_item("description", tool.description)?;
                    dict.set_item("inputSchema", pythonize::pythonize(py, &tool.input_schema)?)?;
                    list.append(dict)?;
                }
                Ok(list.into())
            })
        })
    }
}

// Python tool wrapper for Rust
struct PyToolWrapper {
    tool: PyObject,
}

#[async_trait]
impl Tool for PyToolWrapper {
    async fn execute(&self, params: Value) -> MCPResult<Value> {
        Python::with_gil(|py| {
            let args = pythonize::pythonize(py, &params)?;
            let result = self.tool.call_method1(py, "execute", (args,))?;
            pythonize::depythonize(result.as_ref(py))
                .map_err(|e| MCPError::ToolError { 
                    tool: self.name().to_string(), 
                    source: Box::new(e) 
                })
        })
    }

    fn schema(&self) -> &ToolSchema {
        // Implementation details...
    }

    fn name(&self) -> &str {
        // Implementation details...
    }
}

#[pymodule]
fn mcp_rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMCPServer>()?;
    m.add_class::<PyMCPClient>()?;
    
    // Add version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    
    Ok(())
}
```

## 5. Performance Optimization Utilities

### src/performance/mod.rs
```rust
use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use std::sync::Arc;

// Object pool for frequent allocations
pub struct ObjectPool<T> {
    pool: Arc<ArrayQueue<T>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T> ObjectPool<T> {
    pub fn new<F>(capacity: usize, factory: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let pool = Arc::new(ArrayQueue::new(capacity));
        
        // Pre-populate pool
        for _ in 0..capacity {
            let _ = pool.push(factory());
        }
        
        Self {
            pool,
            factory: Box::new(factory),
        }
    }

    pub fn acquire(&self) -> PooledObject<T> {
        let obj = self.pool.pop().unwrap_or_else(|| (self.factory)());
        
        PooledObject {
            inner: Some(obj),
            pool: self.pool.clone(),
        }
    }
}

pub struct PooledObject<T> {
    inner: Option<T>,
    pool: Arc<ArrayQueue<T>>,
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(obj) = self.inner.take() {
            let _ = self.pool.push(obj);
        }
    }
}

impl<T> std::ops::Deref for PooledObject<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<T> std::ops::DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

// Zero-allocation metrics collection
pub struct Metrics {
    counters: DashMap<&'static str, AtomicU64>,
    gauges: DashMap<&'static str, AtomicI64>,
    histograms: DashMap<&'static str, Histogram>,
}

impl Metrics {
    pub fn increment(&self, name: &'static str) {
        self.counters
            .entry(name)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_duration(&self, name: &'static str, duration: Duration) {
        self.histograms
            .entry(name)
            .or_insert_with(Histogram::new)
            .record(duration.as_micros() as u64);
    }

    pub fn set_gauge(&self, name: &'static str, value: i64) {
        self.gauges
            .entry(name)
            .or_insert_with(|| AtomicI64::new(0))
            .store(value, Ordering::Relaxed);
    }
}
```

## 6. Testing Patterns

### tests/integration_test.rs
```rust
use mcp_rust_core::prelude::*;
use wiremock::{MockServer, Mock, ResponseTemplate};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_server_lifecycle() {
    // Setup
    let server = MCPServer::builder()
        .host("127.0.0.1")
        .port(0) // Random port
        .build()
        .await
        .unwrap();
    
    let addr = server.local_addr();
    let server_handle = tokio::spawn(async move {
        server.start().await
    });
    
    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Test client connection
    let client = MCPClient::connect(&format!("ws://{}", addr))
        .await
        .unwrap();
    
    // Test tool listing
    let tools = client.list_tools().await.unwrap();
    assert!(!tools.is_empty());
    
    // Shutdown
    server_handle.abort();
}

#[tokio::test]
async fn test_concurrent_requests() {
    let server = create_test_server().await;
    let client = MCPClient::connect(&server.url()).await.unwrap();
    
    // Spawn multiple concurrent requests
    let mut handles = vec![];
    
    for i in 0..100 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            client.call_tool("echo", json!({ "message": format!("test-{}", i) }))
                .await
        });
        handles.push(handle);
    }
    
    // Wait for all requests
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // Verify all succeeded
    for result in results {
        assert!(result.unwrap().is_ok());
    }
}

// Property-based testing
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_message_serialization(msg in any::<String>()) {
        let request = MCPRequest {
            id: "test".to_string(),
            method: "echo".to_string(),
            params: json!({ "message": msg }),
        };
        
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: MCPRequest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(request.id, deserialized.id);
        assert_eq!(request.method, deserialized.method);
        assert_eq!(request.params, deserialized.params);
    }
}
```

## 7. Benchmarking

### benches/mcp_bench.rs
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mcp_rust_core::prelude::*;

fn benchmark_tool_execution(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let registry = ToolRegistry::new();
    
    // Register test tool
    registry.register(Arc::new(EchoTool));
    
    let mut group = c.benchmark_group("tool_execution");
    
    for size in [10, 100, 1000, 10000].iter() {
        let params = json!({ "data": vec![0u8; *size] });
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, _| {
                b.to_async(&runtime).iter(|| async {
                    registry.execute("echo", black_box(params.clone())).await
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_concurrent_connections(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("concurrent_connections", |b| {
        b.to_async(&runtime).iter(|| async {
            let server = create_test_server().await;
            
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    let url = server.url();
                    tokio::spawn(async move {
                        MCPClient::connect(&url).await
                    })
                })
                .collect();
            
            futures::future::join_all(handles).await
        });
    });
}

criterion_group!(benches, benchmark_tool_execution, benchmark_concurrent_connections);
criterion_main!(benches);
```

## 8. Production Deployment

### Dockerfile
```dockerfile
# Build stage
FROM rust:1.75 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build with optimizations
RUN cargo build --release --features production

# Python wheel build
FROM python:3.11-slim as wheel-builder

WORKDIR /app
COPY --from=builder /app/target/release/libmcp_rust_core.so ./
COPY pyproject.toml setup.py ./
COPY python ./python

RUN pip install maturin
RUN maturin build --release

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel and install
COPY --from=wheel-builder /app/target/wheels/*.whl ./
RUN pip install *.whl && rm *.whl

# Non-root user
RUN useradd -m -u 1001 mcp
USER mcp

EXPOSE 8080

CMD ["python", "-m", "mcp_rust_core.server"]
```

## Key Implementation Patterns

1. **Zero-Copy Operations**: Use `Arc` and `Bytes` for shared data
2. **Lock-Free Structures**: Prefer `DashMap` and atomic operations
3. **Async-First Design**: All I/O operations are async
4. **Error Propagation**: Use `thiserror` for typed errors
5. **Observability**: Built-in metrics and tracing
6. **Python Integration**: Seamless PyO3 bindings
7. **Testing**: Comprehensive unit, integration, and property tests
8. **Performance**: Object pools and careful memory management

This implementation provides a solid foundation for a production-ready MCP Rust module with excellent performance characteristics and maintainability.