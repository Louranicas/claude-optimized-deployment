# Rust Core API Reference

## Table of Contents

1. [Infrastructure Module](#infrastructure-module)
2. [Performance Module](#performance-module)
3. [Security Module](#security-module)
4. [Circle of Experts](#circle-of-experts)
5. [MCP Manager](#mcp-manager)
6. [Memory-Mapped I/O](#memory-mapped-io)
7. [SIMD Operations](#simd-operations)
8. [Zero-Copy Networking](#zero-copy-networking)
9. [Lock-Free Collections](#lock-free-collections)
10. [Error Types](#error-types)

## Infrastructure Module

### `InfrastructureScanner`

High-performance infrastructure scanning with parallel execution.

```rust
pub struct InfrastructureScanner {
    // Private fields
}

impl InfrastructureScanner {
    /// Create a new scanner with default configuration
    pub fn new() -> Self
    
    /// Create a scanner with custom configuration
    pub fn with_config(config: ScannerConfig) -> Self
    
    /// Scan ports on the specified host
    /// Returns a vector of open ports
    pub async fn scan_ports(
        &self, 
        host: &str, 
        ports: Range<u16>
    ) -> Result<Vec<u16>, InfrastructureError>
    
    /// Discover services on the network
    pub async fn discover_services(
        &self,
        subnet: &str
    ) -> Result<Vec<ServiceInfo>, InfrastructureError>
    
    /// Get system information
    pub fn get_system_info(&self) -> SystemInfo
}
```

### `ConfigParser`

Zero-copy configuration parsing.

```rust
pub struct ConfigParser {
    // Private fields
}

impl ConfigParser {
    /// Parse YAML configuration
    pub fn parse_yaml(content: &str) -> Result<Config, ParseError>
    
    /// Parse TOML configuration
    pub fn parse_toml(content: &str) -> Result<Config, ParseError>
    
    /// Parse JSON configuration
    pub fn parse_json(content: &str) -> Result<Config, ParseError>
    
    /// Validate configuration against schema
    pub fn validate(&self, config: &Config) -> Result<(), ValidationError>
}
```

## Performance Module

### `MetricsCollector`

Real-time performance metrics collection.

```rust
pub struct MetricsCollector {
    // Private fields
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self
    
    /// Record a timing metric
    pub fn record_timing(&self, name: &str, duration: Duration)
    
    /// Record a counter metric
    pub fn increment_counter(&self, name: &str, value: u64)
    
    /// Record a gauge metric
    pub fn record_gauge(&self, name: &str, value: f64)
    
    /// Get current metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot
    
    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String
}
```

### `Profiler`

Performance profiling utilities.

```rust
pub struct Profiler {
    // Private fields
}

impl Profiler {
    /// Start CPU profiling
    pub fn start_cpu_profile(&mut self) -> Result<(), ProfileError>
    
    /// Stop CPU profiling and save results
    pub fn stop_cpu_profile(&mut self, path: &Path) -> Result<(), ProfileError>
    
    /// Capture heap profile
    pub fn heap_profile(&self) -> HeapProfile
    
    /// Analyze performance bottlenecks
    pub fn analyze_bottlenecks(&self) -> Vec<Bottleneck>
}
```

## Security Module

### `SecurityScanner`

Comprehensive security scanning capabilities.

```rust
pub struct SecurityScanner {
    // Private fields
}

impl SecurityScanner {
    /// Create a new security scanner
    pub fn new() -> Self
    
    /// Scan for vulnerabilities
    pub async fn scan_vulnerabilities(
        &self,
        target: &str
    ) -> Result<Vec<Vulnerability>, SecurityError>
    
    /// Check SSL/TLS configuration
    pub async fn check_tls(
        &self,
        host: &str,
        port: u16
    ) -> Result<TlsReport, SecurityError>
    
    /// Validate access controls
    pub fn validate_access_controls(
        &self,
        config: &SecurityConfig
    ) -> Result<ValidationReport, SecurityError>
}
```

## Circle of Experts

### `ExpertCircle`

Distributed expert consultation system.

```rust
pub struct ExpertCircle {
    // Private fields
}

impl ExpertCircle {
    /// Create a new expert circle
    pub fn new(config: CircleConfig) -> Self
    
    /// Register an expert
    pub fn register_expert(
        &mut self,
        expert: Box<dyn Expert>
    ) -> Result<ExpertId, CircleError>
    
    /// Submit a query to the circle
    pub async fn query(
        &self,
        question: &str,
        options: QueryOptions
    ) -> Result<ConsensusResponse, CircleError>
    
    /// Get expert performance metrics
    pub fn get_expert_metrics(&self, id: ExpertId) -> Option<ExpertMetrics>
}
```

### `Expert` Trait

```rust
pub trait Expert: Send + Sync {
    /// Expert's unique identifier
    fn id(&self) -> &str;
    
    /// Expert's area of expertise
    fn expertise(&self) -> Vec<String>;
    
    /// Process a query
    async fn process_query(
        &self,
        query: &str
    ) -> Result<ExpertResponse, ExpertError>;
    
    /// Get confidence level for a query
    fn confidence_level(&self, query: &str) -> f32;
}
```

## MCP Manager

### `MCPManager`

Comprehensive MCP server management.

```rust
pub struct MCPManager {
    // Private fields
}

impl MCPManager {
    /// Create a new MCP manager
    pub async fn new(config: MCPConfig) -> Result<Self, MCPError>
    
    /// Deploy a new MCP server
    pub async fn deploy_server(
        &self,
        spec: ServerSpec
    ) -> Result<ServerId, MCPError>
    
    /// Get server status
    pub async fn get_server_status(
        &self,
        id: ServerId
    ) -> Result<ServerStatus, MCPError>
    
    /// Execute a tool on a server
    pub async fn execute_tool(
        &self,
        server_id: ServerId,
        tool_name: &str,
        params: serde_json::Value
    ) -> Result<serde_json::Value, MCPError>
    
    /// List all servers
    pub async fn list_servers(&self) -> Vec<ServerInfo>
    
    /// Get server metrics
    pub async fn get_metrics(
        &self,
        server_id: Option<ServerId>
    ) -> Result<ServerMetrics, MCPError>
}
```

### `Plugin` Trait

```rust
pub trait Plugin: Send + Sync {
    /// Plugin metadata
    fn metadata(&self) -> PluginMetadata;
    
    /// Initialize the plugin
    async fn initialize(&mut self) -> Result<(), PluginError>;
    
    /// Handle a request
    async fn handle_request(
        &self,
        request: PluginRequest
    ) -> Result<PluginResponse, PluginError>;
    
    /// Cleanup resources
    async fn cleanup(&mut self) -> Result<(), PluginError>;
}
```

## Memory-Mapped I/O

### `MemoryMappedFile`

Efficient file operations with zero-copy reads.

```rust
pub struct MemoryMappedFile {
    // Private fields
}

impl MemoryMappedFile {
    /// Open a file for memory mapping
    pub fn open(path: &Path) -> Result<Self, IoError>
    
    /// Create a new memory-mapped file
    pub fn create(
        path: &Path,
        size: usize
    ) -> Result<Self, IoError>
    
    /// Get a read-only view of the data
    pub fn as_slice(&self) -> &[u8]
    
    /// Get a mutable view (if opened with write permissions)
    pub fn as_mut_slice(&mut self) -> Option<&mut [u8]>
    
    /// Flush changes to disk
    pub fn flush(&self) -> Result<(), IoError>
}
```

## SIMD Operations

### `SimdProcessor`

SIMD-accelerated data processing.

```rust
pub struct SimdProcessor {
    // Private fields
}

impl SimdProcessor {
    /// Process data in parallel using SIMD
    pub fn process_f32_array(
        &self,
        data: &[f32],
        operation: SimdOp
    ) -> Vec<f32>
    
    /// Find pattern in data using SIMD
    pub fn find_pattern(
        &self,
        haystack: &[u8],
        needle: &[u8]
    ) -> Option<usize>
    
    /// Calculate statistics using SIMD
    pub fn calculate_stats(
        &self,
        data: &[f64]
    ) -> Statistics
}
```

## Zero-Copy Networking

### `ZeroCopySocket`

High-performance network operations.

```rust
pub struct ZeroCopySocket {
    // Private fields
}

impl ZeroCopySocket {
    /// Create a new zero-copy socket
    pub fn new(addr: SocketAddr) -> Result<Self, NetError>
    
    /// Send data without copying
    pub async fn send_zero_copy(
        &self,
        data: &[u8]
    ) -> Result<usize, NetError>
    
    /// Receive data into pre-allocated buffer
    pub async fn recv_into(
        &self,
        buffer: &mut [u8]
    ) -> Result<usize, NetError>
    
    /// Use scatter-gather I/O
    pub async fn sendmsg(
        &self,
        buffers: &[IoSlice<'_>]
    ) -> Result<usize, NetError>
}
```

## Lock-Free Collections

### `LockFreeQueue<T>`

Thread-safe queue without locks.

```rust
pub struct LockFreeQueue<T> {
    // Private fields
}

impl<T: Send> LockFreeQueue<T> {
    /// Create a new lock-free queue
    pub fn new() -> Self
    
    /// Push an item onto the queue
    pub fn push(&self, item: T)
    
    /// Try to pop an item from the queue
    pub fn try_pop(&self) -> Option<T>
    
    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool
    
    /// Get approximate length
    pub fn len(&self) -> usize
}
```

### `ConcurrentHashMap<K, V>`

Thread-safe hash map with fine-grained locking.

```rust
pub struct ConcurrentHashMap<K, V> {
    // Private fields
}

impl<K: Hash + Eq, V> ConcurrentHashMap<K, V> {
    /// Create a new concurrent hash map
    pub fn new() -> Self
    
    /// Insert a key-value pair
    pub fn insert(&self, key: K, value: V) -> Option<V>
    
    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<V>
    
    /// Remove a key-value pair
    pub fn remove(&self, key: &K) -> Option<V>
    
    /// Apply a function to a value
    pub fn update<F>(&self, key: K, f: F) -> Option<V>
    where
        F: FnOnce(Option<V>) -> Option<V>
}
```

## Error Types

### Core Errors

```rust
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Infrastructure error: {0}")]
    Infrastructure(String),
    
    #[error("Performance error: {0}")]
    Performance(String),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("Circle of Experts error: {0}")]
    CircleOfExperts(String),
    
    #[error("MCP error: {0}")]
    MCP(#[from] MCPError),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
}
```

### MCP Errors

```rust
#[derive(Debug, Error)]
pub enum MCPError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Server not found: {0}")]
    ServerNotFound(ServerId),
    
    #[error("Tool execution failed: {0}")]
    ToolExecutionFailed(String),
    
    #[error("Plugin error: {0}")]
    PluginError(#[from] PluginError),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}
```

## Python Bindings

All Rust types are exposed to Python through PyO3 bindings. Example usage:

```python
from claude_optimized_deployment_rust import (
    InfrastructureScanner,
    MCPManager,
    ExpertCircle,
    MetricsCollector
)

# Infrastructure scanning
scanner = InfrastructureScanner()
open_ports = await scanner.scan_ports("localhost", range(1, 1024))

# MCP management
manager = MCPManager({"max_concurrent": 100})
server_id = await manager.deploy_server({
    "name": "docker",
    "type": "docker",
    "port": 8001
})

# Expert consultation
circle = ExpertCircle({"consensus_threshold": 0.7})
response = await circle.query(
    "What's the best deployment strategy?",
    {"timeout": 30, "min_experts": 3}
)

# Metrics collection
metrics = MetricsCollector()
metrics.record_timing("api_call", 0.025)
snapshot = metrics.snapshot()
```