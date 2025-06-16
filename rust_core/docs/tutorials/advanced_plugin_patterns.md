# Advanced Plugin Development Patterns

This guide covers advanced patterns and techniques for building sophisticated MCP Manager plugins.

## Table of Contents

1. [Plugin Composition](#plugin-composition)
2. [Middleware Pattern](#middleware-pattern)
3. [Event-Driven Architecture](#event-driven-architecture)
4. [Resource Pooling](#resource-pooling)
5. [Circuit Breaker Pattern](#circuit-breaker-pattern)
6. [Plugin Pipelines](#plugin-pipelines)
7. [Distributed Plugins](#distributed-plugins)
8. [Performance Optimization](#performance-optimization)

## Plugin Composition

### Composing Multiple Plugins

```rust
use async_trait::async_trait;
use claude_optimized_deployment_rust::mcp_manager::plugin::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Composite plugin that delegates to multiple sub-plugins
#[derive(Debug)]
pub struct CompositePlugin {
    metadata: PluginMetadata,
    plugins: HashMap<String, Arc<dyn Plugin>>,
    router: Arc<dyn RequestRouter>,
}

#[async_trait]
pub trait RequestRouter: Send + Sync + std::fmt::Debug {
    fn route(&self, request: &PluginRequest) -> Option<String>;
}

#[derive(Debug)]
struct CapabilityRouter {
    routes: HashMap<Capability, String>,
}

impl RequestRouter for CapabilityRouter {
    fn route(&self, request: &PluginRequest) -> Option<String> {
        self.routes.get(&request.capability).cloned()
    }
}

#[async_trait]
impl Plugin for CompositePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        // Initialize all sub-plugins
        for (name, plugin) in &self.plugins {
            let sub_config = config.get(name).unwrap_or(&serde_json::Value::Null);
            
            // Clone to get mutable reference
            let plugin_clone = plugin.clone();
            if let Some(mut_plugin) = Arc::get_mut(&mut plugin_clone) {
                mut_plugin.initialize(sub_config.clone()).await
                    .map_err(|e| PluginError::Initialization(
                        format!("Failed to initialize {}: {}", name, e)
                    ))?;
            }
        }
        Ok(())
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Route to appropriate sub-plugin
        let plugin_name = self.router.route(&request)
            .ok_or_else(|| PluginError::CapabilityNotSupported(request.capability.clone()))?;
        
        let plugin = self.plugins.get(&plugin_name)
            .ok_or_else(|| PluginError::Internal(format!("Plugin {} not found", plugin_name)))?;
        
        // Delegate to sub-plugin
        plugin.handle(request).await
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        // Shutdown all sub-plugins
        let mut errors = Vec::new();
        
        for (name, plugin) in &mut self.plugins {
            let plugin_clone = plugin.clone();
            if let Some(mut_plugin) = Arc::get_mut(&mut plugin_clone) {
                if let Err(e) = mut_plugin.shutdown().await {
                    errors.push(format!("{}: {}", name, e));
                }
            }
        }
        
        if !errors.is_empty() {
            return Err(PluginError::Shutdown(errors.join(", ")));
        }
        
        Ok(())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Usage example
impl CompositePlugin {
    pub fn builder() -> CompositePluginBuilder {
        CompositePluginBuilder::new()
    }
}

pub struct CompositePluginBuilder {
    plugins: HashMap<String, Arc<dyn Plugin>>,
    routes: HashMap<Capability, String>,
}

impl CompositePluginBuilder {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            routes: HashMap::new(),
        }
    }
    
    pub fn add_plugin(mut self, name: String, plugin: Arc<dyn Plugin>) -> Self {
        // Register all capabilities from this plugin
        for capability in &plugin.metadata().provides {
            self.routes.insert(capability.clone(), name.clone());
        }
        self.plugins.insert(name, plugin);
        self
    }
    
    pub fn build(self) -> CompositePlugin {
        // Aggregate metadata from all plugins
        let mut all_capabilities = Vec::new();
        let mut all_dependencies = Vec::new();
        
        for plugin in self.plugins.values() {
            all_capabilities.extend(plugin.metadata().provides.clone());
            all_dependencies.extend(plugin.metadata().dependencies.clone());
        }
        
        CompositePlugin {
            metadata: PluginMetadata {
                id: "composite-plugin".to_string(),
                name: "Composite Plugin".to_string(),
                version: "1.0.0".to_string(),
                provides: all_capabilities,
                dependencies: all_dependencies,
                // ... other fields
            },
            plugins: self.plugins,
            router: Arc::new(CapabilityRouter { routes: self.routes }),
        }
    }
}
```

## Middleware Pattern

### Request/Response Middleware

```rust
use std::future::Future;
use std::pin::Pin;

#[async_trait]
pub trait Middleware: Send + Sync + std::fmt::Debug {
    async fn before_handle(&self, request: &mut PluginRequest) -> Result<()>;
    async fn after_handle(&self, response: &mut PluginResponse) -> Result<()>;
    async fn on_error(&self, error: &PluginError, request: &PluginRequest) -> Result<()>;
}

#[derive(Debug)]
pub struct MiddlewarePlugin<P: Plugin> {
    inner: P,
    middlewares: Vec<Box<dyn Middleware>>,
}

impl<P: Plugin> MiddlewarePlugin<P> {
    pub fn new(plugin: P) -> Self {
        Self {
            inner: plugin,
            middlewares: Vec::new(),
        }
    }
    
    pub fn add_middleware(mut self, middleware: Box<dyn Middleware>) -> Self {
        self.middlewares.push(middleware);
        self
    }
}

#[async_trait]
impl<P: Plugin> Plugin for MiddlewarePlugin<P> {
    fn metadata(&self) -> &PluginMetadata {
        self.inner.metadata()
    }
    
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        self.inner.initialize(config).await
    }
    
    async fn handle(&self, mut request: PluginRequest) -> Result<PluginResponse> {
        // Run before middlewares
        for middleware in &self.middlewares {
            middleware.before_handle(&mut request).await?;
        }
        
        // Handle request
        let result = self.inner.handle(request.clone()).await;
        
        match result {
            Ok(mut response) => {
                // Run after middlewares
                for middleware in &self.middlewares {
                    middleware.after_handle(&mut response).await?;
                }
                Ok(response)
            }
            Err(ref error) => {
                // Run error middlewares
                for middleware in &self.middlewares {
                    middleware.on_error(error, &request).await?;
                }
                result
            }
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Example middlewares

#[derive(Debug)]
struct LoggingMiddleware;

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn before_handle(&self, request: &mut PluginRequest) -> Result<()> {
        info!("Request {}: {} {}", request.id, request.capability, request.method);
        Ok(())
    }
    
    async fn after_handle(&self, response: &mut PluginResponse) -> Result<()> {
        info!("Response {}: {:?}", response.request_id, response.result);
        Ok(())
    }
    
    async fn on_error(&self, error: &PluginError, request: &PluginRequest) -> Result<()> {
        error!("Error handling {}: {}", request.id, error);
        Ok(())
    }
}

#[derive(Debug)]
struct MetricsMiddleware {
    metrics: Arc<Mutex<Metrics>>,
}

#[async_trait]
impl Middleware for MetricsMiddleware {
    async fn before_handle(&self, request: &mut PluginRequest) -> Result<()> {
        request.metadata["start_time"] = serde_json::json!(chrono::Utc::now().timestamp_millis());
        Ok(())
    }
    
    async fn after_handle(&self, response: &mut PluginResponse) -> Result<()> {
        if let Some(start) = response.metadata.get("start_time").and_then(|v| v.as_i64()) {
            let duration = chrono::Utc::now().timestamp_millis() - start;
            
            let mut metrics = self.metrics.lock().await;
            metrics.request_count += 1;
            metrics.total_duration_ms += duration as u64;
            metrics.last_request_duration_ms = duration as u64;
        }
        Ok(())
    }
    
    async fn on_error(&self, _error: &PluginError, _request: &PluginRequest) -> Result<()> {
        let mut metrics = self.metrics.lock().await;
        metrics.error_count += 1;
        Ok(())
    }
}

#[derive(Debug)]
struct AuthenticationMiddleware {
    validator: Arc<dyn TokenValidator>,
}

#[async_trait]
impl Middleware for AuthenticationMiddleware {
    async fn before_handle(&self, request: &mut PluginRequest) -> Result<()> {
        let token = request.metadata.get("auth_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PluginError::Authentication("Missing auth token".to_string()))?;
        
        self.validator.validate(token).await
            .map_err(|e| PluginError::Authentication(e.to_string()))?;
        
        Ok(())
    }
    
    async fn after_handle(&self, _response: &mut PluginResponse) -> Result<()> {
        Ok(())
    }
    
    async fn on_error(&self, _error: &PluginError, _request: &PluginRequest) -> Result<()> {
        Ok(())
    }
}
```

## Event-Driven Architecture

### Event-Based Plugin Communication

```rust
use tokio::sync::broadcast;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum PluginEvent {
    StateChanged { plugin_id: String, state: serde_json::Value },
    RequestCompleted { plugin_id: String, request_id: String, duration_ms: u64 },
    ErrorOccurred { plugin_id: String, error: String },
    Custom { plugin_id: String, event_type: String, data: serde_json::Value },
}

#[derive(Debug)]
pub struct EventDrivenPlugin {
    metadata: PluginMetadata,
    event_sender: broadcast::Sender<PluginEvent>,
    event_receiver: broadcast::Receiver<PluginEvent>,
    handlers: Arc<RwLock<HashMap<String, Box<dyn EventHandler>>>>,
}

#[async_trait]
pub trait EventHandler: Send + Sync + std::fmt::Debug {
    async fn handle_event(&self, event: &PluginEvent) -> Result<()>;
}

impl EventDrivenPlugin {
    pub fn new() -> Self {
        let (sender, receiver) = broadcast::channel(1000);
        
        Self {
            metadata: PluginMetadata {
                id: "event-driven-plugin".to_string(),
                // ... other fields
            },
            event_sender: sender,
            event_receiver: receiver,
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn register_handler(&self, event_type: String, handler: Box<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(event_type, handler);
    }
    
    pub async fn emit_event(&self, event: PluginEvent) -> Result<()> {
        self.event_sender.send(event.clone())
            .map_err(|_| PluginError::Internal("Failed to send event".to_string()))?;
        
        // Process handlers
        let handlers = self.handlers.read().await;
        let event_type = match &event {
            PluginEvent::StateChanged { .. } => "state_changed",
            PluginEvent::RequestCompleted { .. } => "request_completed",
            PluginEvent::ErrorOccurred { .. } => "error_occurred",
            PluginEvent::Custom { event_type, .. } => event_type.as_str(),
        };
        
        if let Some(handler) = handlers.get(event_type) {
            handler.handle_event(&event).await?;
        }
        
        Ok(())
    }
    
    pub fn subscribe(&self) -> broadcast::Receiver<PluginEvent> {
        self.event_sender.subscribe()
    }
}

// Example: Plugin that reacts to events
#[derive(Debug)]
struct ReactivePlugin {
    base: EventDrivenPlugin,
    state: Arc<RwLock<ReactiveState>>,
}

#[derive(Debug)]
struct ReactiveState {
    processing_queue: Vec<String>,
    completed_count: u64,
}

impl ReactivePlugin {
    pub async fn new() -> Self {
        let base = EventDrivenPlugin::new();
        let state = Arc::new(RwLock::new(ReactiveState {
            processing_queue: Vec::new(),
            completed_count: 0,
        }));
        
        // Register event handlers
        let state_clone = state.clone();
        base.register_handler("request_completed".to_string(), Box::new(
            CompletionHandler { state: state_clone }
        )).await;
        
        Self { base, state }
    }
}

#[derive(Debug)]
struct CompletionHandler {
    state: Arc<RwLock<ReactiveState>>,
}

#[async_trait]
impl EventHandler for CompletionHandler {
    async fn handle_event(&self, event: &PluginEvent) -> Result<()> {
        if let PluginEvent::RequestCompleted { request_id, .. } = event {
            let mut state = self.state.write().await;
            state.processing_queue.retain(|id| id != request_id);
            state.completed_count += 1;
            
            info!("Request {} completed. Total: {}", request_id, state.completed_count);
        }
        Ok(())
    }
}
```

## Resource Pooling

### Connection Pool Implementation

```rust
use tokio::sync::Semaphore;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct ResourcePool<T: Resource> {
    resources: Arc<Mutex<VecDeque<T>>>,
    semaphore: Arc<Semaphore>,
    factory: Arc<dyn ResourceFactory<T>>,
    config: PoolConfig,
    metrics: Arc<Mutex<PoolMetrics>>,
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_size: usize,
    pub max_size: usize,
    pub acquire_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub validation_interval_ms: u64,
}

#[derive(Debug, Default)]
struct PoolMetrics {
    acquired_count: u64,
    released_count: u64,
    created_count: u64,
    destroyed_count: u64,
    timeout_count: u64,
    validation_failures: u64,
}

#[async_trait]
pub trait Resource: Send + Sync + std::fmt::Debug {
    async fn validate(&self) -> bool;
    async fn reset(&mut self) -> Result<()>;
}

#[async_trait]
pub trait ResourceFactory<T: Resource>: Send + Sync + std::fmt::Debug {
    async fn create(&self) -> Result<T>;
    async fn destroy(&self, resource: T) -> Result<()>;
}

pub struct PooledResource<T: Resource> {
    resource: Option<T>,
    pool: Arc<ResourcePool<T>>,
}

impl<T: Resource> Drop for PooledResource<T> {
    fn drop(&mut self) {
        if let Some(resource) = self.resource.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.release(resource).await;
            });
        }
    }
}

impl<T: Resource> std::ops::Deref for PooledResource<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.resource.as_ref().expect("Resource already released")
    }
}

impl<T: Resource> std::ops::DerefMut for PooledResource<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.resource.as_mut().expect("Resource already released")
    }
}

impl<T: Resource + 'static> ResourcePool<T> {
    pub fn new(factory: Arc<dyn ResourceFactory<T>>, config: PoolConfig) -> Self {
        let pool = Self {
            resources: Arc::new(Mutex::new(VecDeque::new())),
            semaphore: Arc::new(Semaphore::new(config.max_size)),
            factory,
            config: config.clone(),
            metrics: Arc::new(Mutex::new(PoolMetrics::default())),
        };
        
        // Start background tasks
        pool.start_maintenance();
        
        pool
    }
    
    pub async fn acquire(&self) -> Result<PooledResource<T>> {
        // Try to acquire permit with timeout
        let permit = tokio::time::timeout(
            Duration::from_millis(self.config.acquire_timeout_ms),
            self.semaphore.acquire()
        ).await.map_err(|_| {
            let mut metrics = self.metrics.lock().await;
            metrics.timeout_count += 1;
            PluginError::Timeout("Failed to acquire resource from pool".to_string())
        })?.map_err(|_| PluginError::Internal("Semaphore closed".to_string()))?;
        
        // Get or create resource
        let resource = {
            let mut resources = self.resources.lock().await;
            resources.pop_front()
        };
        
        let resource = match resource {
            Some(mut res) => {
                // Validate existing resource
                if res.validate().await {
                    res.reset().await?;
                    res
                } else {
                    // Create new resource
                    let mut metrics = self.metrics.lock().await;
                    metrics.validation_failures += 1;
                    self.factory.destroy(res).await?;
                    self.create_resource().await?
                }
            }
            None => {
                // Create new resource
                self.create_resource().await?
            }
        };
        
        let mut metrics = self.metrics.lock().await;
        metrics.acquired_count += 1;
        
        // Forget permit so it's not released
        permit.forget();
        
        Ok(PooledResource {
            resource: Some(resource),
            pool: Arc::new(self.clone()),
        })
    }
    
    async fn release(&self, resource: T) {
        let mut resources = self.resources.lock().await;
        resources.push_back(resource);
        
        let mut metrics = self.metrics.lock().await;
        metrics.released_count += 1;
        
        // Release permit
        self.semaphore.add_permits(1);
    }
    
    async fn create_resource(&self) -> Result<T> {
        let resource = self.factory.create().await?;
        
        let mut metrics = self.metrics.lock().await;
        metrics.created_count += 1;
        
        Ok(resource)
    }
    
    fn start_maintenance(&self) {
        let pool = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_millis(pool.config.validation_interval_ms)
            );
            
            loop {
                interval.tick().await;
                
                // Validate and clean up resources
                let mut resources = pool.resources.lock().await;
                let mut to_remove = Vec::new();
                
                for (i, resource) in resources.iter().enumerate() {
                    if !resource.validate().await {
                        to_remove.push(i);
                    }
                }
                
                // Remove invalid resources
                for i in to_remove.into_iter().rev() {
                    if let Some(resource) = resources.remove(i) {
                        drop(resources); // Release lock
                        
                        let _ = pool.factory.destroy(resource).await;
                        
                        let mut metrics = pool.metrics.lock().await;
                        metrics.destroyed_count += 1;
                        
                        resources = pool.resources.lock().await;
                    }
                }
                
                // Ensure minimum pool size
                let current_size = resources.len();
                drop(resources);
                
                for _ in current_size..pool.config.min_size {
                    if let Ok(resource) = pool.create_resource().await {
                        let mut resources = pool.resources.lock().await;
                        resources.push_back(resource);
                    }
                }
            }
        });
    }
}

// Example: Database connection pool
#[derive(Debug)]
struct DatabaseConnection {
    id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: Arc<Mutex<chrono::DateTime<chrono::Utc>>>,
}

#[async_trait]
impl Resource for DatabaseConnection {
    async fn validate(&self) -> bool {
        // Check if connection is still alive
        let last_used = *self.last_used.lock().await;
        let idle_time = chrono::Utc::now() - last_used;
        
        idle_time.num_seconds() < 300 // 5 minutes idle timeout
    }
    
    async fn reset(&mut self) -> Result<()> {
        // Reset connection state
        *self.last_used.lock().await = chrono::Utc::now();
        Ok(())
    }
}

#[derive(Debug)]
struct DatabaseFactory {
    connection_string: String,
}

#[async_trait]
impl ResourceFactory<DatabaseConnection> for DatabaseFactory {
    async fn create(&self) -> Result<DatabaseConnection> {
        // Simulate connection creation
        Ok(DatabaseConnection {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now(),
            last_used: Arc::new(Mutex::new(chrono::Utc::now())),
        })
    }
    
    async fn destroy(&self, _connection: DatabaseConnection) -> Result<()> {
        // Close connection
        Ok(())
    }
}
```

## Circuit Breaker Pattern

### Fault-Tolerant Plugin

```rust
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};

#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u64,
    success_threshold: u64,
    timeout_ms: u64,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: AtomicI64,
    state: Arc<RwLock<CircuitState>>,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open { opened_at: chrono::DateTime<chrono::Utc> },
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u64, success_threshold: u64, timeout_ms: u64) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            timeout_ms,
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: AtomicI64::new(0),
            state: Arc::new(RwLock::new(CircuitState::Closed)),
        }
    }
    
    pub async fn call<F, R>(&self, operation: F) -> Result<R>
    where
        F: Future<Output = Result<R>>,
    {
        // Check circuit state
        let current_state = self.get_state().await;
        
        match current_state {
            CircuitState::Open { opened_at } => {
                let elapsed = chrono::Utc::now() - opened_at;
                if elapsed.num_milliseconds() as u64 > self.timeout_ms {
                    // Try half-open
                    *self.state.write().await = CircuitState::HalfOpen;
                } else {
                    return Err(PluginError::CircuitOpen(
                        "Circuit breaker is open".to_string()
                    ));
                }
            }
            _ => {}
        }
        
        // Execute operation
        match operation.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(error) => {
                self.on_failure().await;
                Err(error)
            }
        }
    }
    
    async fn get_state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
    
    async fn on_success(&self) {
        self.failure_count.store(0, Ordering::SeqCst);
        let success = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
        
        let mut state = self.state.write().await;
        match *state {
            CircuitState::HalfOpen => {
                if success >= self.success_threshold {
                    *state = CircuitState::Closed;
                    self.success_count.store(0, Ordering::SeqCst);
                    info!("Circuit breaker closed");
                }
            }
            _ => {}
        }
    }
    
    async fn on_failure(&self) {
        self.success_count.store(0, Ordering::SeqCst);
        let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.last_failure_time.store(chrono::Utc::now().timestamp_millis(), Ordering::SeqCst);
        
        let mut state = self.state.write().await;
        match *state {
            CircuitState::Closed => {
                if failures >= self.failure_threshold {
                    *state = CircuitState::Open {
                        opened_at: chrono::Utc::now(),
                    };
                    warn!("Circuit breaker opened after {} failures", failures);
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open {
                    opened_at: chrono::Utc::now(),
                };
                warn!("Circuit breaker reopened from half-open state");
            }
            _ => {}
        }
    }
}

// Circuit breaker plugin wrapper
#[derive(Debug)]
pub struct CircuitBreakerPlugin<P: Plugin> {
    inner: P,
    circuit_breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
}

impl<P: Plugin> CircuitBreakerPlugin<P> {
    pub fn new(plugin: P) -> Self {
        Self {
            inner: plugin,
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    async fn get_circuit_breaker(&self, method: &str) -> Arc<CircuitBreaker> {
        let mut breakers = self.circuit_breakers.write().await;
        
        breakers.entry(method.to_string())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(5, 3, 30000)))
            .clone()
    }
}

#[async_trait]
impl<P: Plugin> Plugin for CircuitBreakerPlugin<P> {
    fn metadata(&self) -> &PluginMetadata {
        self.inner.metadata()
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let breaker = self.get_circuit_breaker(&request.method).await;
        
        breaker.call(async {
            self.inner.handle(request).await
        }).await
    }
    
    // ... other methods delegate to inner
}
```

## Plugin Pipelines

### Sequential Processing Pipeline

```rust
#[derive(Debug)]
pub struct Pipeline {
    stages: Vec<Arc<dyn PipelineStage>>,
}

#[async_trait]
pub trait PipelineStage: Send + Sync + std::fmt::Debug {
    async fn process(&self, data: PipelineData) -> Result<PipelineData>;
    fn can_handle(&self, data: &PipelineData) -> bool;
}

#[derive(Debug, Clone)]
pub struct PipelineData {
    pub id: String,
    pub stage: usize,
    pub data: serde_json::Value,
    pub metadata: HashMap<String, serde_json::Value>,
    pub errors: Vec<String>,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder { stages: Vec::new() }
    }
    
    pub async fn execute(&self, initial_data: serde_json::Value) -> Result<PipelineData> {
        let mut pipeline_data = PipelineData {
            id: uuid::Uuid::new_v4().to_string(),
            stage: 0,
            data: initial_data,
            metadata: HashMap::new(),
            errors: Vec::new(),
        };
        
        for (i, stage) in self.stages.iter().enumerate() {
            pipeline_data.stage = i;
            
            if !stage.can_handle(&pipeline_data) {
                info!("Stage {} skipped", i);
                continue;
            }
            
            match stage.process(pipeline_data.clone()).await {
                Ok(result) => {
                    pipeline_data = result;
                }
                Err(e) => {
                    pipeline_data.errors.push(format!("Stage {} failed: {}", i, e));
                    return Err(PluginError::Pipeline(format!("Stage {} failed: {}", i, e)));
                }
            }
        }
        
        Ok(pipeline_data)
    }
}

pub struct PipelineBuilder {
    stages: Vec<Arc<dyn PipelineStage>>,
}

impl PipelineBuilder {
    pub fn add_stage(mut self, stage: Arc<dyn PipelineStage>) -> Self {
        self.stages.push(stage);
        self
    }
    
    pub fn build(self) -> Pipeline {
        Pipeline { stages: self.stages }
    }
}

// Example pipeline stages

#[derive(Debug)]
struct ValidationStage {
    schema: serde_json::Value,
}

#[async_trait]
impl PipelineStage for ValidationStage {
    async fn process(&self, mut data: PipelineData) -> Result<PipelineData> {
        // Validate data against schema
        info!("Validating data for pipeline {}", data.id);
        
        // Add validation metadata
        data.metadata.insert(
            "validated_at".to_string(),
            serde_json::json!(chrono::Utc::now().to_rfc3339())
        );
        
        Ok(data)
    }
    
    fn can_handle(&self, _data: &PipelineData) -> bool {
        true // Always validate
    }
}

#[derive(Debug)]
struct TransformStage {
    transformer: Arc<dyn DataTransformer>,
}

#[async_trait]
pub trait DataTransformer: Send + Sync + std::fmt::Debug {
    async fn transform(&self, data: serde_json::Value) -> Result<serde_json::Value>;
}

#[async_trait]
impl PipelineStage for TransformStage {
    async fn process(&self, mut data: PipelineData) -> Result<PipelineData> {
        info!("Transforming data for pipeline {}", data.id);
        
        data.data = self.transformer.transform(data.data).await?;
        
        data.metadata.insert(
            "transformed_at".to_string(),
            serde_json::json!(chrono::Utc::now().to_rfc3339())
        );
        
        Ok(data)
    }
    
    fn can_handle(&self, data: &PipelineData) -> bool {
        // Only transform if validation passed
        data.metadata.contains_key("validated_at")
    }
}

#[derive(Debug)]
struct EnrichmentStage {
    enricher: Arc<dyn DataEnricher>,
}

#[async_trait]
pub trait DataEnricher: Send + Sync + std::fmt::Debug {
    async fn enrich(&self, data: serde_json::Value) -> Result<serde_json::Value>;
}

#[async_trait]
impl PipelineStage for EnrichmentStage {
    async fn process(&self, mut data: PipelineData) -> Result<PipelineData> {
        info!("Enriching data for pipeline {}", data.id);
        
        data.data = self.enricher.enrich(data.data).await?;
        
        data.metadata.insert(
            "enriched_at".to_string(),
            serde_json::json!(chrono::Utc::now().to_rfc3339())
        );
        
        Ok(data)
    }
    
    fn can_handle(&self, data: &PipelineData) -> bool {
        // Only enrich if transformed
        data.metadata.contains_key("transformed_at")
    }
}

// Pipeline plugin
#[derive(Debug)]
pub struct PipelinePlugin {
    metadata: PluginMetadata,
    pipelines: Arc<RwLock<HashMap<String, Pipeline>>>,
}

#[async_trait]
impl Plugin for PipelinePlugin {
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let pipeline_name = request.params.get("pipeline")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PluginError::InvalidRequest("pipeline parameter required".into()))?;
        
        let pipelines = self.pipelines.read().await;
        let pipeline = pipelines.get(pipeline_name)
            .ok_or_else(|| PluginError::NotFound(format!("Pipeline {} not found", pipeline_name)))?;
        
        let input_data = request.params.get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        
        let result = pipeline.execute(input_data).await?;
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: serde_json::json!({
                    "pipeline_id": result.id,
                    "stages_completed": result.stage + 1,
                    "result": result.data,
                    "metadata": result.metadata,
                }),
            },
            metadata: serde_json::json!({}),
        })
    }
    
    // ... other trait methods
}
```

## Distributed Plugins

### Multi-Node Plugin Coordination

```rust
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: String,
    pub address: String,
    pub capabilities: Vec<Capability>,
    pub load: f64,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct DistributedPlugin {
    metadata: PluginMetadata,
    node_id: String,
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    coordinator: Arc<dyn Coordinator>,
    heartbeat_tx: watch::Sender<chrono::DateTime<chrono::Utc>>,
}

#[async_trait]
pub trait Coordinator: Send + Sync + std::fmt::Debug {
    async fn elect_leader(&self, nodes: &[NodeInfo]) -> Option<String>;
    async fn route_request(&self, request: &PluginRequest, nodes: &[NodeInfo]) -> Option<String>;
    async fn sync_state(&self, state: serde_json::Value) -> Result<()>;
}

impl DistributedPlugin {
    pub fn new(node_id: String, coordinator: Arc<dyn Coordinator>) -> Self {
        let (tx, _rx) = watch::channel(chrono::Utc::now());
        
        Self {
            metadata: PluginMetadata {
                id: format!("distributed-plugin-{}", node_id),
                // ... other fields
            },
            node_id,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            coordinator,
            heartbeat_tx: tx,
        }
    }
    
    pub async fn join_cluster(&self, seeds: Vec<String>) -> Result<()> {
        info!("Node {} joining cluster with seeds: {:?}", self.node_id, seeds);
        
        // Connect to seed nodes
        for seed in seeds {
            if let Ok(node_info) = self.discover_node(&seed).await {
                let mut nodes = self.nodes.write().await;
                nodes.insert(node_info.id.clone(), node_info);
            }
        }
        
        // Start heartbeat
        self.start_heartbeat();
        
        // Start node discovery
        self.start_discovery();
        
        Ok(())
    }
    
    async fn discover_node(&self, address: &str) -> Result<NodeInfo> {
        // In practice, this would make an RPC call
        Ok(NodeInfo {
            id: uuid::Uuid::new_v4().to_string(),
            address: address.to_string(),
            capabilities: vec![],
            load: 0.0,
            last_heartbeat: chrono::Utc::now(),
        })
    }
    
    fn start_heartbeat(&self) {
        let tx = self.heartbeat_tx.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                let _ = tx.send(chrono::Utc::now());
            }
        });
    }
    
    fn start_discovery(&self) {
        let nodes = self.nodes.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Remove stale nodes
                let mut nodes = nodes.write().await;
                let now = chrono::Utc::now();
                
                nodes.retain(|_, node| {
                    let age = now - node.last_heartbeat;
                    age.num_seconds() < 60 // 1 minute timeout
                });
            }
        });
    }
}

#[async_trait]
impl Plugin for DistributedPlugin {
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let nodes = self.nodes.read().await;
        let all_nodes: Vec<NodeInfo> = nodes.values().cloned().collect();
        
        // Route request to appropriate node
        if let Some(target_node) = self.coordinator.route_request(&request, &all_nodes).await {
            if target_node == self.node_id {
                // Handle locally
                self.handle_local(request).await
            } else {
                // Forward to remote node
                self.forward_request(request, &target_node).await
            }
        } else {
            Err(PluginError::NoAvailableNodes)
        }
    }
    
    // ... other trait methods
}

// Example coordinator implementation
#[derive(Debug)]
struct ConsistentHashCoordinator {
    ring: Arc<RwLock<ConsistentHashRing>>,
}

#[async_trait]
impl Coordinator for ConsistentHashCoordinator {
    async fn elect_leader(&self, nodes: &[NodeInfo]) -> Option<String> {
        // Simple: node with lowest ID is leader
        nodes.iter()
            .min_by_key(|n| &n.id)
            .map(|n| n.id.clone())
    }
    
    async fn route_request(&self, request: &PluginRequest, nodes: &[NodeInfo]) -> Option<String> {
        let ring = self.ring.read().await;
        ring.get_node(&request.id)
    }
    
    async fn sync_state(&self, state: serde_json::Value) -> Result<()> {
        // Broadcast state to all nodes
        Ok(())
    }
}
```

## Performance Optimization

### Async Batch Processing

```rust
use tokio::sync::mpsc;
use futures::stream::{Stream, StreamExt};

#[derive(Debug)]
pub struct BatchProcessor<T, R> {
    batch_size: usize,
    timeout_ms: u64,
    processor: Arc<dyn BatchHandler<T, R>>,
    sender: mpsc::Sender<BatchRequest<T, R>>,
}

#[derive(Debug)]
struct BatchRequest<T, R> {
    item: T,
    response_tx: oneshot::Sender<Result<R>>,
}

#[async_trait]
pub trait BatchHandler<T, R>: Send + Sync + std::fmt::Debug {
    async fn process_batch(&self, items: Vec<T>) -> Vec<Result<R>>;
}

impl<T: Send + 'static, R: Send + 'static> BatchProcessor<T, R> {
    pub fn new(
        batch_size: usize,
        timeout_ms: u64,
        processor: Arc<dyn BatchHandler<T, R>>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        
        let processor_clone = processor.clone();
        tokio::spawn(async move {
            Self::run_processor(receiver, batch_size, timeout_ms, processor_clone).await;
        });
        
        Self {
            batch_size,
            timeout_ms,
            processor,
            sender,
        }
    }
    
    pub async fn process(&self, item: T) -> Result<R> {
        let (tx, rx) = oneshot::channel();
        
        self.sender.send(BatchRequest {
            item,
            response_tx: tx,
        }).await.map_err(|_| PluginError::Internal("Batch processor closed".to_string()))?;
        
        rx.await.map_err(|_| PluginError::Internal("Response channel closed".to_string()))?
    }
    
    async fn run_processor(
        mut receiver: mpsc::Receiver<BatchRequest<T, R>>,
        batch_size: usize,
        timeout_ms: u64,
        processor: Arc<dyn BatchHandler<T, R>>,
    ) {
        let mut batch = Vec::with_capacity(batch_size);
        let mut response_txs = Vec::with_capacity(batch_size);
        
        loop {
            // Collect batch
            let timeout = tokio::time::sleep(Duration::from_millis(timeout_ms));
            tokio::pin!(timeout);
            
            loop {
                tokio::select! {
                    Some(request) = receiver.recv() => {
                        batch.push(request.item);
                        response_txs.push(request.response_tx);
                        
                        if batch.len() >= batch_size {
                            break;
                        }
                    }
                    _ = &mut timeout => {
                        if !batch.is_empty() {
                            break;
                        }
                    }
                    else => return, // Channel closed
                }
            }
            
            // Process batch
            let items = std::mem::take(&mut batch);
            let txs = std::mem::take(&mut response_txs);
            
            let results = processor.process_batch(items).await;
            
            // Send responses
            for (tx, result) in txs.into_iter().zip(results.into_iter()) {
                let _ = tx.send(result);
            }
        }
    }
}

// Example: Batch database operations
#[derive(Debug)]
struct DatabaseBatchHandler {
    pool: Arc<ResourcePool<DatabaseConnection>>,
}

#[async_trait]
impl BatchHandler<DatabaseQuery, QueryResult> for DatabaseBatchHandler {
    async fn process_batch(&self, queries: Vec<DatabaseQuery>) -> Vec<Result<QueryResult>> {
        let conn = match self.pool.acquire().await {
            Ok(conn) => conn,
            Err(e) => return vec![Err(e); queries.len()],
        };
        
        // Execute all queries in a single transaction
        let mut results = Vec::with_capacity(queries.len());
        
        // Start transaction
        conn.begin_transaction().await;
        
        for query in queries {
            let result = conn.execute_query(query).await;
            results.push(result);
        }
        
        // Commit transaction
        conn.commit_transaction().await;
        
        results
    }
}

// Caching layer
#[derive(Debug)]
pub struct CachedPlugin<P: Plugin> {
    inner: P,
    cache: Arc<Cache<String, serde_json::Value>>,
}

#[derive(Debug)]
struct Cache<K, V> {
    entries: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    max_size: usize,
    ttl_ms: u64,
}

#[derive(Debug)]
struct CacheEntry<V> {
    value: V,
    created_at: chrono::DateTime<chrono::Utc>,
    access_count: AtomicU64,
    last_accessed: AtomicI64,
}

impl<K: Hash + Eq + Clone, V: Clone> Cache<K, V> {
    pub async fn get(&self, key: &K) -> Option<V> {
        let entries = self.entries.read().await;
        
        if let Some(entry) = entries.get(key) {
            let age = chrono::Utc::now() - entry.created_at;
            
            if age.num_milliseconds() as u64 <= self.ttl_ms {
                entry.access_count.fetch_add(1, Ordering::SeqCst);
                entry.last_accessed.store(chrono::Utc::now().timestamp_millis(), Ordering::SeqCst);
                return Some(entry.value.clone());
            }
        }
        
        None
    }
    
    pub async fn put(&self, key: K, value: V) {
        let mut entries = self.entries.write().await;
        
        // Evict if at capacity
        if entries.len() >= self.max_size {
            // LRU eviction
            if let Some((evict_key, _)) = entries.iter()
                .min_by_key(|(_, entry)| entry.last_accessed.load(Ordering::SeqCst))
                .map(|(k, v)| (k.clone(), v)) {
                entries.remove(&evict_key);
            }
        }
        
        entries.insert(key, CacheEntry {
            value,
            created_at: chrono::Utc::now(),
            access_count: AtomicU64::new(0),
            last_accessed: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
        });
    }
}

#[async_trait]
impl<P: Plugin> Plugin for CachedPlugin<P> {
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Generate cache key
        let cache_key = format!("{}:{}:{}", 
            request.capability, 
            request.method, 
            serde_json::to_string(&request.params)?
        );
        
        // Check cache
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success { data: cached },
                metadata: serde_json::json!({ "cached": true }),
            });
        }
        
        // Process request
        let response = self.inner.handle(request).await?;
        
        // Cache successful responses
        if let PluginResult::Success { ref data } = response.result {
            self.cache.put(cache_key, data.clone()).await;
        }
        
        Ok(response)
    }
    
    // ... other trait methods delegate to inner
}
```

## Summary

These advanced patterns enable you to build sophisticated, production-ready plugins:

1. **Plugin Composition**: Build complex plugins from simpler components
2. **Middleware**: Add cross-cutting concerns like logging and metrics
3. **Event-Driven**: Enable loose coupling between components
4. **Resource Pooling**: Efficiently manage expensive resources
5. **Circuit Breaker**: Handle failures gracefully
6. **Pipelines**: Process data through multiple stages
7. **Distribution**: Scale across multiple nodes
8. **Performance**: Optimize with batching and caching

Choose patterns based on your specific requirements and combine them as needed for your use case.