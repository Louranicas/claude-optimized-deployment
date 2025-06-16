//! Plugin System for MCP Manager
//! 
//! This is not just a plugin system. This is the apotheosis of extensibility.
//! Every line of code here represents the crystallization of decades of 
//! systems programming wisdom.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

pub mod traits;
pub use traits::{Plugin, PluginFactory};
pub mod registry;
pub mod loader;
pub mod lifecycle;
pub mod discovery;
pub mod capabilities;
pub mod schema;
pub mod negotiation;
pub mod hot_reload;
pub mod version;
pub mod state_transfer;
pub mod rollback;
pub mod zero_downtime;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::any::Any;
use std::sync::Arc;
use thiserror::Error;

/// The result type for all plugin operations
pub type Result<T> = std::result::Result<T, PluginError>;

/// Plugin errors - comprehensive and actionable
#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),
    
    #[error("Plugin loading failed: {0}")]
    LoadingFailed(String),
    
    #[error("Incompatible plugin version: expected {expected}, got {actual}")]
    IncompatibleVersion { expected: String, actual: String },
    
    #[error("Missing capability: {0}")]
    MissingCapability(String),
    
    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Plugin execution error: {0}")]
    ExecutionError(String),
    
    #[error("Dependency not satisfied: {0}")]
    DependencyNotSatisfied(String),
    
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
    
    #[error("Invalid plugin manifest: {0}")]
    InvalidManifest(String),
    
    #[error("Security violation: {0}")]
    SecurityViolation(String),
}

/// Type alias for backwards compatibility
pub type Metadata = PluginMetadata;
pub type Request = PluginRequest;
pub type Response = PluginResponse;

/// Plugin handle type
pub type Handle = Box<dyn Plugin>;

/// Plugin state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unloaded,
    Loading,
    Loaded,
    Initializing,
    Ready,
    Stopping,
    Stopped,
    Failed,
    ShuttingDown,
    Shutdown,
    Error,
}

/// Plugin metadata - everything needed to understand a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique identifier
    pub id: String,
    
    /// Human-readable name
    pub name: String,
    
    /// Semantic version
    pub version: String,
    
    /// Plugin author
    pub author: String,
    
    /// Plugin description
    pub description: String,
    
    /// License identifier (SPDX)
    pub license: String,
    
    /// Homepage URL
    pub homepage: Option<String>,
    
    /// Repository URL
    pub repository: Option<String>,
    
    /// Minimum MCP version required
    pub min_mcp_version: String,
    
    /// Dependencies on other plugins
    pub dependencies: Vec<PluginDependency>,
    
    /// Capabilities provided
    pub provides: Vec<Capability>,
    
    /// Capabilities required
    pub requires: Vec<Capability>,
}

/// Plugin dependency specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    /// Plugin ID
    pub id: String,
    
    /// Version requirement (semver)
    pub version: String,
    
    /// Is this dependency optional?
    pub optional: bool,
}

/// Capability definition - what a plugin can do
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    /// Namespace (e.g., "docker", "k8s", "monitoring")
    pub namespace: String,
    
    /// Capability name (e.g., "container.create", "pod.list")
    pub name: String,
    
    /// Version of this capability
    pub version: u32,
}

impl Capability {
    /// Create a new capability
    pub fn new(namespace: impl Into<String>, name: impl Into<String>, version: u32) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            version,
        }
    }
    
    /// Parse from string format "namespace.name:version"
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(PluginError::InvalidManifest(
                format!("Invalid capability format: {}", s)
            ));
        }
        
        let version: u32 = parts[1].parse()
            .map_err(|_| PluginError::InvalidManifest(
                format!("Invalid capability version: {}", parts[1])
            ))?;
            
        let ns_name: Vec<&str> = parts[0].split('.').collect();
        if ns_name.len() < 2 {
            return Err(PluginError::InvalidManifest(
                format!("Invalid capability namespace.name: {}", parts[0])
            ));
        }
        
        Ok(Self {
            namespace: ns_name[0].to_string(),
            name: ns_name[1..].join("."),
            version,
        })
    }
    
    /// Convert to string format
    pub fn to_string(&self) -> String {
        format!("{}.{}:{}", self.namespace, self.name, self.version)
    }
}

/// Plugin request - what gets sent to a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    /// Unique request ID
    pub id: String,
    
    /// Target capability
    pub capability: Capability,
    
    /// Method to invoke
    pub method: String,
    
    /// Request parameters
    pub params: Value,
    
    /// Request metadata (headers, auth, etc.)
    pub metadata: Value,
}

/// Plugin response - what comes back
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResponse {
    /// Request ID this responds to
    pub request_id: String,
    
    /// Success or error
    pub result: PluginResult,
    
    /// Response metadata
    pub metadata: Value,
}

/// Plugin result - success or error
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum PluginResult {
    #[serde(rename = "success")]
    Success { data: Value },
    
    #[serde(rename = "error")]
    Error { code: String, message: String, details: Option<Value> },
}


/// Plugin lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// Plugin is not loaded
    Unloaded,
    
    /// Plugin is loaded but not initialized
    Loaded,
    
    /// Plugin is initializing
    Initializing,
    
    /// Plugin is ready to handle requests
    Ready,
    
    /// Plugin is shutting down
    ShuttingDown,
    
    /// Plugin has shut down
    Shutdown,
    
    /// Plugin is in error state
    Error,
}

/// Plugin handle - what the system uses to interact with plugins
pub struct PluginHandle {
    /// The actual plugin
    plugin: Arc<tokio::sync::RwLock<Box<dyn Plugin>>>,
    
    /// Current state
    state: Arc<tokio::sync::RwLock<PluginState>>,
    
    /// Metrics
    metrics: Arc<tokio::sync::Mutex<PluginMetrics>>,
}

impl std::fmt::Debug for PluginHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginHandle")
            .field("state", &"<locked>")
            .field("metrics", &"<locked>")
            .finish()
    }
}

/// Plugin metrics - performance and health tracking
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginMetrics {
    /// Total requests handled
    pub requests_total: u64,
    
    /// Successful requests
    pub requests_success: u64,
    
    /// Failed requests
    pub requests_failed: u64,
    
    /// Total request duration in microseconds
    pub total_duration_us: u64,
    
    /// Last health check timestamp and result (unix timestamp)
    pub last_health_check: Option<(i64, bool)>,
}

impl PluginHandle {
    /// Create a new plugin handle
    pub fn new(plugin: Box<dyn Plugin>) -> Self {
        Self {
            plugin: Arc::new(tokio::sync::RwLock::new(plugin)),
            state: Arc::new(tokio::sync::RwLock::new(PluginState::Loaded)),
            metrics: Arc::new(tokio::sync::Mutex::new(PluginMetrics::default())),
        }
    }
    
    /// Get current state
    pub async fn state(&self) -> PluginState {
        *self.state.read().await
    }
    
    /// Set state
    pub async fn set_state(&self, state: PluginState) {
        *self.state.write().await = state;
    }
    
    /// Get metadata
    pub async fn metadata(&self) -> PluginMetadata {
        self.plugin.read().await.metadata().clone()
    }
    
    /// Initialize the plugin
    pub async fn initialize(&self, config: Value) -> Result<()> {
        self.set_state(PluginState::Initializing).await;
        
        match self.plugin.write().await.initialize(config).await {
            Ok(()) => {
                self.set_state(PluginState::Ready).await;
                Ok(())
            }
            Err(e) => {
                self.set_state(PluginState::Error).await;
                Err(e)
            }
        }
    }
    
    /// Handle a request
    pub async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let state = self.state().await;
        if state != PluginState::Ready {
            return Err(PluginError::ExecutionError(
                format!("Plugin not ready, current state: {:?}", state)
            ));
        }
        
        let start = std::time::Instant::now();
        let result = self.plugin.read().await.handle(request).await;
        let duration = start.elapsed();
        
        // Update metrics
        let mut metrics = self.metrics.lock().await;
        metrics.requests_total += 1;
        metrics.total_duration_us += duration.as_micros() as u64;
        
        match &result {
            Ok(_) => metrics.requests_success += 1,
            Err(_) => metrics.requests_failed += 1,
        }
        
        result
    }
    
    /// Shutdown the plugin
    pub async fn shutdown(&self) -> Result<()> {
        self.set_state(PluginState::ShuttingDown).await;
        
        match self.plugin.write().await.shutdown().await {
            Ok(()) => {
                self.set_state(PluginState::Shutdown).await;
                Ok(())
            }
            Err(e) => {
                self.set_state(PluginState::Error).await;
                Err(e)
            }
        }
    }
    
    /// Perform health check
    pub async fn health_check(&self) -> Result<bool> {
        let result = self.plugin.read().await.health_check().await;
        
        let mut metrics = self.metrics.lock().await;
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        metrics.last_health_check = Some((timestamp, result.is_ok()));
        
        result
    }
    
    /// Get metrics
    pub async fn metrics(&self) -> PluginMetrics {
        self.metrics.lock().await.clone()
    }
}

/// Plugin factory - for creating plugins dynamically

/// Static plugin registration
#[macro_export]
macro_rules! register_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn _create_plugin() -> *mut dyn $crate::plugin::Plugin {
            let plugin = Box::new(<$plugin_type>::new());
            Box::into_raw(plugin) as *mut dyn $crate::plugin::Plugin
        }
        
        #[no_mangle]
        pub extern "C" fn _plugin_api_version() -> u32 {
            $crate::plugin::PLUGIN_API_VERSION
        }
    };
}

/// Plugin API version for compatibility checking
pub const PLUGIN_API_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_parsing() {
        let cap = Capability::parse("docker.container.create:1").unwrap();
        assert_eq!(cap.namespace, "docker");
        assert_eq!(cap.name, "container.create");
        assert_eq!(cap.version, 1);
        
        let cap_str = cap.to_string();
        assert_eq!(cap_str, "docker.container.create:1");
    }
    
    #[test]
    fn test_capability_invalid_format() {
        assert!(Capability::parse("invalid").is_err());
        assert!(Capability::parse("no:version:here").is_err());
        assert!(Capability::parse("docker.container:abc").is_err());
    }
}