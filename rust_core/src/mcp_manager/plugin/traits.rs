//! Traits - The Contracts of Extensibility
//!
//! Every trait here is a promise, a guarantee of behavior.
//! These are the building blocks of infinite extensibility.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use async_trait::async_trait;
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use super::{Capability, Metadata, Request, Response, Result};

/// The core plugin trait - what every plugin must implement
/// Factory trait for creating plugin instances
pub trait PluginFactory: Send + Sync {
    /// Create a new plugin instance
    fn create(&self) -> Result<Box<dyn Plugin>>;
}

#[async_trait]
pub trait Plugin: Send + Sync + Any + 'static {
    /// Get plugin metadata
    fn metadata(&self) -> &Metadata;
    
    /// Initialize the plugin with configuration
    async fn initialize(&mut self, config: Value) -> Result<()>;
    
    /// Handle a request
    async fn handle(&self, request: Request) -> Result<Response>;
    
    /// Shutdown the plugin gracefully
    async fn shutdown(&mut self) -> Result<()>;
    
    /// Health check
    async fn health_check(&self) -> Result<bool> {
        Ok(true)
    }
    
    /// Get plugin-specific metrics
    async fn metrics(&self) -> Result<Value> {
        Ok(Value::Object(serde_json::Map::new()))
    }
    
    /// As any for downcasting
    fn as_any(&self) -> &dyn Any;
    
    /// As mutable any for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Trait for plugins that can be discovered dynamically
pub trait Discoverable {
    /// Get discovery metadata
    fn discovery_metadata() -> DiscoveryMetadata;
}

/// Discovery metadata for plugins
#[derive(Debug, Clone)]
pub struct DiscoveryMetadata {
    /// File patterns to match (e.g., "*.so", "*.dll")
    pub file_patterns: Vec<String>,
    
    /// Directories to search
    pub search_paths: Vec<String>,
    
    /// Whether to search recursively
    pub recursive: bool,
    
    /// Excluded patterns
    pub exclude_patterns: Vec<String>,
}

/// Trait for plugins that support hot reload
#[async_trait]
pub trait HotReloadable: {
    /// Check if the plugin can be safely reloaded
    async fn can_reload(&self) -> Result<bool>;
    
    /// Prepare for reload (save state)
    async fn prepare_reload(&self) -> Result<Value>;
    
    /// Restore state after reload
    async fn restore_state(&mut self, state: Value) -> Result<()>;
}

/// Trait for plugins that provide capabilities
pub trait CapabilityProvider {
    /// Get all capabilities this plugin provides
    fn provides(&self) -> &[Capability];
    
    /// Check if a specific capability is provided
    fn has_capability(&self, capability: &Capability) -> bool {
        self.provides().iter().any(|c| c == capability)
    }
    
    /// Get capability version
    fn capability_version(&self, namespace: &str, name: &str) -> Option<u32> {
        self.provides()
            .iter()
            .find(|c| c.namespace == namespace && c.name == name)
            .map(|c| c.version)
    }
}

/// Trait for plugins that depend on other plugins
pub trait DependencyAware {
    /// Get plugin dependencies
    fn dependencies(&self) -> &[Dependency];
    
    /// Called when a dependency is available
    fn on_dependency_available(&mut self, plugin_id: &str, capabilities: &[Capability]);
    
    /// Called when a dependency is removed
    fn on_dependency_removed(&mut self, plugin_id: &str);
}

/// dependency specification
#[derive(Debug, Clone)]
pub struct Dependency {
    /// ID
    pub id: String,
    
    /// Version requirement (semver)
    pub version: String,
    
    /// Required capabilities
    pub required_capabilities: Vec<Capability>,
    
    /// Is this dependency optional?
    pub optional: bool,
}

/// Trait for plugins that can be configured
#[async_trait]
pub trait Configurable {
    /// Get configuration schema
    fn config_schema(&self) -> Result<Value>;
    
    /// Validate configuration
    async fn validate_config(&self, config: &Value) -> Result<Vec<ConfigValidationError>>;
    
    /// Apply configuration changes
    async fn apply_config(&mut self, config: Value) -> Result<()>;
    
    /// Get current configuration
    fn current_config(&self) -> Result<Value>;
}

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    /// Field path (e.g., "server.port")
    pub path: String,
    
    /// Error message
    pub message: String,
    
    /// Severity
    pub severity: ValidationSeverity,
}

/// Validation severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Configuration is invalid and cannot be used
    Error,
    
    /// Configuration is valid but may cause issues
    Warning,
    
    /// Informational message
    Info,
}

/// Trait for plugins that expose metrics
#[async_trait]
pub trait Measurable {
    /// Get metric definitions
    fn metric_definitions(&self) -> Vec<MetricDefinition>;
    
    /// Collect current metrics
    async fn collect_metrics(&self) -> Result<MetricCollection>;
    
    /// Reset metrics
    async fn reset_metrics(&mut self) -> Result<()>;
}

/// Metric definition
#[derive(Debug, Clone)]
pub struct MetricDefinition {
    /// Metric name
    pub name: String,
    
    /// Metric type
    pub metric_type: MetricType,
    
    /// Description
    pub description: String,
    
    /// Labels
    pub labels: Vec<String>,
    
    /// Unit
    pub unit: Option<String>,
}

/// Metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Collection of metrics
#[derive(Debug, Clone)]
pub struct MetricCollection {
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    
    /// Metrics
    pub metrics: HashMap<String, MetricValue>,
}

/// Metric value
#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram { buckets: Vec<(f64, u64)>, sum: f64, count: u64 },
    Summary { quantiles: Vec<(f64, f64)>, sum: f64, count: u64 },
}

/// Trait for plugins that can be sandboxed
#[async_trait]
pub trait Sandboxable: {
    /// Get sandbox requirements
    fn sandbox_requirements(&self) -> SandboxRequirements;
    
    /// Called when entering sandbox
    async fn on_sandbox_enter(&mut self) -> Result<()>;
    
    /// Called when exiting sandbox
    async fn on_sandbox_exit(&mut self) -> Result<()>;
}

/// Sandbox requirements
#[derive(Debug, Clone, Default)]
pub struct SandboxRequirements {
    /// Memory limit in bytes
    pub memory_limit: Option<usize>,
    
    /// CPU time limit in milliseconds
    pub cpu_limit: Option<u64>,
    
    /// Allowed system calls
    pub allowed_syscalls: Vec<String>,
    
    /// Allowed file paths
    pub allowed_paths: Vec<String>,
    
    /// Network access
    pub network_access: bool,
    
    /// Environment variables
    pub env_vars: HashMap<String, String>,
}

/// Trait for plugins that support versioning
pub trait Versioned {
    /// Get plugin version
    fn version(&self) -> &str;
    
    /// Get API version
    fn api_version(&self) -> u32;
    
    /// Check compatibility with another version
    fn is_compatible_with(&self, other_version: &str) -> bool;
    
    /// Get changelog
    fn changelog(&self) -> Option<&str> {
        None
    }
}

/// Trait for plugins that can be extended
#[async_trait]
pub trait Extensible: {
    /// Register an extension
    async fn register_extension(&mut self, extension: Box<dyn Extension>) -> Result<()>;
    
    /// Unregister an extension
    async fn unregister_extension(&mut self, id: &str) -> Result<()>;
    
    /// Get registered extensions
    fn extensions(&self) -> Vec<&dyn Extension>;
}

/// Extension trait
#[async_trait]
pub trait Extension: Send + Sync + 'static {
    /// Extension ID
    fn id(&self) -> &str;
    
    /// Extension capabilities
    fn capabilities(&self) -> &[Capability];
    
    /// Handle request
    async fn handle(&self, request: Request) -> Result<Response>;
}

/// Factory trait for creating plugins
pub trait Factory: Send + Sync + 'static {
    /// Create a new plugin instance
    fn create(&self) -> Result<Box<dyn Plugin>>;
    
    /// Get factory metadata
    fn metadata(&self) -> &Metadata;
}

/// Trait for plugins that support transactions
#[async_trait]
pub trait Transactional: Plugin {
    /// Begin a transaction
    async fn begin_transaction(&mut self) -> Result<TransactionId>;
    
    /// Commit a transaction
    async fn commit_transaction(&mut self, id: TransactionId) -> Result<()>;
    
    /// Rollback a transaction
    async fn rollback_transaction(&mut self, id: TransactionId) -> Result<()>;
    
    /// Get active transactions
    fn active_transactions(&self) -> Vec<TransactionId>;
}

/// Transaction identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(pub String);

/// Trait for plugins that support events
#[async_trait]
pub trait EventEmitter {
    /// Subscribe to events
    async fn subscribe(&mut self, event_type: &str, callback: EventCallback) -> Result<SubscriptionId>;
    
    /// Unsubscribe from events
    async fn unsubscribe(&mut self, id: SubscriptionId) -> Result<()>;
    
    /// Emit an event
    async fn emit(&self, event: Event) -> Result<()>;
}

/// Event callback
pub type EventCallback = Arc<dyn Fn(Event) + Send + Sync>;

/// Subscription identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub String);

/// Event structure
#[derive(Debug, Clone)]
pub struct Event {
    /// Event type
    pub event_type: String,
    
    /// Event source
    pub source: String,
    
    /// Event data
    pub data: Value,
    
    /// Timestamp
    pub timestamp: std::time::SystemTime,
}

/// Trait for plugins that support authentication
#[async_trait]
pub trait Authenticatable {
    /// Authenticate a request
    async fn authenticate(&self, credentials: &Value) -> Result<AuthenticationResult>;
    
    /// Get authentication requirements
    fn auth_requirements(&self) -> AuthRequirements;
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// Whether authentication succeeded
    pub success: bool,
    
    /// User/service identity
    pub identity: Option<String>,
    
    /// Granted permissions
    pub permissions: Vec<String>,
    
    /// Token for future requests
    pub token: Option<String>,
}

/// Authentication requirements
#[derive(Debug, Clone)]
pub struct AuthRequirements {
    /// Required authentication methods
    pub methods: Vec<AuthMethod>,
    
    /// Whether authentication is optional
    pub optional: bool,
}

/// Authentication methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// API key
    ApiKey,
    
    /// Bearer token
    BearerToken,
    
    /// Basic auth
    BasicAuth,
    
    /// OAuth2
    OAuth2,
    
    /// Custom method
    Custom(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_provider() {
        struct TestPlugin {
            capabilities: Vec<Capability>,
        }
        
        impl CapabilityProvider for TestPlugin {
            fn provides(&self) -> &[Capability] {
                &self.capabilities
            }
        }
        
        let plugin = TestPlugin {
            capabilities: vec![
                Capability::new("docker", "container.create", 1),
                Capability::new("docker", "container.list", 1),
            ],
        };
        
        assert!(plugin.has_capability(&Capability::new("docker", "container.create", 1)));
        assert!(!plugin.has_capability(&Capability::new("k8s", "pod.create", 1)));
        assert_eq!(plugin.capability_version("docker", "container.create"), Some(1));
    }
}