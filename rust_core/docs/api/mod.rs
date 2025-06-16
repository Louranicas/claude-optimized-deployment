//! MCP Manager API Documentation
//!
//! Comprehensive API documentation for the MCP Manager plugin system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

#![doc = include_str!("../../README.md")]

/// # MCP Manager Core API
///
/// The MCP Manager provides a comprehensive plugin system for extending functionality
/// in a modular, type-safe, and performant manner.
///
/// ## Core Components
///
/// - **Plugin System**: Trait-based plugin architecture with lifecycle management
/// - **Registry**: Thread-safe plugin registration and discovery
/// - **Hot Reload**: Zero-downtime plugin updates with state preservation
/// - **Version Management**: Semantic versioning with migration support
/// - **State Transfer**: Efficient state migration between plugin versions
/// - **Rollback**: Checkpoint-based recovery system
/// - **Zero-Downtime**: Traffic shifting and health monitoring
///
/// ## Quick Start
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::*;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a plugin registry
/// let registry = Arc::new(tokio::sync::RwLock::new(
///     registry::PluginRegistry::new()
/// ));
///
/// // Load and register a plugin
/// let loader = loader::PluginLoader::new();
/// let plugin = loader.load_plugin("path/to/plugin.so").await?;
/// 
/// registry.write().await.register("my-plugin".to_string(), plugin)?;
///
/// // Use the plugin
/// let plugin = registry.read().await.get("my-plugin").unwrap();
/// let request = PluginRequest {
///     id: "req-1".to_string(),
///     capability: Capability::new("namespace", "action", 1),
///     method: "process".to_string(),
///     params: serde_json::json!({"data": "example"}),
///     metadata: serde_json::json!({}),
/// };
///
/// let response = plugin.handle(request).await?;
/// # Ok(())
/// # }
/// ```
pub mod plugin;

/// # Registry API
///
/// The registry provides thread-safe plugin management with capability-based discovery.
///
/// ## Features
///
/// - Thread-safe plugin storage
/// - Capability-based lookup
/// - Plugin lifecycle management
/// - Event notifications
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::registry::*;
/// # use claude_optimized_deployment_rust::mcp_manager::plugin::*;
/// # use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = PluginRegistry::new();
///
/// // Register a plugin
/// # let plugin = Arc::new(PluginHandle::new(Box::new(MockPlugin)));
/// registry.register("example".to_string(), plugin)?;
///
/// // Find plugins by capability
/// let capability = Capability::new("data", "process", 1);
/// let plugins = registry.find_by_capability(&capability);
///
/// // List all plugins
/// let all_plugins = registry.list_all();
/// # Ok(())
/// # }
/// # struct MockPlugin;
/// # impl Plugin for MockPlugin {
/// #     fn metadata(&self) -> &PluginMetadata { unimplemented!() }
/// #     async fn initialize(&mut self, _: serde_json::Value) -> Result<()> { Ok(()) }
/// #     async fn handle(&self, _: PluginRequest) -> Result<PluginResponse> { unimplemented!() }
/// #     async fn shutdown(&mut self) -> Result<()> { Ok(()) }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// ```
pub mod registry;

/// # Hot Reload API
///
/// Enables zero-downtime plugin updates with automatic state preservation.
///
/// ## Features
///
/// - Graceful plugin replacement
/// - Automatic state transfer
/// - Request queuing during reload
/// - Rollback on failure
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::hot_reload::*;
/// # use claude_optimized_deployment_rust::mcp_manager::plugin::*;
/// # use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let loader = Arc::new(loader::PluginLoader::new());
/// let config = HotReloadConfig::default();
/// let manager = HotReloadManager::new(loader, config);
///
/// // Start the hot reload manager
/// manager.start().await?;
///
/// // Register a plugin for hot reload
/// # let plugin = Arc::new(PluginHandle::new(Box::new(MockPlugin)));
/// manager.register_plugin(
///     "my-plugin".to_string(),
///     plugin,
///     Some("path/to/plugin.so".into()),
/// ).await?;
///
/// // Trigger a reload
/// manager.reload_plugin(
///     "my-plugin",
///     ReloadReason::FileChanged,
///     false, // no force
/// ).await?;
/// # Ok(())
/// # }
/// # struct MockPlugin;
/// # impl Plugin for MockPlugin {
/// #     fn metadata(&self) -> &PluginMetadata { unimplemented!() }
/// #     async fn initialize(&mut self, _: serde_json::Value) -> Result<()> { Ok(()) }
/// #     async fn handle(&self, _: PluginRequest) -> Result<PluginResponse> { unimplemented!() }
/// #     async fn shutdown(&mut self) -> Result<()> { Ok(()) }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// ```
pub mod hot_reload;

/// # State Transfer API
///
/// Provides efficient state migration between plugin versions.
///
/// ## Features
///
/// - Streaming state transfer
/// - Schema validation
/// - Compression support
/// - Progress tracking
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::state_transfer::*;
/// # use std::sync::Arc;
/// # use tokio::sync::RwLock;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = StateTransferConfig::default();
/// let coordinator = StateTransferCoordinator::new(config);
///
/// // Transfer state between plugins
/// # let source: Arc<RwLock<Box<dyn StateTransferable>>> = unimplemented!();
/// # let target: Arc<RwLock<Box<dyn StateTransferable>>> = unimplemented!();
/// let result = coordinator.transfer_state(source, target).await?;
///
/// if result.success {
///     println!("State transferred in {:?}", result.duration);
/// }
/// # Ok(())
/// # }
/// ```
pub mod state_transfer;

/// # Version Management API
///
/// Handles semantic versioning and compatibility checking.
///
/// ## Features
///
/// - Semantic version parsing
/// - Compatibility validation
/// - Migration planning
/// - Version history tracking
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::version::*;
/// use semver::Version;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = VersionConfig::default();
/// let manager = VersionManager::new(config);
///
/// // Parse and validate version
/// let version = manager.parse_version("1.2.3")?;
///
/// // Check compatibility
/// let current = Version::new(1, 0, 0);
/// let target = Version::new(1, 2, 0);
/// let compat = manager.check_compatibility(&current, &target)?;
///
/// if compat.is_compatible {
///     println!("Versions are compatible!");
/// }
/// # Ok(())
/// # }
/// ```
pub mod version;

/// # Rollback API
///
/// Provides checkpoint-based recovery for plugin state.
///
/// ## Features
///
/// - Automatic checkpointing
/// - Manual checkpoint creation
/// - Quick rollback execution
/// - Checkpoint management
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::rollback::*;
/// # use claude_optimized_deployment_rust::mcp_manager::plugin::*;
/// # use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let state_transfer = Arc::new(state_transfer::StateTransferCoordinator::new(Default::default()));
/// # let version_manager = Arc::new(version::VersionManager::new(Default::default()));
/// let config = RollbackConfig::default();
/// let manager = RollbackManager::new(state_transfer, version_manager, config);
///
/// // Create a checkpoint
/// # let plugin = Arc::new(PluginHandle::new(Box::new(MockPlugin)));
/// # let state = state_transfer::StateSnapshot::default();
/// let checkpoint = manager.create_checkpoint(
///     "my-plugin",
///     plugin,
///     state,
///     CheckpointType::Manual,
///     "Before major update",
/// ).await?;
///
/// // Later, rollback if needed
/// let result = manager.rollback_to_checkpoint("my-plugin", &checkpoint.id).await?;
/// # Ok(())
/// # }
/// # struct MockPlugin;
/// # impl Plugin for MockPlugin {
/// #     fn metadata(&self) -> &PluginMetadata { unimplemented!() }
/// #     async fn initialize(&mut self, _: serde_json::Value) -> Result<()> { Ok(()) }
/// #     async fn handle(&self, _: PluginRequest) -> Result<PluginResponse> { unimplemented!() }
/// #     async fn shutdown(&mut self) -> Result<()> { Ok(()) }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// ```
pub mod rollback;

/// # Zero-Downtime API
///
/// Enables seamless plugin updates without service interruption.
///
/// ## Features
///
/// - Traffic shifting strategies
/// - Health monitoring
/// - Automatic rollback
/// - Performance metrics
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::zero_downtime::*;
/// # use claude_optimized_deployment_rust::mcp_manager::plugin::*;
/// # use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let hot_reload = Arc::new(hot_reload::HotReloadManager::new(
/// #     Arc::new(loader::PluginLoader::new()),
/// #     Default::default()
/// # ));
/// # let rollback = Arc::new(rollback::RollbackManager::new(
/// #     Arc::new(state_transfer::StateTransferCoordinator::new(Default::default())),
/// #     Arc::new(version::VersionManager::new(Default::default())),
/// #     Default::default()
/// # ));
/// # let state_transfer = Arc::new(state_transfer::StateTransferCoordinator::new(Default::default()));
/// let config = ZeroDowntimeConfig::default();
/// let coordinator = ZeroDowntimeCoordinator::new(
///     hot_reload,
///     rollback,
///     state_transfer,
///     config,
/// );
///
/// // Perform zero-downtime update
/// # let new_plugin = Arc::new(PluginHandle::new(Box::new(MockPlugin)));
/// let plan = UpdatePlan {
///     plugin_id: "my-plugin".to_string(),
///     new_version: semver::Version::new(2, 0, 0),
///     strategy: UpdateStrategy::BlueGreen,
///     # new_plugin,
///     # validation_period: std::time::Duration::from_secs(60),
///     # rollback_on_error: true,
///     # health_check_config: None,
/// };
///
/// let result = coordinator.execute_update(plan).await?;
/// # Ok(())
/// # }
/// # struct MockPlugin;
/// # impl Plugin for MockPlugin {
/// #     fn metadata(&self) -> &PluginMetadata { unimplemented!() }
/// #     async fn initialize(&mut self, _: serde_json::Value) -> Result<()> { Ok(()) }
/// #     async fn handle(&self, _: PluginRequest) -> Result<PluginResponse> { unimplemented!() }
/// #     async fn shutdown(&mut self) -> Result<()> { Ok(()) }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// ```
pub mod zero_downtime;

/// # Configuration API
///
/// Provides comprehensive configuration management for all components.
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::config::*;
///
/// # fn example() {
/// // Load configuration from environment
/// let config = PluginSystemConfig::from_env();
///
/// // Or create custom configuration
/// let config = PluginSystemConfig {
///     registry: RegistryConfig {
///         max_plugins: 1000,
///         enable_metrics: true,
///         # ..Default::default()
///     },
///     hot_reload: hot_reload::HotReloadConfig {
///         enabled: true,
///         watch_interval_ms: 1000,
///         # ..Default::default()
///     },
///     # ..Default::default()
/// };
/// # }
/// ```
pub mod config;

/// # Error Handling
///
/// Comprehensive error types for all plugin system operations.
///
/// ## Error Categories
///
/// - `PluginError`: General plugin operation errors
/// - `RegistryError`: Registry-specific errors
/// - `StateTransferError`: State migration errors
/// - `VersionError`: Version compatibility errors
/// - `RollbackError`: Checkpoint/rollback errors
///
/// ## Example
///
/// ```rust
/// use claude_optimized_deployment_rust::mcp_manager::plugin::{Result, PluginError};
///
/// fn process_plugin() -> Result<()> {
///     // Simulate an error
///     Err(PluginError::NotFound("plugin-id".to_string()))?
/// }
///
/// match process_plugin() {
///     Ok(_) => println!("Success!"),
///     Err(PluginError::NotFound(id)) => {
///         eprintln!("Plugin not found: {}", id);
///     }
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub mod errors {
    pub use super::plugin::{Result, PluginError};
}

/// # Best Practices
///
/// ## Plugin Development
///
/// 1. **Implement all trait methods**: Ensure your plugin properly implements
///    initialize, handle, shutdown, and as_any methods.
///
/// 2. **Handle errors gracefully**: Return appropriate errors rather than panicking.
///
/// 3. **Make plugins stateless when possible**: Use external storage for persistent state.
///
/// 4. **Version your plugins**: Use semantic versioning for compatibility.
///
/// ## Performance Optimization
///
/// 1. **Use async operations**: Leverage Tokio for concurrent request handling.
///
/// 2. **Implement caching**: Cache frequently accessed data within reason.
///
/// 3. **Monitor metrics**: Use the built-in metrics to track performance.
///
/// 4. **Profile regularly**: Use the benchmark suite to identify bottlenecks.
///
/// ## Security Considerations
///
/// 1. **Validate inputs**: Always validate plugin request parameters.
///
/// 2. **Use capability-based security**: Define and check capabilities properly.
///
/// 3. **Sandbox plugins**: Run plugins with minimal required permissions.
///
/// 4. **Audit plugin code**: Review third-party plugins before deployment.
pub mod best_practices {}