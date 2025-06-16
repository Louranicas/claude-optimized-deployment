# Building Your First MCP Manager Plugin

This tutorial walks you through creating your first plugin for the MCP Manager system.

## Prerequisites

- Rust 1.70+ installed
- Basic knowledge of Rust and async programming
- Familiarity with JSON and error handling

## Project Setup

### 1. Create a New Rust Project

```bash
cargo new --lib my-first-plugin
cd my-first-plugin
```

### 2. Add Dependencies

Edit `Cargo.toml`:

```toml
[package]
name = "my-first-plugin"
version = "0.1.0"
edition = "2021"

[dependencies]
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
claude-optimized-deployment-rust = { path = "../rust_core" }
chrono = "0.4"
uuid = { version = "1.0", features = ["v4"] }
tracing = "0.1"

[lib]
crate-type = ["cdylib", "rlib"]
```

## Step 1: Define Your Plugin Structure

Create `src/lib.rs`:

```rust
use async_trait::async_trait;
use claude_optimized_deployment_rust::mcp_manager::plugin::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Our plugin's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginConfig {
    api_key: String,
    endpoint: String,
    timeout_ms: u64,
    max_retries: u32,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            endpoint: "https://api.example.com".to_string(),
            timeout_ms: 5000,
            max_retries: 3,
        }
    }
}

/// Our plugin's internal state
#[derive(Debug)]
struct PluginState {
    config: PluginConfig,
    request_count: u64,
    last_error: Option<String>,
}

/// The main plugin structure
#[derive(Debug)]
pub struct MyFirstPlugin {
    metadata: PluginMetadata,
    state: Arc<RwLock<PluginState>>,
}

impl MyFirstPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                id: "my-first-plugin".to_string(),
                name: "My First Plugin".to_string(),
                version: "0.1.0".to_string(),
                author: "Your Name".to_string(),
                description: "A simple example plugin".to_string(),
                license: "MIT".to_string(),
                homepage: Some("https://example.com".to_string()),
                repository: Some("https://github.com/example/my-first-plugin".to_string()),
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("example", "hello", 1),
                    Capability::new("example", "echo", 1),
                    Capability::new("example", "stats", 1),
                ],
                requires: vec![],
            },
            state: Arc::new(RwLock::new(PluginState {
                config: PluginConfig::default(),
                request_count: 0,
                last_error: None,
            })),
        }
    }
}
```

## Step 2: Implement the Plugin Trait

```rust
#[async_trait]
impl Plugin for MyFirstPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        info!("Initializing {} v{}", self.metadata.name, self.metadata.version);
        
        // Parse configuration
        let plugin_config: PluginConfig = serde_json::from_value(config)
            .map_err(|e| PluginError::Configuration(format!("Invalid config: {}", e)))?;
        
        // Validate configuration
        if plugin_config.api_key.is_empty() {
            return Err(PluginError::Configuration("API key is required".to_string()));
        }
        
        // Update state
        let mut state = self.state.write().await;
        state.config = plugin_config;
        
        info!("Plugin initialized successfully");
        Ok(())
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Update request count
        {
            let mut state = self.state.write().await;
            state.request_count += 1;
        }
        
        info!("Handling request: {} (method: {})", request.id, request.method);
        
        // Route based on capability and method
        let result = match (request.capability.name.as_str(), request.method.as_str()) {
            ("hello", "greet") => self.handle_greet(request).await,
            ("echo", "echo") => self.handle_echo(request).await,
            ("stats", "get") => self.handle_stats(request).await,
            _ => Err(PluginError::MethodNotFound(request.method.clone())),
        };
        
        // Track errors
        if let Err(ref e) = result {
            let mut state = self.state.write().await;
            state.last_error = Some(e.to_string());
            error!("Request {} failed: {}", request.id, e);
        }
        
        result
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down {}", self.metadata.name);
        
        // Perform cleanup
        let state = self.state.read().await;
        info!("Processed {} requests during lifetime", state.request_count);
        
        Ok(())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
```

## Step 3: Implement Request Handlers

```rust
impl MyFirstPlugin {
    async fn handle_greet(&self, request: PluginRequest) -> Result<PluginResponse> {
        let name = request.params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("World");
        
        let greeting = format!("Hello, {}!", name);
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: serde_json::json!({
                    "greeting": greeting,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                }),
            },
            metadata: serde_json::json!({
                "plugin_version": self.metadata.version,
            }),
        })
    }
    
    async fn handle_echo(&self, request: PluginRequest) -> Result<PluginResponse> {
        let message = request.params
            .get("message")
            .ok_or_else(|| PluginError::InvalidRequest("message parameter required".to_string()))?;
        
        // Simulate some processing delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: serde_json::json!({
                    "echo": message,
                    "processed_at": chrono::Utc::now().to_rfc3339(),
                }),
            },
            metadata: serde_json::json!({}),
        })
    }
    
    async fn handle_stats(&self, request: PluginRequest) -> Result<PluginResponse> {
        let state = self.state.read().await;
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: serde_json::json!({
                    "request_count": state.request_count,
                    "last_error": state.last_error,
                    "config": {
                        "endpoint": state.config.endpoint,
                        "timeout_ms": state.config.timeout_ms,
                    },
                }),
            },
            metadata: serde_json::json!({}),
        })
    }
}
```

## Step 4: Add State Transfer Support (Optional)

```rust
#[async_trait]
impl StateTransferable for MyFirstPlugin {
    async fn export_state(&self) -> Result<StateSnapshot> {
        let state = self.state.read().await;
        
        let mut sections = std::collections::HashMap::new();
        
        // Export configuration
        sections.insert("config".to_string(), StateSection {
            name: "config".to_string(),
            schema_version: 1,
            data: serde_json::to_vec(&state.config)
                .map_err(|e| PluginError::StateSerialization(e.to_string()))?,
            compressed: false,
            encryption: None,
            metadata: std::collections::HashMap::new(),
        });
        
        // Export statistics
        sections.insert("stats".to_string(), StateSection {
            name: "stats".to_string(),
            schema_version: 1,
            data: serde_json::to_vec(&serde_json::json!({
                "request_count": state.request_count,
                "last_error": state.last_error,
            })).map_err(|e| PluginError::StateSerialization(e.to_string()))?,
            compressed: false,
            encryption: None,
            metadata: std::collections::HashMap::new(),
        });
        
        Ok(StateSnapshot {
            id: uuid::Uuid::new_v4().to_string(),
            plugin_id: self.metadata.id.clone(),
            plugin_version: self.metadata.version.clone(),
            schema_version: 1,
            timestamp: chrono::Utc::now().timestamp(),
            sections,
            metadata: StateMetadata {
                reason: StateCreationReason::Export,
                created_by: "plugin".to_string(),
                tags: vec![],
                expires_at: None,
                custom: std::collections::HashMap::new(),
            },
            checksum: "placeholder".to_string(), // In practice, calculate real checksum
        })
    }
    
    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        let mut state = self.state.write().await;
        let mut imported_sections = Vec::new();
        let mut failed_sections = Vec::new();
        
        // Import configuration
        if let Some(config_section) = snapshot.sections.get("config") {
            match serde_json::from_slice::<PluginConfig>(&config_section.data) {
                Ok(config) => {
                    state.config = config;
                    imported_sections.push("config".to_string());
                }
                Err(e) => {
                    failed_sections.push(FailedSection {
                        name: "config".to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        // Import statistics
        if let Some(stats_section) = snapshot.sections.get("stats") {
            match serde_json::from_slice::<serde_json::Value>(&stats_section.data) {
                Ok(stats) => {
                    if let Some(count) = stats.get("request_count").and_then(|v| v.as_u64()) {
                        state.request_count = count;
                    }
                    if let Some(error) = stats.get("last_error").and_then(|v| v.as_str()) {
                        state.last_error = Some(error.to_string());
                    }
                    imported_sections.push("stats".to_string());
                }
                Err(e) => {
                    failed_sections.push(FailedSection {
                        name: "stats".to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        Ok(StateImportResult {
            imported_sections,
            failed_sections,
            warnings: vec![],
            duration: std::time::Duration::from_millis(1),
        })
    }
    
    async fn validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation> {
        Ok(StateValidation {
            is_valid: snapshot.plugin_id == self.metadata.id,
            schema_compatible: snapshot.schema_version <= 1,
            version_compatible: true,
            section_validations: std::collections::HashMap::new(),
            compatibility_score: 1.0,
        })
    }
    
    fn state_schema_version(&self) -> u32 {
        1
    }
}
```

## Step 5: Export Plugin Constructor

```rust
/// Export the plugin constructor for dynamic loading
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    let plugin = MyFirstPlugin::new();
    Box::into_raw(Box::new(plugin) as Box<dyn Plugin>)
}
```

## Step 6: Testing Your Plugin

Create `tests/plugin_test.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use claude_optimized_deployment_rust::mcp_manager::plugin::*;
    
    #[tokio::test]
    async fn test_plugin_initialization() {
        let mut plugin = MyFirstPlugin::new();
        
        let config = serde_json::json!({
            "api_key": "test-key",
            "endpoint": "https://test.example.com",
            "timeout_ms": 3000,
            "max_retries": 5
        });
        
        let result = plugin.initialize(config).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_greet_handler() {
        let mut plugin = MyFirstPlugin::new();
        
        // Initialize first
        let config = serde_json::json!({ "api_key": "test" });
        plugin.initialize(config).await.unwrap();
        
        // Test greet
        let request = PluginRequest {
            id: "test-1".to_string(),
            capability: Capability::new("example", "hello", 1),
            method: "greet".to_string(),
            params: serde_json::json!({ "name": "Alice" }),
            metadata: serde_json::json!({}),
        };
        
        let response = plugin.handle(request).await.unwrap();
        
        match response.result {
            PluginResult::Success { data } => {
                assert_eq!(data["greeting"], "Hello, Alice!");
            }
            _ => panic!("Expected success result"),
        }
    }
    
    #[tokio::test]
    async fn test_state_transfer() {
        let mut plugin = MyFirstPlugin::new();
        
        // Initialize and make some requests
        let config = serde_json::json!({ "api_key": "test" });
        plugin.initialize(config).await.unwrap();
        
        // Make a request to update state
        let request = PluginRequest {
            id: "test-2".to_string(),
            capability: Capability::new("example", "hello", 1),
            method: "greet".to_string(),
            params: serde_json::json!({}),
            metadata: serde_json::json!({}),
        };
        plugin.handle(request).await.unwrap();
        
        // Export state
        let snapshot = plugin.export_state().await.unwrap();
        assert_eq!(snapshot.sections.len(), 2);
        
        // Create new plugin and import state
        let mut new_plugin = MyFirstPlugin::new();
        let result = new_plugin.import_state(snapshot).await.unwrap();
        assert_eq!(result.imported_sections.len(), 2);
    }
}
```

## Step 7: Building and Deploying

### Build the Plugin

```bash
cargo build --release
```

### Create a Plugin Package

Create `plugin.json`:

```json
{
    "id": "my-first-plugin",
    "name": "My First Plugin",
    "version": "0.1.0",
    "library": "target/release/libmy_first_plugin.so",
    "configuration": {
        "schema": {
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "API key for authentication"
                },
                "endpoint": {
                    "type": "string",
                    "format": "uri",
                    "default": "https://api.example.com"
                },
                "timeout_ms": {
                    "type": "integer",
                    "minimum": 100,
                    "default": 5000
                },
                "max_retries": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 3
                }
            },
            "required": ["api_key"]
        }
    }
}
```

### Deploy to MCP Manager

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create plugin loader
    let loader = PluginLoader::new();
    
    // Load the plugin
    let plugin = loader.load_plugin("target/release/libmy_first_plugin.so").await?;
    
    // Register with registry
    let registry = Arc::new(RwLock::new(PluginRegistry::new()));
    registry.write().await.register("my-first-plugin".to_string(), plugin)?;
    
    // Plugin is now ready to use!
    println!("Plugin deployed successfully!");
    
    Ok(())
}
```

## Best Practices

### 1. Error Handling

Always provide meaningful error messages:

```rust
fn validate_request(params: &serde_json::Value) -> Result<String> {
    params.get("required_field")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::InvalidRequest(
            "Missing required field 'required_field'".to_string()
        ))
        .map(|s| s.to_string())
}
```

### 2. Logging

Use structured logging for debugging:

```rust
use tracing::{info, debug, warn, error, instrument};

#[instrument(skip(self))]
async fn handle_complex_operation(&self, data: &str) -> Result<String> {
    debug!("Starting complex operation");
    
    let result = match self.process_data(data).await {
        Ok(processed) => {
            info!("Successfully processed {} bytes", processed.len());
            processed
        }
        Err(e) => {
            error!("Processing failed: {}", e);
            return Err(e);
        }
    };
    
    Ok(result)
}
```

### 3. Resource Management

Clean up resources properly:

```rust
struct ResourceManager {
    connections: Vec<Connection>,
}

impl Drop for ResourceManager {
    fn drop(&mut self) {
        for conn in &mut self.connections {
            if let Err(e) = conn.close() {
                error!("Failed to close connection: {}", e);
            }
        }
    }
}
```

### 4. Configuration Validation

Validate configuration thoroughly:

```rust
impl PluginConfig {
    fn validate(&self) -> Result<()> {
        if self.api_key.is_empty() {
            return Err(PluginError::Configuration("API key cannot be empty".into()));
        }
        
        if self.timeout_ms < 100 {
            return Err(PluginError::Configuration("Timeout must be at least 100ms".into()));
        }
        
        if !self.endpoint.starts_with("https://") {
            warn!("Using non-HTTPS endpoint: {}", self.endpoint);
        }
        
        Ok(())
    }
}
```

## Next Steps

1. **Add more capabilities**: Extend your plugin with additional functionality
2. **Implement caching**: Add caching for improved performance
3. **Add metrics**: Implement performance metrics and monitoring
4. **Create integration tests**: Test your plugin with the full MCP Manager
5. **Document your API**: Create comprehensive documentation for users

## Troubleshooting

### Common Issues

1. **Plugin fails to load**
   - Check that all dependencies are available
   - Verify the plugin exports the correct symbols
   - Check logs for detailed error messages

2. **State transfer fails**
   - Ensure schema versions are compatible
   - Validate serialization format
   - Check for breaking changes in state structure

3. **Performance issues**
   - Profile your plugin code
   - Implement caching where appropriate
   - Use async operations for I/O

### Getting Help

- Check the API documentation
- Review example plugins in the repository
- Ask questions in the community forums
- File issues on GitHub