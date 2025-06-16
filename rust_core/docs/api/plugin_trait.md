# Plugin Trait API Reference

The `Plugin` trait is the core interface that all MCP Manager plugins must implement.

## Trait Definition

```rust
#[async_trait]
pub trait Plugin: Send + Sync + std::fmt::Debug + 'static {
    /// Returns metadata about the plugin
    fn metadata(&self) -> &PluginMetadata;
    
    /// Initialize the plugin with configuration
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()>;
    
    /// Handle a plugin request
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse>;
    
    /// Shutdown the plugin gracefully
    async fn shutdown(&mut self) -> Result<()>;
    
    /// Get plugin as Any for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}
```

## Required Methods

### `metadata(&self) -> &PluginMetadata`

Returns immutable reference to the plugin's metadata.

**Example:**
```rust
fn metadata(&self) -> &PluginMetadata {
    &self.metadata
}
```

### `initialize(&mut self, config: serde_json::Value) -> Result<()>`

Initializes the plugin with the provided configuration. This method is called once when the plugin is loaded.

**Parameters:**
- `config`: JSON configuration object

**Returns:**
- `Ok(())` on successful initialization
- `Err(PluginError)` on failure

**Example:**
```rust
async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
    self.api_key = config.get("api_key")
        .and_then(|v| v.as_str())
        .ok_or(PluginError::Configuration("api_key required".into()))?
        .to_string();
    
    self.client = HttpClient::new(&self.api_key)?;
    Ok(())
}
```

### `handle(&self, request: PluginRequest) -> Result<PluginResponse>`

Processes a plugin request and returns a response.

**Parameters:**
- `request`: The incoming plugin request

**Returns:**
- `Ok(PluginResponse)` with the result
- `Err(PluginError)` on failure

**Example:**
```rust
async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
    match request.method.as_str() {
        "process" => {
            let data = request.params.get("data")
                .ok_or(PluginError::InvalidRequest("data required".into()))?;
            
            let result = self.process_data(data).await?;
            
            Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success { data: result },
                metadata: serde_json::json!({}),
            })
        }
        _ => Err(PluginError::MethodNotFound(request.method)),
    }
}
```

### `shutdown(&mut self) -> Result<()>`

Performs cleanup when the plugin is being unloaded.

**Returns:**
- `Ok(())` on successful shutdown
- `Err(PluginError)` on failure

**Example:**
```rust
async fn shutdown(&mut self) -> Result<()> {
    // Close connections
    if let Some(client) = self.client.take() {
        client.close().await?;
    }
    
    // Save state if needed
    self.save_state().await?;
    
    Ok(())
}
```

### `as_any(&self) -> &dyn std::any::Any`

Returns the plugin as a trait object for downcasting.

**Example:**
```rust
fn as_any(&self) -> &dyn std::any::Any {
    self
}
```

## Associated Types

### `PluginMetadata`

Contains information about the plugin:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub id: String,              // Unique identifier
    pub name: String,            // Human-readable name
    pub version: String,         // Semantic version
    pub author: String,          // Plugin author
    pub description: String,     // Plugin description
    pub license: String,         // License identifier
    pub homepage: Option<String>,     // Project homepage
    pub repository: Option<String>,   // Source repository
    pub min_mcp_version: String,      // Minimum MCP version required
    pub dependencies: Vec<Dependency>, // Plugin dependencies
    pub provides: Vec<Capability>,    // Capabilities provided
    pub requires: Vec<Capability>,    // Capabilities required
}
```

### `PluginRequest`

Request sent to a plugin:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    pub id: String,              // Unique request ID
    pub capability: Capability,  // Target capability
    pub method: String,          // Method to invoke
    pub params: serde_json::Value, // Method parameters
    pub metadata: serde_json::Value, // Request metadata
}
```

### `PluginResponse`

Response from a plugin:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResponse {
    pub request_id: String,      // ID of the original request
    pub result: PluginResult,    // Result of the operation
    pub metadata: serde_json::Value, // Response metadata
}
```

### `PluginResult`

Result of a plugin operation:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginResult {
    Success { data: serde_json::Value },
    Error { code: String, message: String, details: Option<serde_json::Value> },
}
```

## Implementation Guidelines

1. **Thread Safety**: Plugins must be `Send + Sync` for concurrent use.

2. **Error Handling**: Return appropriate errors rather than panicking.

3. **Async Operations**: Use async/await for I/O operations.

4. **State Management**: Keep mutable state behind appropriate synchronization primitives.

5. **Resource Cleanup**: Always implement proper cleanup in `shutdown()`.

## Complete Example

```rust
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
struct ExamplePlugin {
    metadata: PluginMetadata,
    config: Arc<RwLock<Config>>,
    client: Option<HttpClient>,
}

#[derive(Debug)]
struct Config {
    api_key: String,
    timeout_ms: u64,
}

#[async_trait]
impl Plugin for ExamplePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        let api_key = config.get("api_key")
            .and_then(|v| v.as_str())
            .ok_or(PluginError::Configuration("api_key required".into()))?;
        
        let timeout_ms = config.get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(5000);
        
        *self.config.write().await = Config {
            api_key: api_key.to_string(),
            timeout_ms,
        };
        
        self.client = Some(HttpClient::new(api_key, timeout_ms)?);
        
        Ok(())
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let client = self.client.as_ref()
            .ok_or(PluginError::NotInitialized)?;
        
        match request.method.as_str() {
            "fetch" => {
                let url = request.params.get("url")
                    .and_then(|v| v.as_str())
                    .ok_or(PluginError::InvalidRequest("url required".into()))?;
                
                let data = client.get(url).await?;
                
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success { data },
                    metadata: json!({
                        "timestamp": chrono::Utc::now().timestamp(),
                    }),
                })
            }
            _ => Err(PluginError::MethodNotFound(request.method)),
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        if let Some(client) = self.client.take() {
            client.close().await?;
        }
        Ok(())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
```