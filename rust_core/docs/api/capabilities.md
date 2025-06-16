# Capabilities API Reference

Capabilities define what functionality a plugin provides and requires, enabling dynamic discovery and dependency resolution.

## Capability Structure

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    pub namespace: String,
    pub name: String,
    pub version: u32,
}
```

## Creating Capabilities

### Basic Creation

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::Capability;

// Create a capability
let cap = Capability::new("data", "process", 1);

// From string notation
let cap = Capability::from_str("data:process:1")?;

// Using builder pattern
let cap = Capability::builder()
    .namespace("data")
    .name("process")
    .version(1)
    .build()?;
```

### Capability Naming Conventions

1. **Namespace**: Broad category of functionality
   - `data` - Data processing capabilities
   - `network` - Network operations
   - `storage` - Storage operations
   - `compute` - Computational tasks
   - `monitoring` - Monitoring and metrics
   - `security` - Security operations

2. **Name**: Specific functionality within namespace
   - `data:transform` - Data transformation
   - `network:http` - HTTP operations
   - `storage:s3` - S3 storage operations
   - `compute:gpu` - GPU computation
   - `monitoring:metrics` - Metrics collection
   - `security:auth` - Authentication

3. **Version**: Capability API version (starts at 1)

## Capability Matching

### Exact Matching

```rust
let required = Capability::new("data", "process", 1);
let provided = Capability::new("data", "process", 1);

assert!(provided.matches(&required));
```

### Version Compatibility

```rust
impl Capability {
    /// Check if this capability satisfies the requirement
    pub fn satisfies(&self, required: &Capability) -> bool {
        self.namespace == required.namespace &&
        self.name == required.name &&
        self.version >= required.version
    }
}

// Example
let provided = Capability::new("data", "process", 2);
let required = Capability::new("data", "process", 1);

assert!(provided.satisfies(&required)); // v2 satisfies v1 requirement
```

### Pattern Matching

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::CapabilityPattern;

// Match any version
let pattern = CapabilityPattern::new("data", "process", None);
assert!(pattern.matches(&Capability::new("data", "process", 1)));
assert!(pattern.matches(&Capability::new("data", "process", 2)));

// Match specific version or higher
let pattern = CapabilityPattern::new("data", "process", Some(2));
assert!(!pattern.matches(&Capability::new("data", "process", 1)));
assert!(pattern.matches(&Capability::new("data", "process", 2)));
assert!(pattern.matches(&Capability::new("data", "process", 3)));

// Wildcard matching
let pattern = CapabilityPattern::from_str("data:*:1")?;
assert!(pattern.matches(&Capability::new("data", "process", 1)));
assert!(pattern.matches(&Capability::new("data", "transform", 1)));
```

## Capability Sets

### Managing Multiple Capabilities

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::CapabilitySet;

let mut capabilities = CapabilitySet::new();

// Add capabilities
capabilities.add(Capability::new("data", "process", 1));
capabilities.add(Capability::new("data", "transform", 1));
capabilities.add(Capability::new("network", "http", 2));

// Check if set provides a capability
let required = Capability::new("data", "process", 1);
assert!(capabilities.provides(&required));

// Check if set satisfies all requirements
let requirements = vec![
    Capability::new("data", "process", 1),
    Capability::new("network", "http", 1),
];
assert!(capabilities.satisfies_all(&requirements));

// Find capabilities by namespace
let data_caps = capabilities.by_namespace("data");
assert_eq!(data_caps.len(), 2);
```

### Capability Dependencies

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub capability: Capability,
    pub optional: bool,
}

impl Dependency {
    pub fn required(capability: Capability) -> Self {
        Self { capability, optional: false }
    }
    
    pub fn optional(capability: Capability) -> Self {
        Self { capability, optional: true }
    }
}

// In plugin metadata
let metadata = PluginMetadata {
    // ... other fields ...
    provides: vec![
        Capability::new("ml", "inference", 1),
        Capability::new("ml", "training", 1),
    ],
    requires: vec![
        Capability::new("compute", "gpu", 1),
        Capability::new("storage", "large", 1),
    ],
    dependencies: vec![
        Dependency::required(Capability::new("data", "process", 2)),
        Dependency::optional(Capability::new("monitoring", "metrics", 1)),
    ],
};
```

## Capability Discovery

### Registry-Based Discovery

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::registry::PluginRegistry;

let registry = PluginRegistry::new();

// Find all plugins providing a capability
let capability = Capability::new("data", "process", 1);
let plugins = registry.find_by_capability(&capability);

// Find plugins matching a pattern
let pattern = CapabilityPattern::from_str("network:*:*")?;
let network_plugins = registry.find_by_pattern(&pattern);

// Find plugin with best version match
let best_match = registry.find_best_match(&capability);
```

### Dynamic Capability Resolution

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::CapabilityResolver;

let resolver = CapabilityResolver::new(registry);

// Resolve a single capability
let capability = Capability::new("storage", "s3", 1);
match resolver.resolve(&capability).await? {
    Some(plugin) => {
        println!("Found plugin: {}", plugin.metadata().id);
    }
    None => {
        println!("No plugin provides {:?}", capability);
    }
}

// Resolve multiple capabilities
let required = vec![
    Capability::new("data", "process", 1),
    Capability::new("storage", "s3", 1),
    Capability::new("network", "http", 2),
];

let resolution = resolver.resolve_all(&required).await?;
match resolution {
    ResolutionResult::Complete(plugins) => {
        println!("All capabilities resolved!");
        for (cap, plugin) in plugins {
            println!("{:?} -> {}", cap, plugin.metadata().id);
        }
    }
    ResolutionResult::Partial(resolved, missing) => {
        println!("Missing capabilities: {:?}", missing);
    }
}
```

## Capability Negotiation

### Protocol Negotiation

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::CapabilityNegotiator;

// Client announces capabilities
let client_caps = vec![
    Capability::new("protocol", "http", 2),
    Capability::new("protocol", "grpc", 1),
    Capability::new("encoding", "json", 1),
    Capability::new("encoding", "protobuf", 1),
];

// Server announces capabilities
let server_caps = vec![
    Capability::new("protocol", "http", 3),
    Capability::new("protocol", "websocket", 1),
    Capability::new("encoding", "json", 1),
    Capability::new("encoding", "msgpack", 1),
];

// Negotiate common capabilities
let negotiator = CapabilityNegotiator::new();
let agreement = negotiator.negotiate(&client_caps, &server_caps)?;

// Result: protocol:http:2, encoding:json:1
```

### Feature Detection

```rust
impl Plugin {
    /// Check if plugin supports a feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match feature {
            "streaming" => self.has_capability("data", "stream", 1),
            "batch" => self.has_capability("data", "batch", 1),
            "async" => self.has_capability("compute", "async", 1),
            _ => false,
        }
    }
    
    /// Get feature level
    pub fn feature_level(&self, feature: &str) -> Option<u32> {
        self.metadata.provides.iter()
            .find(|cap| cap.namespace == "feature" && cap.name == feature)
            .map(|cap| cap.version)
    }
}
```

## Standard Capabilities

### Core Capabilities

```rust
pub mod standard {
    use super::Capability;
    
    // Lifecycle capabilities
    pub const LIFECYCLE_INIT: Capability = Capability::new("lifecycle", "init", 1);
    pub const LIFECYCLE_START: Capability = Capability::new("lifecycle", "start", 1);
    pub const LIFECYCLE_STOP: Capability = Capability::new("lifecycle", "stop", 1);
    pub const LIFECYCLE_RELOAD: Capability = Capability::new("lifecycle", "reload", 1);
    
    // State management capabilities
    pub const STATE_EXPORT: Capability = Capability::new("state", "export", 1);
    pub const STATE_IMPORT: Capability = Capability::new("state", "import", 1);
    pub const STATE_TRANSFER: Capability = Capability::new("state", "transfer", 1);
    
    // Monitoring capabilities
    pub const MONITOR_METRICS: Capability = Capability::new("monitor", "metrics", 1);
    pub const MONITOR_HEALTH: Capability = Capability::new("monitor", "health", 1);
    pub const MONITOR_TRACE: Capability = Capability::new("monitor", "trace", 1);
    
    // Data processing capabilities
    pub const DATA_TRANSFORM: Capability = Capability::new("data", "transform", 1);
    pub const DATA_VALIDATE: Capability = Capability::new("data", "validate", 1);
    pub const DATA_STREAM: Capability = Capability::new("data", "stream", 1);
    pub const DATA_BATCH: Capability = Capability::new("data", "batch", 1);
}
```

## Best Practices

### 1. Capability Design

- Use hierarchical namespaces for organization
- Keep capability names concise and descriptive
- Version capabilities independently
- Document capability contracts

### 2. Version Management

- Start versions at 1, not 0
- Increment version for breaking changes
- Maintain backward compatibility when possible
- Document version differences

### 3. Dependency Declaration

- Declare minimal required versions
- Use optional dependencies when appropriate
- Test with different capability versions
- Handle missing optional capabilities gracefully

### 4. Discovery Patterns

- Cache capability lookups for performance
- Implement fallback strategies
- Handle capability resolution failures
- Monitor capability usage

## Example: Complete Plugin with Capabilities

```rust
use async_trait::async_trait;
use claude_optimized_deployment_rust::mcp_manager::plugin::*;

#[derive(Debug)]
struct DataProcessor {
    metadata: PluginMetadata,
}

impl DataProcessor {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                id: "data-processor".to_string(),
                name: "Advanced Data Processor".to_string(),
                version: "2.0.0".to_string(),
                author: "Example Corp".to_string(),
                description: "Processes data with ML capabilities".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![
                    Dependency::required(Capability::new("compute", "cpu", 1)),
                    Dependency::optional(Capability::new("compute", "gpu", 1)),
                ],
                provides: vec![
                    // Data processing
                    Capability::new("data", "transform", 2),
                    Capability::new("data", "validate", 1),
                    Capability::new("data", "stream", 1),
                    Capability::new("data", "batch", 1),
                    
                    // ML capabilities
                    Capability::new("ml", "inference", 1),
                    Capability::new("ml", "preprocess", 1),
                    
                    // Format support
                    Capability::new("format", "json", 1),
                    Capability::new("format", "csv", 1),
                    Capability::new("format", "parquet", 1),
                ],
                requires: vec![
                    // Required infrastructure
                    Capability::new("storage", "temp", 1),
                    Capability::new("memory", "large", 1),
                ],
            },
        }
    }
    
    fn check_gpu_available(&self) -> bool {
        // Check if optional GPU capability is available
        // In practice, this would check with the capability resolver
        false
    }
}

#[async_trait]
impl Plugin for DataProcessor {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Route based on capability
        match (request.capability.namespace.as_str(), request.capability.name.as_str()) {
            ("data", "transform") => self.handle_transform(request).await,
            ("data", "validate") => self.handle_validate(request).await,
            ("ml", "inference") => self.handle_inference(request).await,
            _ => Err(PluginError::CapabilityNotSupported(request.capability)),
        }
    }
    
    // ... other trait methods ...
}

impl DataProcessor {
    async fn handle_transform(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Implementation based on capability version
        match request.capability.version {
            1 => self.transform_v1(request).await,
            2 => self.transform_v2(request).await,
            _ => Err(PluginError::VersionNotSupported(request.capability.version)),
        }
    }
    
    async fn transform_v2(&self, request: PluginRequest) -> Result<PluginResponse> {
        // V2 adds GPU acceleration if available
        if self.check_gpu_available() {
            // Use GPU-accelerated path
        } else {
            // Fall back to CPU implementation
        }
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success { 
                data: serde_json::json!({"status": "transformed"})
            },
            metadata: serde_json::json!({
                "capability_version": 2,
                "gpu_used": self.check_gpu_available(),
            }),
        })
    }
}