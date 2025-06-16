# MCP Manager Migration Guide

This guide helps you migrate plugins between versions and handle breaking changes in the MCP Manager plugin system.

## Table of Contents

1. [Version Migration Strategy](#version-migration-strategy)
2. [State Migration](#state-migration)
3. [API Migration](#api-migration)
4. [Capability Evolution](#capability-evolution)
5. [Zero-Downtime Migration](#zero-downtime-migration)
6. [Rollback Procedures](#rollback-procedures)
7. [Common Migration Scenarios](#common-migration-scenarios)

## Version Migration Strategy

### Semantic Versioning

MCP Manager follows semantic versioning (SemVer):

- **Major version (X.0.0)**: Breaking changes
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes, backward compatible

### Compatibility Rules

```rust
use semver::Version;
use claude_optimized_deployment_rust::mcp_manager::plugin::version::*;

// Check compatibility
let current = Version::parse("1.2.3")?;
let target = Version::parse("1.3.0")?;

let compat = version_manager.check_compatibility(&current, &target)?;
if compat.is_compatible {
    println!("Safe to upgrade!");
} else {
    println!("Breaking changes detected: {:?}", compat.breaking_changes);
}
```

### Migration Planning

```rust
// Plan migration path
let plan = version_manager.plan_migration(&current, &target)?;

for step in plan.steps {
    println!("Step {}: {} -> {}", 
        step.order, 
        step.from_version, 
        step.to_version
    );
    
    if let Some(migration) = step.migration_script {
        println!("  Migration required: {}", migration);
    }
}
```

## State Migration

### Implementing State Migration

```rust
use async_trait::async_trait;
use claude_optimized_deployment_rust::mcp_manager::plugin::*;

#[async_trait]
impl StateTransferable for MyPlugin {
    async fn export_state(&self) -> Result<StateSnapshot> {
        let state = self.state.read().await;
        
        // Export with schema version
        let snapshot = StateSnapshot {
            schema_version: 2, // Current schema version
            sections: self.export_sections(&state).await?,
            // ... other fields
        };
        
        Ok(snapshot)
    }
    
    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        // Handle different schema versions
        match snapshot.schema_version {
            1 => self.import_v1_state(snapshot).await,
            2 => self.import_v2_state(snapshot).await,
            v => Err(StateTransferError::UnsupportedSchema(v)),
        }
    }
}

impl MyPlugin {
    async fn import_v1_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        // Migrate v1 -> v2 schema
        let migrated = self.migrate_v1_to_v2(snapshot)?;
        self.import_v2_state(migrated).await
    }
    
    fn migrate_v1_to_v2(&self, v1_snapshot: StateSnapshot) -> Result<StateSnapshot> {
        let mut v2_snapshot = v1_snapshot.clone();
        v2_snapshot.schema_version = 2;
        
        // Transform data structure
        if let Some(config) = v2_snapshot.sections.get_mut("config") {
            let v1_config: ConfigV1 = serde_json::from_slice(&config.data)?;
            let v2_config = ConfigV2 {
                // Map old fields to new structure
                api_endpoint: v1_config.api_url,
                timeout_ms: v1_config.timeout_seconds * 1000,
                // New fields with defaults
                retry_policy: RetryPolicy::default(),
            };
            config.data = serde_json::to_vec(&v2_config)?;
        }
        
        Ok(v2_snapshot)
    }
}
```

### State Schema Evolution

```rust
// Version 1 schema
#[derive(Serialize, Deserialize)]
struct ConfigV1 {
    api_url: String,
    timeout_seconds: u64,
}

// Version 2 schema (current)
#[derive(Serialize, Deserialize)]
struct ConfigV2 {
    api_endpoint: String,     // Renamed field
    timeout_ms: u64,          // Changed units
    retry_policy: RetryPolicy, // New field
}

// Migration helper
fn migrate_config_v1_to_v2(v1: ConfigV1) -> ConfigV2 {
    ConfigV2 {
        api_endpoint: v1.api_url,
        timeout_ms: v1.timeout_seconds * 1000,
        retry_policy: RetryPolicy::default(),
    }
}
```

## API Migration

### Handling Method Changes

```rust
impl Plugin for MyPlugin {
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        match request.method.as_str() {
            // Current methods
            "process_data" => self.handle_process_data(request).await,
            
            // Deprecated methods with compatibility layer
            "processData" => {
                // Old camelCase method - redirect to new method
                let mut new_request = request.clone();
                new_request.method = "process_data".to_string();
                self.handle(new_request).await
            }
            
            // Removed methods with helpful error
            "old_method" => {
                Err(PluginError::Deprecated(
                    "old_method is deprecated. Use 'new_method' instead.".to_string()
                ))
            }
            
            _ => Err(PluginError::MethodNotFound(request.method)),
        }
    }
}
```

### Parameter Migration

```rust
async fn handle_process_data(&self, request: PluginRequest) -> Result<PluginResponse> {
    // Handle both old and new parameter formats
    let data = if let Some(new_format) = request.params.get("data") {
        // New format
        new_format.clone()
    } else if let Some(old_format) = request.params.get("input_data") {
        // Old format - transform to new
        json!({
            "data": old_format,
            "format": "legacy"
        })
    } else {
        return Err(PluginError::InvalidRequest("data parameter required".into()));
    };
    
    // Process with unified format
    self.process(data).await
}
```

## Capability Evolution

### Versioning Capabilities

```rust
// Plugin supporting multiple capability versions
impl Plugin for MyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &PluginMetadata {
            provides: vec![
                // Current version
                Capability::new("data", "transform", 3),
                // Maintain compatibility with older versions
                Capability::new("data", "transform", 2),
                Capability::new("data", "transform", 1),
            ],
            // ...
        }
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        if request.capability.namespace == "data" && request.capability.name == "transform" {
            match request.capability.version {
                1 => self.transform_v1(request).await,
                2 => self.transform_v2(request).await,
                3 => self.transform_v3(request).await,
                v => Err(PluginError::VersionNotSupported(v)),
            }
        } else {
            Err(PluginError::CapabilityNotSupported(request.capability))
        }
    }
}
```

### Capability Deprecation

```rust
// Mark capabilities as deprecated
pub struct DeprecatedCapability {
    pub capability: Capability,
    pub deprecated_since: Version,
    pub removal_version: Option<Version>,
    pub alternative: Option<Capability>,
    pub message: String,
}

impl Plugin for MyPlugin {
    fn deprecated_capabilities(&self) -> Vec<DeprecatedCapability> {
        vec![
            DeprecatedCapability {
                capability: Capability::new("data", "legacy_transform", 1),
                deprecated_since: Version::new(2, 0, 0),
                removal_version: Some(Version::new(3, 0, 0)),
                alternative: Some(Capability::new("data", "transform", 2)),
                message: "Use data:transform:2 for better performance".to_string(),
            },
        ]
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        // Check for deprecated capability usage
        if let Some(deprecation) = self.is_deprecated(&request.capability) {
            // Log warning
            warn!("Deprecated capability used: {} - {}", 
                  request.capability, deprecation.message);
            
            // Still handle the request for compatibility
            self.handle_legacy(request).await
        } else {
            self.handle_current(request).await
        }
    }
}
```

## Zero-Downtime Migration

### Blue-Green Deployment

```rust
use claude_optimized_deployment_rust::mcp_manager::plugin::zero_downtime::*;

// Configure zero-downtime update
let update_plan = UpdatePlan {
    plugin_id: "my-plugin".to_string(),
    new_version: Version::new(2, 0, 0),
    strategy: UpdateStrategy::BlueGreen,
    new_plugin: new_plugin_instance,
    validation_period: Duration::from_secs(300), // 5 minutes
    rollback_on_error: true,
    health_check_config: Some(HealthCheckConfig {
        interval_ms: 1000,
        timeout_ms: 500,
        healthy_threshold: 3,
        unhealthy_threshold: 2,
        check_type: HealthCheckType::Custom(Box::new(|plugin| {
            // Custom health check
            Box::pin(async move {
                plugin.handle(health_check_request()).await.is_ok()
            })
        })),
    }),
};

// Execute migration
let result = zero_downtime_coordinator.execute_update(update_plan).await?;

match result.status {
    UpdateStatus::Completed => println!("Migration successful!"),
    UpdateStatus::RolledBack => println!("Migration failed, rolled back"),
    _ => println!("Migration in progress..."),
}
```

### Gradual Traffic Shift

```rust
// Configure gradual rollout
let update_plan = UpdatePlan {
    strategy: UpdateStrategy::Canary {
        initial_percentage: 10.0,
        increment: 10.0,
        increment_interval: Duration::from_secs(300),
        error_threshold: 0.01, // 1% error rate triggers rollback
    },
    // ... other fields
};

// Monitor progress
let progress = zero_downtime_coordinator.get_update_progress(&plugin_id).await?;
println!("Current traffic split: {}% new version", progress.traffic_percentage);
```

## Rollback Procedures

### Automatic Rollback

```rust
// Configure automatic rollback
let rollback_config = RollbackConfig {
    enabled: true,
    max_checkpoints: 10,
    checkpoint_interval: Duration::from_secs(3600), // Every hour
    auto_checkpoint: true,
    retention_period: Duration::from_days(7),
};

let rollback_manager = RollbackManager::new(
    state_transfer_coordinator,
    version_manager,
    rollback_config,
);

// Migration with automatic rollback on failure
match perform_migration().await {
    Ok(_) => {
        // Create success checkpoint
        rollback_manager.create_checkpoint(
            plugin_id,
            plugin_handle,
            state_snapshot,
            CheckpointType::PostMigration,
            "Successful migration to v2.0.0",
        ).await?;
    }
    Err(e) => {
        // Automatic rollback to last checkpoint
        let result = rollback_manager.rollback_to_latest(plugin_id).await?;
        println!("Rolled back to checkpoint: {}", result.checkpoint_id);
    }
}
```

### Manual Rollback

```rust
// List available checkpoints
let checkpoints = rollback_manager.list_checkpoints(plugin_id).await?;
for cp in checkpoints {
    println!("{}: {} - {}", cp.id, cp.created_at, cp.description);
}

// Rollback to specific checkpoint
let checkpoint_id = "cp-20240115-120000";
let result = rollback_manager.rollback_to_checkpoint(
    plugin_id,
    checkpoint_id,
).await?;

if result.success {
    println!("Successfully rolled back in {:?}", result.duration);
}
```

## Common Migration Scenarios

### Scenario 1: Database Schema Update

```rust
// Plugin with database dependency
impl Plugin for DatabasePlugin {
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        // Check database schema version
        let db_version = self.get_db_schema_version().await?;
        let required_version = 5;
        
        if db_version < required_version {
            // Run migrations
            self.run_migrations(db_version, required_version).await?;
        }
        
        Ok(())
    }
    
    async fn run_migrations(&self, from: u32, to: u32) -> Result<()> {
        for version in from..to {
            match version {
                3 => self.migrate_v3_to_v4().await?,
                4 => self.migrate_v4_to_v5().await?,
                _ => {}
            }
        }
        Ok(())
    }
}
```

### Scenario 2: Configuration Format Change

```rust
// Handle both YAML and JSON configs
impl Plugin for ConfigurablePlugin {
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        // Try to detect old YAML format
        if let Some(yaml_str) = config.as_str() {
            // Parse YAML and convert to new JSON format
            let yaml_config: serde_yaml::Value = serde_yaml::from_str(yaml_str)?;
            let json_config = serde_json::to_value(yaml_config)?;
            self.apply_config(json_config).await?;
        } else {
            // Already in JSON format
            self.apply_config(config).await?;
        }
        
        Ok(())
    }
}
```

### Scenario 3: API Endpoint Migration

```rust
// Migrate from REST to gRPC
impl Plugin for ApiPlugin {
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        match request.params.get("protocol").and_then(|p| p.as_str()) {
            Some("grpc") => self.handle_grpc(request).await,
            Some("rest") | None => {
                // Default to REST for compatibility
                warn!("REST API is deprecated, please migrate to gRPC");
                self.handle_rest(request).await
            }
            _ => Err(PluginError::InvalidRequest("Unknown protocol".into())),
        }
    }
}
```

## Migration Checklist

### Before Migration

- [ ] Review breaking changes in release notes
- [ ] Test migration in staging environment
- [ ] Create full backup/checkpoint
- [ ] Prepare rollback plan
- [ ] Notify dependent services
- [ ] Schedule maintenance window (if needed)

### During Migration

- [ ] Monitor error rates
- [ ] Check resource utilization
- [ ] Validate data integrity
- [ ] Test critical functionality
- [ ] Monitor dependent services

### After Migration

- [ ] Verify all features working
- [ ] Check performance metrics
- [ ] Review logs for warnings/errors
- [ ] Update documentation
- [ ] Remove deprecated code (after grace period)
- [ ] Create post-migration checkpoint

## Best Practices

1. **Always maintain backward compatibility** for at least one major version
2. **Use feature flags** to gradually roll out changes
3. **Provide clear deprecation warnings** with migration instructions
4. **Test migrations thoroughly** in non-production environments
5. **Document all breaking changes** in release notes
6. **Implement comprehensive health checks** for validation
7. **Plan for rollback** at every stage
8. **Monitor closely** during and after migration
9. **Communicate changes** to all stakeholders
10. **Keep migration windows small** to minimize risk