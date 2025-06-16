# StateTransferable Trait API Reference

The `StateTransferable` trait enables plugins to export and import their state for hot reload, migration, and backup purposes.

## Trait Definition

```rust
#[async_trait]
pub trait StateTransferable: Plugin {
    /// Export the current state of the plugin
    async fn export_state(&self) -> Result<StateSnapshot>;
    
    /// Import state into the plugin
    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult>;
    
    /// Validate a state snapshot before importing
    async fn validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation>;
    
    /// Get the current state schema version
    fn state_schema_version(&self) -> u32;
}
```

## Required Methods

### `export_state(&self) -> Result<StateSnapshot>`

Exports the current state of the plugin into a snapshot.

**Returns:**
- `Ok(StateSnapshot)` containing the serialized state
- `Err(StateTransferError)` on failure

**Example:**
```rust
async fn export_state(&self) -> Result<StateSnapshot> {
    let state = self.state.read().await;
    
    let mut sections = HashMap::new();
    
    // Export configuration
    sections.insert("config".to_string(), StateSection {
        name: "config".to_string(),
        schema_version: 1,
        data: serde_json::to_vec(&*state.config)?,
        compressed: false,
        encryption: None,
        metadata: HashMap::new(),
    });
    
    // Export cache
    sections.insert("cache".to_string(), StateSection {
        name: "cache".to_string(),
        schema_version: 1,
        data: bincode::serialize(&*state.cache)?,
        compressed: true,
        encryption: None,
        metadata: hashmap!{
            "entries".to_string() => state.cache.len().to_string(),
        },
    });
    
    Ok(StateSnapshot {
        id: Uuid::new_v4().to_string(),
        plugin_id: self.metadata.id.clone(),
        plugin_version: self.metadata.version.clone(),
        schema_version: self.state_schema_version(),
        timestamp: Utc::now().timestamp(),
        sections,
        metadata: StateMetadata {
            reason: StateCreationReason::HotReload,
            created_by: "system".to_string(),
            tags: vec!["auto-export".to_string()],
            expires_at: None,
            custom: HashMap::new(),
        },
        checksum: calculate_checksum(&sections),
    })
}
```

### `import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult>`

Imports state from a snapshot into the plugin.

**Parameters:**
- `snapshot`: The state snapshot to import

**Returns:**
- `Ok(StateImportResult)` with import details
- `Err(StateTransferError)` on failure

**Example:**
```rust
async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
    let start = Instant::now();
    let mut imported_sections = Vec::new();
    let mut failed_sections = Vec::new();
    let mut warnings = Vec::new();
    
    // Validate snapshot first
    let validation = self.validate_state(&snapshot).await?;
    if !validation.is_valid {
        return Err(StateTransferError::ValidationFailed(
            "Invalid snapshot".into()
        ));
    }
    
    let mut state = self.state.write().await;
    
    // Import configuration
    if let Some(config_section) = snapshot.sections.get("config") {
        match serde_json::from_slice::<Config>(&config_section.data) {
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
    
    // Import cache with compatibility handling
    if let Some(cache_section) = snapshot.sections.get("cache") {
        let data = if cache_section.compressed {
            decompress(&cache_section.data)?
        } else {
            cache_section.data.clone()
        };
        
        match bincode::deserialize::<Cache>(&data) {
            Ok(cache) => {
                state.cache = cache;
                imported_sections.push("cache".to_string());
            }
            Err(_) => {
                warnings.push("Cache format incompatible, starting fresh".to_string());
                state.cache = Cache::new();
            }
        }
    }
    
    Ok(StateImportResult {
        imported_sections,
        failed_sections,
        warnings,
        duration: start.elapsed(),
    })
}
```

### `validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation>`

Validates a state snapshot before importing.

**Parameters:**
- `snapshot`: Reference to the state snapshot to validate

**Returns:**
- `Ok(StateValidation)` with validation results
- `Err(StateTransferError)` on validation error

**Example:**
```rust
async fn validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation> {
    let mut section_validations = HashMap::new();
    let mut is_valid = true;
    
    // Check plugin compatibility
    let plugin_compatible = snapshot.plugin_id == self.metadata.id;
    if !plugin_compatible {
        is_valid = false;
    }
    
    // Check schema version
    let schema_compatible = snapshot.schema_version <= self.state_schema_version();
    if !schema_compatible {
        is_valid = false;
    }
    
    // Check version compatibility
    let current_version = Version::parse(&self.metadata.version)?;
    let snapshot_version = Version::parse(&snapshot.plugin_version)?;
    let version_compatible = current_version.major == snapshot_version.major;
    
    // Validate each section
    for (name, section) in &snapshot.sections {
        let validation = match name.as_str() {
            "config" => validate_config_section(section),
            "cache" => validate_cache_section(section),
            _ => SectionValidation {
                is_valid: false,
                errors: vec!["Unknown section".to_string()],
                warnings: vec![],
            },
        };
        
        if !validation.is_valid {
            is_valid = false;
        }
        
        section_validations.insert(name.clone(), validation);
    }
    
    // Calculate compatibility score
    let compatibility_score = calculate_compatibility_score(
        &snapshot,
        &self.metadata,
        &section_validations,
    );
    
    Ok(StateValidation {
        is_valid,
        schema_compatible,
        version_compatible,
        section_validations,
        compatibility_score,
    })
}
```

### `state_schema_version(&self) -> u32`

Returns the current schema version for the plugin's state.

**Returns:**
- Schema version number

**Example:**
```rust
fn state_schema_version(&self) -> u32 {
    2 // Increment when state format changes
}
```

## Associated Types

### `StateSnapshot`

Complete state snapshot:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub schema_version: u32,
    pub timestamp: i64,
    pub sections: HashMap<String, StateSection>,
    pub metadata: StateMetadata,
    pub checksum: String,
}
```

### `StateSection`

Individual section of state:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSection {
    pub name: String,
    pub schema_version: u32,
    pub data: Vec<u8>,
    pub compressed: bool,
    pub encryption: Option<EncryptionInfo>,
    pub metadata: HashMap<String, String>,
}
```

### `StateImportResult`

Result of state import operation:

```rust
#[derive(Debug, Clone)]
pub struct StateImportResult {
    pub imported_sections: Vec<String>,
    pub failed_sections: Vec<FailedSection>,
    pub warnings: Vec<String>,
    pub duration: Duration,
}
```

### `StateValidation`

Result of state validation:

```rust
#[derive(Debug, Clone)]
pub struct StateValidation {
    pub is_valid: bool,
    pub schema_compatible: bool,
    pub version_compatible: bool,
    pub section_validations: HashMap<String, SectionValidation>,
    pub compatibility_score: f64,
}
```

## Implementation Guidelines

1. **Atomicity**: State export/import should be atomic operations.

2. **Backward Compatibility**: Support importing older schema versions.

3. **Partial Import**: Handle partial state import gracefully.

4. **Compression**: Use compression for large state sections.

5. **Validation**: Always validate before importing state.

## Complete Example

```rust
use async_trait::async_trait;
use std::collections::HashMap;
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug)]
struct StatefulPlugin {
    metadata: PluginMetadata,
    state: Arc<RwLock<PluginState>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PluginState {
    config: Config,
    cache: Cache,
    metrics: Metrics,
}

#[async_trait]
impl StateTransferable for StatefulPlugin {
    async fn export_state(&self) -> Result<StateSnapshot> {
        let state = self.state.read().await;
        let mut sections = HashMap::new();
        
        // Export all state sections
        sections.insert("config".to_string(), StateSection {
            name: "config".to_string(),
            schema_version: 1,
            data: serde_json::to_vec(&state.config)?,
            compressed: false,
            encryption: None,
            metadata: HashMap::new(),
        });
        
        sections.insert("cache".to_string(), StateSection {
            name: "cache".to_string(),
            schema_version: 1,
            data: compress(&bincode::serialize(&state.cache)?)?,
            compressed: true,
            encryption: None,
            metadata: hashmap!{
                "size".to_string() => state.cache.size_bytes().to_string(),
            },
        });
        
        sections.insert("metrics".to_string(), StateSection {
            name: "metrics".to_string(),
            schema_version: 1,
            data: serde_json::to_vec(&state.metrics)?,
            compressed: false,
            encryption: None,
            metadata: HashMap::new(),
        });
        
        let checksum = calculate_checksum(&sections);
        
        Ok(StateSnapshot {
            id: Uuid::new_v4().to_string(),
            plugin_id: self.metadata.id.clone(),
            plugin_version: self.metadata.version.clone(),
            schema_version: self.state_schema_version(),
            timestamp: Utc::now().timestamp(),
            sections,
            metadata: StateMetadata {
                reason: StateCreationReason::Export,
                created_by: "plugin".to_string(),
                tags: vec![],
                expires_at: None,
                custom: HashMap::new(),
            },
            checksum,
        })
    }
    
    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        // Validate first
        let validation = self.validate_state(&snapshot).await?;
        if !validation.is_valid {
            return Err(StateTransferError::ValidationFailed(
                format!("Validation score: {}", validation.compatibility_score)
            ));
        }
        
        let start = Instant::now();
        let mut state = self.state.write().await;
        let mut result = StateImportResult {
            imported_sections: Vec::new(),
            failed_sections: Vec::new(),
            warnings: Vec::new(),
            duration: Duration::default(),
        };
        
        // Import each section with error handling
        for (name, section) in snapshot.sections {
            match self.import_section(&mut state, name.clone(), section).await {
                Ok(warnings) => {
                    result.imported_sections.push(name);
                    result.warnings.extend(warnings);
                }
                Err(e) => {
                    result.failed_sections.push(FailedSection {
                        name,
                        error: e.to_string(),
                    });
                }
            }
        }
        
        result.duration = start.elapsed();
        Ok(result)
    }
    
    async fn validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation> {
        let mut validation = StateValidation {
            is_valid: true,
            schema_compatible: true,
            version_compatible: true,
            section_validations: HashMap::new(),
            compatibility_score: 1.0,
        };
        
        // Check basic compatibility
        if snapshot.plugin_id != self.metadata.id {
            validation.is_valid = false;
            validation.compatibility_score = 0.0;
            return Ok(validation);
        }
        
        // Check schema version
        if snapshot.schema_version > self.state_schema_version() {
            validation.schema_compatible = false;
            validation.is_valid = false;
            validation.compatibility_score *= 0.5;
        }
        
        // Validate each section
        for (name, section) in &snapshot.sections {
            let section_valid = self.validate_section(name, section);
            if !section_valid.is_valid {
                validation.is_valid = false;
            }
            validation.section_validations.insert(name.clone(), section_valid);
        }
        
        Ok(validation)
    }
    
    fn state_schema_version(&self) -> u32 {
        1
    }
}

impl StatefulPlugin {
    async fn import_section(
        &self,
        state: &mut PluginState,
        name: String,
        section: StateSection,
    ) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        
        match name.as_str() {
            "config" => {
                state.config = serde_json::from_slice(&section.data)?;
            }
            "cache" => {
                let data = if section.compressed {
                    decompress(&section.data)?
                } else {
                    section.data
                };
                state.cache = bincode::deserialize(&data)?;
            }
            "metrics" => {
                // Metrics might be optional
                match serde_json::from_slice(&section.data) {
                    Ok(metrics) => state.metrics = metrics,
                    Err(_) => warnings.push("Metrics import failed, using defaults".to_string()),
                }
            }
            _ => warnings.push(format!("Unknown section: {}", name)),
        }
        
        Ok(warnings)
    }
    
    fn validate_section(&self, name: &str, section: &StateSection) -> SectionValidation {
        let mut validation = SectionValidation {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        
        // Check section-specific requirements
        match name {
            "config" => {
                if section.schema_version > 1 {
                    validation.errors.push("Config schema too new".to_string());
                    validation.is_valid = false;
                }
            }
            "cache" => {
                if !section.compressed {
                    validation.warnings.push("Cache should be compressed".to_string());
                }
            }
            _ => {
                validation.warnings.push("Unknown section".to_string());
            }
        }
        
        validation
    }
}
```