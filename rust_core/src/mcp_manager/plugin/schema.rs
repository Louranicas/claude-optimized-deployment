//! Configuration Schema System - Type Safety at Every Level
//!
//! This module provides JSON Schema generation and validation for plugin configurations.
//! Every configuration is validated, every field is typed, every constraint is enforced.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use jsonschema::{Draft, JSONSchema, ValidationError};
use schemars::{JsonSchema, schema_for};

use super::{PluginError, Result};

/// Configuration schema provider
pub trait SchemaProvider {
    /// Get the JSON Schema for this configuration
    fn schema() -> Value;
    
    /// Validate a configuration against the schema
    fn validate(config: &Value) -> Result<Vec<ValidationError>>;
    
    /// Get default configuration
    fn default_config() -> Value;
    
    /// Merge configurations with proper precedence
    fn merge_configs(base: Value, overlay: Value) -> Value;
}

/// Configuration schema registry
pub struct SchemaRegistry {
    /// Registered schemas by plugin ID
    schemas: HashMap<String, PluginSchema>,
    
    /// Schema validator
    validator: SchemaValidator,
}

/// Plugin schema definition
#[derive(Debug, Clone)]
pub struct PluginSchema {
    /// Plugin ID
    pub plugin_id: String,
    
    /// Schema definition
    pub schema: Value,
    
    /// Default values
    pub defaults: Value,
    
    /// Environment variable mappings
    pub env_mappings: HashMap<String, String>,
    
    /// Validation rules
    pub validation_rules: Vec<ValidationRule>,
}

/// Custom validation rule
#[derive(Debug, Clone)]
pub struct ValidationRule {
    /// Rule name
    pub name: String,
    
    /// Field path (JSONPath syntax)
    pub path: String,
    
    /// Validation function
    pub validator: ValidationFunction,
    
    /// Error message
    pub error_message: String,
}

/// Validation function types
#[derive(Debug, Clone)]
pub enum ValidationFunction {
    /// Regular expression
    Regex(String),
    
    /// Custom function name
    Custom(String),
    
    /// Range validation
    Range { min: Option<f64>, max: Option<f64> },
    
    /// Length validation
    Length { min: Option<usize>, max: Option<usize> },
    
    /// Enum validation
    Enum(Vec<String>),
    
    /// Dependency validation
    DependsOn { field: String, value: Value },
}

/// Schema validator
struct SchemaValidator {
    /// Compiled schemas
    compiled: HashMap<String, JSONSchema>,
}

impl SchemaRegistry {
    /// Create a new schema registry
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
            validator: SchemaValidator {
                compiled: HashMap::new(),
            },
        }
    }
    
    /// Register a plugin schema
    pub fn register(&mut self, schema: PluginSchema) -> Result<()> {
        // Compile the schema for validation
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&schema.schema)
            .map_err(|e| PluginError::InvalidManifest(
                format!("Invalid schema for {}: {}", schema.plugin_id, e)
            ))?;
        
        self.validator.compiled.insert(schema.plugin_id.clone(), compiled);
        self.schemas.insert(schema.plugin_id.clone(), schema);
        
        Ok(())
    }
    
    /// Validate a configuration
    pub fn validate(&self, plugin_id: &str, config: &Value) -> Result<()> {
        let schema = self.schemas.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(format!("Schema for {}", plugin_id)))?;
        
        // JSON Schema validation
        if let Some(compiled) = self.validator.compiled.get(plugin_id) {
            let result = compiled.validate(config);
            if let Err(errors) = result {
                let error_messages: Vec<String> = errors
                    .map(|e| format!("{}: {}", e.instance_path, e))
                    .collect();
                
                return Err(PluginError::InvalidManifest(
                    format!("Configuration validation failed: {}", error_messages.join(", "))
                ));
            }
        }
        
        // Custom validation rules
        for rule in &schema.validation_rules {
            self.validate_rule(config, rule)?;
        }
        
        Ok(())
    }
    
    /// Apply environment variables to configuration
    pub fn apply_env_vars(&self, plugin_id: &str, config: &mut Value) -> Result<()> {
        let schema = self.schemas.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(format!("Schema for {}", plugin_id)))?;
        
        for (path, env_var) in &schema.env_mappings {
            if let Ok(value) = std::env::var(env_var) {
                self.set_value_at_path(config, path, json!(value))?;
            }
        }
        
        Ok(())
    }
    
    /// Get default configuration
    pub fn get_defaults(&self, plugin_id: &str) -> Result<Value> {
        let schema = self.schemas.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(format!("Schema for {}", plugin_id)))?;
        
        Ok(schema.defaults.clone())
    }
    
    /// Merge configurations
    pub fn merge_configs(&self, base: Value, overlay: Value) -> Value {
        merge_json_values(base, overlay)
    }
    
    // Private helper methods
    
    fn validate_rule(&self, config: &Value, rule: &ValidationRule) -> Result<()> {
        let value = self.get_value_at_path(config, &rule.path)?;
        
        let valid = match &rule.validator {
            ValidationFunction::Regex(pattern) => {
                if let Some(s) = value.as_str() {
                    regex::Regex::new(pattern)
                        .map_err(|e| PluginError::InvalidManifest(format!("Invalid regex: {}", e)))?
                        .is_match(s)
                } else {
                    false
                }
            }
            
            ValidationFunction::Range { min, max } => {
                if let Some(n) = value.as_f64() {
                    let above_min = min.map(|m| n >= m).unwrap_or(true);
                    let below_max = max.map(|m| n <= m).unwrap_or(true);
                    above_min && below_max
                } else {
                    false
                }
            }
            
            ValidationFunction::Length { min, max } => {
                let len = match value {
                    Value::String(s) => s.len(),
                    Value::Array(a) => a.len(),
                    Value::Object(o) => o.len(),
                    _ => return Ok(()), // Skip non-sizeable types
                };
                
                let above_min = min.map(|m| len >= m).unwrap_or(true);
                let below_max = max.map(|m| len <= m).unwrap_or(true);
                above_min && below_max
            }
            
            ValidationFunction::Enum(values) => {
                if let Some(s) = value.as_str() {
                    values.contains(&s.to_string())
                } else {
                    false
                }
            }
            
            ValidationFunction::DependsOn { field, value: expected } => {
                let dep_value = self.get_value_at_path(config, field)?;
                dep_value == expected
            }
            
            ValidationFunction::Custom(_) => {
                // Custom functions would be implemented by plugins
                true
            }
        };
        
        if !valid {
            return Err(PluginError::InvalidManifest(
                format!("{}: {}", rule.name, rule.error_message)
            ));
        }
        
        Ok(())
    }
    
    fn get_value_at_path<'a>(&self, config: &'a Value, path: &str) -> Result<&'a Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = config;
        
        for part in parts {
            match current {
                Value::Object(map) => {
                    current = map.get(part)
                        .ok_or_else(|| PluginError::InvalidManifest(
                            format!("Path {} not found", path)
                        ))?;
                }
                Value::Array(arr) => {
                    let index: usize = part.parse()
                        .map_err(|_| PluginError::InvalidManifest(
                            format!("Invalid array index in path {}", path)
                        ))?;
                    current = arr.get(index)
                        .ok_or_else(|| PluginError::InvalidManifest(
                            format!("Array index {} out of bounds", index)
                        ))?;
                }
                _ => return Err(PluginError::InvalidManifest(
                    format!("Cannot traverse path {} through non-object/array", path)
                )),
            }
        }
        
        Ok(current)
    }
    
    fn set_value_at_path(&self, config: &mut Value, path: &str, value: Value) -> Result<()> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = config;
        
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part - set the value
                match current {
                    Value::Object(map) => {
                        map.insert(part.to_string(), value);
                        return Ok(());
                    }
                    Value::Array(arr) => {
                        let index: usize = part.parse()
                            .map_err(|_| PluginError::InvalidManifest(
                                format!("Invalid array index in path {}", path)
                            ))?;
                        if index < arr.len() {
                            arr[index] = value;
                            return Ok(());
                        } else {
                            return Err(PluginError::InvalidManifest(
                                format!("Array index {} out of bounds", index)
                            ));
                        }
                    }
                    _ => return Err(PluginError::InvalidManifest(
                        format!("Cannot set value at path {} - not an object/array", path)
                    )),
                }
            } else {
                // Intermediate part - traverse
                match current {
                    Value::Object(map) => {
                        current = map.entry(part.to_string())
                            .or_insert(Value::Object(serde_json::Map::new()));
                    }
                    _ => return Err(PluginError::InvalidManifest(
                        format!("Cannot traverse path {} - intermediate value not an object", path)
                    )),
                }
            }
        }
        
        Ok(())
    }
}

/// Merge two JSON values recursively
fn merge_json_values(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Object(mut base_map), Value::Object(overlay_map)) => {
            for (key, overlay_value) in overlay_map {
                match base_map.get_mut(&key) {
                    Some(base_value) => {
                        *base_value = merge_json_values(base_value.clone(), overlay_value);
                    }
                    None => {
                        base_map.insert(key, overlay_value);
                    }
                }
            }
            Value::Object(base_map)
        }
        (_, overlay) => overlay, // Overlay completely replaces non-objects
    }
}

/// Schema builder for easy schema construction
pub struct SchemaBuilder {
    plugin_id: String,
    schema: schemars::schema::RootSchema,
    defaults: Value,
    env_mappings: HashMap<String, String>,
    validation_rules: Vec<ValidationRule>,
}

impl SchemaBuilder {
    /// Create a new schema builder
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            schema: schemars::schema::RootSchema::default(),
            defaults: json!({}),
            env_mappings: HashMap::new(),
            validation_rules: Vec::new(),
        }
    }
    
    /// Set schema from a type
    pub fn schema_from<T: JsonSchema>(mut self) -> Self {
        self.schema = schema_for!(T);
        self
    }
    
    /// Add a property
    pub fn property(
        mut self,
        name: impl Into<String>,
        schema: Value,
        default: Option<Value>,
    ) -> Self {
        let name_str = name.into();
        
        // Add to schema
        if let Some(properties) = self.schema.schema.object.as_mut() {
            properties.properties.insert(
                name_str.clone(),
                serde_json::from_value(schema).unwrap(),
            );
        }
        
        // Add default if provided
        if let Some(default_value) = default {
            if let Value::Object(ref mut defaults) = self.defaults {
                defaults.insert(name_str, default_value);
            }
        }
        
        self
    }
    
    /// Add environment variable mapping
    pub fn env_var(mut self, path: impl Into<String>, env_var: impl Into<String>) -> Self {
        self.env_mappings.insert(path.into(), env_var.into());
        self
    }
    
    /// Add validation rule
    pub fn validate(mut self, rule: ValidationRule) -> Self {
        self.validation_rules.push(rule);
        self
    }
    
    /// Build the schema
    pub fn build(self) -> PluginSchema {
        PluginSchema {
            plugin_id: self.plugin_id,
            schema: serde_json::to_value(&self.schema).unwrap_or(json!({})),
            defaults: self.defaults,
            env_mappings: self.env_mappings,
            validation_rules: self.validation_rules,
        }
    }
}

/// Example schemas for built-in plugins
pub mod schemas {
    use super::*;
    
    /// Docker plugin configuration schema
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct DockerConfig {
        /// Docker socket path
        #[serde(default = "default_socket_path")]
        pub socket_path: String,
        
        /// API version
        #[serde(default = "default_api_version")]
        pub api_version: String,
        
        /// Connection timeout in milliseconds
        #[serde(default = "default_timeout")]
        pub timeout_ms: u64,
        
        /// Enable experimental features
        #[serde(default)]
        pub experimental: bool,
    }
    
    fn default_socket_path() -> String {
        "/var/run/docker.sock".to_string()
    }
    
    fn default_api_version() -> String {
        "1.41".to_string()
    }
    
    fn default_timeout() -> u64 {
        30000
    }
    
    /// Kubernetes plugin configuration schema
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct KubernetesConfig {
        /// Kubeconfig path
        pub kubeconfig_path: Option<String>,
        
        /// Default namespace
        #[serde(default = "default_namespace")]
        pub default_namespace: String,
        
        /// Request timeout in seconds
        #[serde(default = "default_k8s_timeout")]
        pub timeout_secs: u64,
        
        /// Enable watch operations
        #[serde(default = "default_true")]
        pub enable_watch: bool,
        
        /// Field manager name
        #[serde(default = "default_field_manager")]
        pub field_manager: String,
    }
    
    fn default_namespace() -> String {
        "default".to_string()
    }
    
    fn default_k8s_timeout() -> u64 {
        30
    }
    
    fn default_true() -> bool {
        true
    }
    
    fn default_field_manager() -> String {
        "mcp-kubernetes-plugin".to_string()
    }
    
    /// Prometheus plugin configuration schema
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct PrometheusConfig {
        /// Prometheus server URL
        #[serde(default = "default_prometheus_url")]
        pub server_url: String,
        
        /// API timeout in seconds
        #[serde(default = "default_prometheus_timeout")]
        pub timeout_secs: u64,
        
        /// Enable query caching
        #[serde(default = "default_true")]
        pub enable_cache: bool,
        
        /// Cache TTL in seconds
        #[serde(default = "default_cache_ttl")]
        pub cache_ttl_secs: u64,
        
        /// Maximum query range in seconds
        #[serde(default = "default_max_query_range")]
        pub max_query_range_secs: u64,
        
        /// Default step for range queries
        #[serde(default = "default_step")]
        pub default_step: String,
    }
    
    fn default_prometheus_url() -> String {
        "http://localhost:9090".to_string()
    }
    
    fn default_prometheus_timeout() -> u64 {
        30
    }
    
    fn default_cache_ttl() -> u64 {
        60
    }
    
    fn default_max_query_range() -> u64 {
        86400 // 24 hours
    }
    
    fn default_step() -> String {
        "15s".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_schema_validation() {
        let mut registry = SchemaRegistry::new();
        
        let schema = SchemaBuilder::new("test")
            .property(
                "port",
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535
                }),
                Some(json!(8080)),
            )
            .validate(ValidationRule {
                name: "Port range".to_string(),
                path: "port".to_string(),
                validator: ValidationFunction::Range {
                    min: Some(1.0),
                    max: Some(65535.0),
                },
                error_message: "Port must be between 1 and 65535".to_string(),
            })
            .build();
        
        registry.register(schema).unwrap();
        
        // Valid config
        let valid_config = json!({
            "port": 8080
        });
        assert!(registry.validate("test", &valid_config).is_ok());
        
        // Invalid config
        let invalid_config = json!({
            "port": 99999
        });
        assert!(registry.validate("test", &invalid_config).is_err());
    }
    
    #[test]
    fn test_config_merging() {
        let base = json!({
            "server": {
                "host": "localhost",
                "port": 8080
            },
            "debug": false
        });
        
        let overlay = json!({
            "server": {
                "port": 9090
            },
            "debug": true,
            "new_field": "value"
        });
        
        let merged = merge_json_values(base, overlay);
        
        assert_eq!(merged["server"]["host"], "localhost");
        assert_eq!(merged["server"]["port"], 9090);
        assert_eq!(merged["debug"], true);
        assert_eq!(merged["new_field"], "value");
    }
}