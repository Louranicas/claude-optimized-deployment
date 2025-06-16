//! Schema Validation Unit Tests
//!
//! Tests for the configuration schema validation system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::{*, schema::*};
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_builder_basic() {
        let schema = SchemaBuilder::new("test")
            .title("Test Schema")
            .description("A test configuration schema")
            .property(
                "name",
                json!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100
                }),
                Some("The name field".to_string()),
            )
            .property(
                "port",
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535
                }),
                Some("Server port".to_string()),
            )
            .required(vec!["name", "port"])
            .build();

        assert_eq!(schema.id, "test");
        assert_eq!(schema.title, Some("Test Schema".to_string()));
        assert_eq!(schema.properties.len(), 2);
        assert_eq!(schema.required.len(), 2);
    }

    #[test]
    fn test_schema_registry() {
        let mut registry = SchemaRegistry::new();

        // Register schema
        let schema = SchemaBuilder::new("server-config")
            .property(
                "host",
                json!({"type": "string", "format": "hostname"}),
                None,
            )
            .property(
                "port",
                json!({"type": "integer", "minimum": 1, "maximum": 65535}),
                None,
            )
            .required(vec!["host", "port"])
            .build();

        registry.register(schema).unwrap();

        // Validate valid config
        let valid_config = json!({
            "host": "localhost",
            "port": 8080
        });

        let result = registry.validate("server-config", &valid_config).unwrap();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_schema_validation_errors() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("test")
            .property(
                "age",
                json!({"type": "integer", "minimum": 0, "maximum": 150}),
                None,
            )
            .property(
                "email",
                json!({"type": "string", "format": "email"}),
                None,
            )
            .required(vec!["age", "email"])
            .build();

        registry.register(schema).unwrap();

        // Invalid config - missing required field
        let invalid_config = json!({
            "age": 25
        });

        let result = registry.validate("test", &invalid_config).unwrap();
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());

        // Invalid config - wrong type
        let invalid_config2 = json!({
            "age": "not a number",
            "email": "test@example.com"
        });

        let result2 = registry.validate("test", &invalid_config2).unwrap();
        assert!(!result2.is_valid);
    }

    #[test]
    fn test_schema_nested_objects() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("nested")
            .property(
                "database",
                json!({
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "credentials": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "password": {"type": "string"}
                            },
                            "required": ["username", "password"]
                        }
                    },
                    "required": ["host", "port", "credentials"]
                }),
                None,
            )
            .required(vec!["database"])
            .build();

        registry.register(schema).unwrap();

        // Valid nested config
        let config = json!({
            "database": {
                "host": "localhost",
                "port": 5432,
                "credentials": {
                    "username": "admin",
                    "password": "secret"
                }
            }
        });

        let result = registry.validate("nested", &config).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_schema_arrays() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("array-test")
            .property(
                "tags",
                json!({
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 10,
                    "uniqueItems": true
                }),
                None,
            )
            .property(
                "numbers",
                json!({
                    "type": "array",
                    "items": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 100
                    }
                }),
                None,
            )
            .build();

        registry.register(schema).unwrap();

        // Valid arrays
        let config = json!({
            "tags": ["tag1", "tag2", "tag3"],
            "numbers": [10, 20, 30, 40]
        });

        let result = registry.validate("array-test", &config).unwrap();
        assert!(result.is_valid);

        // Invalid - duplicate items
        let invalid_config = json!({
            "tags": ["tag1", "tag2", "tag1"],
            "numbers": [10, 20]
        });

        let result = registry.validate("array-test", &invalid_config).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_schema_additional_properties() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("strict")
            .property("name", json!({"type": "string"}), None)
            .additional_properties(false)
            .build();

        registry.register(schema).unwrap();

        // Config with extra property
        let config = json!({
            "name": "test",
            "extra": "not allowed"
        });

        let result = registry.validate("strict", &config).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_schema_pattern_properties() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("pattern")
            .pattern_property(
                r"^env_.*",
                json!({"type": "string"}),
            )
            .build();

        registry.register(schema).unwrap();

        // Valid config with pattern properties
        let config = json!({
            "env_HOME": "/home/user",
            "env_PATH": "/usr/bin:/usr/local/bin",
            "env_LANG": "en_US.UTF-8"
        });

        let result = registry.validate("pattern", &config).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_schema_enum_validation() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("enum-test")
            .property(
                "log_level",
                json!({
                    "type": "string",
                    "enum": ["debug", "info", "warn", "error"]
                }),
                None,
            )
            .property(
                "environment",
                json!({
                    "type": "string",
                    "enum": ["development", "staging", "production"]
                }),
                None,
            )
            .build();

        registry.register(schema).unwrap();

        // Valid enum values
        let config = json!({
            "log_level": "info",
            "environment": "production"
        });

        let result = registry.validate("enum-test", &config).unwrap();
        assert!(result.is_valid);

        // Invalid enum value
        let invalid_config = json!({
            "log_level": "trace",
            "environment": "production"
        });

        let result = registry.validate("enum-test", &invalid_config).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_schema_conditional_validation() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("conditional")
            .property(
                "type",
                json!({"type": "string", "enum": ["file", "url"]}),
                None,
            )
            .property(
                "path",
                json!({"type": "string"}),
                None,
            )
            .property(
                "url",
                json!({"type": "string", "format": "uri"}),
                None,
            )
            .build();

        registry.register(schema).unwrap();

        // Valid configs for both types
        let file_config = json!({
            "type": "file",
            "path": "/path/to/file"
        });

        let url_config = json!({
            "type": "url",
            "url": "https://example.com"
        });

        assert!(registry.validate("conditional", &file_config).unwrap().is_valid);
        assert!(registry.validate("conditional", &url_config).unwrap().is_valid);
    }

    #[test]
    fn test_schema_merge_configs() {
        let registry = SchemaRegistry::new();

        let base = json!({
            "server": {
                "host": "localhost",
                "port": 8080
            },
            "logging": {
                "level": "info"
            }
        });

        let overlay = json!({
            "server": {
                "port": 9090,
                "ssl": true
            },
            "logging": {
                "file": "/var/log/app.log"
            }
        });

        let merged = registry.merge_configs(base, overlay);

        assert_eq!(merged["server"]["host"], "localhost");
        assert_eq!(merged["server"]["port"], 9090);
        assert_eq!(merged["server"]["ssl"], true);
        assert_eq!(merged["logging"]["level"], "info");
        assert_eq!(merged["logging"]["file"], "/var/log/app.log");
    }

    #[test]
    fn test_schema_registry_duplicate() {
        let mut registry = SchemaRegistry::new();

        let schema1 = SchemaBuilder::new("test").build();
        let schema2 = SchemaBuilder::new("test").build();

        registry.register(schema1).unwrap();
        let result = registry.register(schema2);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginError::AlreadyLoaded(_)
        ));
    }

    #[test]
    fn test_schema_get_and_list() {
        let mut registry = SchemaRegistry::new();

        // Register multiple schemas
        for i in 0..3 {
            let schema = SchemaBuilder::new(&format!("schema-{}", i))
                .title(&format!("Schema {}", i))
                .build();
            registry.register(schema).unwrap();
        }

        // Get specific schema
        let schema = registry.get("schema-1").unwrap();
        assert_eq!(schema.id, "schema-1");
        assert_eq!(schema.title, Some("Schema 1".to_string()));

        // List all schemas
        let schemas = registry.list();
        assert_eq!(schemas.len(), 3);
        assert!(schemas.contains(&"schema-0".to_string()));
        assert!(schemas.contains(&"schema-1".to_string()));
        assert!(schemas.contains(&"schema-2".to_string()));
    }

    #[test]
    fn test_schema_validation_with_defaults() {
        let mut registry = SchemaRegistry::new();

        let schema = SchemaBuilder::new("defaults")
            .property(
                "timeout",
                json!({
                    "type": "integer",
                    "default": 30
                }),
                None,
            )
            .property(
                "retries",
                json!({
                    "type": "integer",
                    "default": 3
                }),
                None,
            )
            .build();

        registry.register(schema).unwrap();

        // Empty config should be valid with defaults
        let config = json!({});
        let result = registry.validate("defaults", &config).unwrap();
        assert!(result.is_valid);
    }
}