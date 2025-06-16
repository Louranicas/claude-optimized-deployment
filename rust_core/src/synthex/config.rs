//! SYNTHEX Configuration Module
//! 
//! Provides configuration structures matching the Python API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main SYNTHEX configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthexConfig {
    // Core settings
    pub max_parallel_searches: usize,
    pub connection_pool_size: usize,
    pub cache_size_mb: usize,
    pub query_timeout_ms: u64,
    pub enable_query_optimization: bool,
    
    // Agent settings
    pub enable_web_search: bool,
    pub enable_database_search: bool,
    pub enable_api_search: bool,
    pub enable_file_search: bool,
    pub enable_knowledge_base: bool,
    
    // Agent configurations
    pub web_search_config: WebSearchConfig,
    pub database_config: DatabaseConfig,
    pub api_config: ApiConfig,
    pub file_search_config: FileSearchConfig,
    pub knowledge_base_config: KnowledgeBaseConfig,
    
    // MCP v2 protocol
    pub mcp_v2_config: McpV2Config,
    
    // Performance settings
    pub enable_work_stealing: bool,
    pub worker_threads: Option<usize>,
    pub enable_zero_copy: bool,
    pub enable_memory_mapping: bool,
    
    // Monitoring
    pub enable_metrics: bool,
    pub metrics_port: u16,
    pub enable_tracing: bool,
    pub tracing_endpoint: Option<String>,
}

impl Default for SynthexConfig {
    fn default() -> Self {
        Self {
            max_parallel_searches: 10000,
            connection_pool_size: 100,
            cache_size_mb: 4096,
            query_timeout_ms: 5000,
            enable_query_optimization: true,
            
            enable_web_search: true,
            enable_database_search: true,
            enable_api_search: true,
            enable_file_search: true,
            enable_knowledge_base: true,
            
            web_search_config: WebSearchConfig::default(),
            database_config: DatabaseConfig::default(),
            api_config: ApiConfig::default(),
            file_search_config: FileSearchConfig::default(),
            knowledge_base_config: KnowledgeBaseConfig::default(),
            
            mcp_v2_config: McpV2Config::default(),
            
            enable_work_stealing: true,
            worker_threads: None,
            enable_zero_copy: true,
            enable_memory_mapping: true,
            
            enable_metrics: true,
            metrics_port: 9090,
            enable_tracing: true,
            tracing_endpoint: None,
        }
    }
}

impl SynthexConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        if let Ok(val) = std::env::var("SYNTHEX_MAX_PARALLEL_SEARCHES") {
            if let Ok(num) = val.parse() {
                config.max_parallel_searches = num;
            }
        }
        
        if let Ok(val) = std::env::var("SYNTHEX_CACHE_SIZE_MB") {
            if let Ok(num) = val.parse() {
                config.cache_size_mb = num;
            }
        }
        
        if let Ok(val) = std::env::var("SYNTHEX_QUERY_TIMEOUT_MS") {
            if let Ok(num) = val.parse() {
                config.query_timeout_ms = num;
            }
        }
        
        // Agent enablement
        if std::env::var("SYNTHEX_DISABLE_WEB_SEARCH").is_ok() {
            config.enable_web_search = false;
        }
        
        if std::env::var("SYNTHEX_DISABLE_DATABASE_SEARCH").is_ok() {
            config.enable_database_search = false;
        }
        
        if std::env::var("SYNTHEX_DISABLE_API_SEARCH").is_ok() {
            config.enable_api_search = false;
        }
        
        if std::env::var("SYNTHEX_DISABLE_FILE_SEARCH").is_ok() {
            config.enable_file_search = false;
        }
        
        if std::env::var("SYNTHEX_DISABLE_KNOWLEDGE_BASE").is_ok() {
            config.enable_knowledge_base = false;
        }
        
        config
    }
    
    /// Convert to format suitable for Python
    pub fn to_python_dict(&self) -> HashMap<String, serde_json::Value> {
        serde_json::from_str(&serde_json::to_string(self).unwrap()).unwrap()
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        
        if self.max_parallel_searches < 1 {
            errors.push("max_parallel_searches must be at least 1".to_string());
        }
        
        if self.cache_size_mb == 0 {
            errors.push("cache_size_mb cannot be zero".to_string());
        }
        
        if self.query_timeout_ms < 100 {
            errors.push("query_timeout_ms must be at least 100ms".to_string());
        }
        
        if self.enable_database_search && self.database_config.connection_string.is_none() {
            errors.push("database_config.connection_string required when database search is enabled".to_string());
        }
        
        errors
    }
}

/// Web search configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSearchConfig {
    pub brave_api_key: Option<String>,
    pub searxng_url: Option<String>,
    pub user_agent: String,
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
    pub cache_size: usize,
    pub cache_ttl_ms: u64,
}

impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            brave_api_key: None,
            searxng_url: None,
            user_agent: "SYNTHEX/1.0 (AI Search Engine)".to_string(),
            max_concurrent_requests: 100,
            request_timeout_ms: 5000,
            cache_size: 10000,
            cache_ttl_ms: 3600000, // 1 hour
        }
    }
}

/// Database search configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub connection_string: Option<String>,
    pub max_connections: usize,
    pub query_timeout_ms: u64,
    pub enable_query_cache: bool,
    pub search_tables: Vec<HashMap<String, serde_json::Value>>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            connection_string: None,
            max_connections: 50,
            query_timeout_ms: 10000,
            enable_query_cache: true,
            search_tables: Vec::new(),
        }
    }
}

/// API search configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub rate_limit_per_second: Option<u32>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 50,
            request_timeout_ms: 10000,
            retry_attempts: 3,
            retry_delay_ms: 1000,
            rate_limit_per_second: Some(100),
        }
    }
}

/// File search configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSearchConfig {
    pub root_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub max_file_size: usize,
    pub supported_extensions: Vec<String>,
}

impl Default for FileSearchConfig {
    fn default() -> Self {
        Self {
            root_paths: vec![".".to_string()],
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "dist".to_string(),
                "__pycache__".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
            supported_extensions: vec![
                "txt".to_string(),
                "md".to_string(),
                "py".to_string(),
                "rs".to_string(),
                "js".to_string(),
                "ts".to_string(),
                "json".to_string(),
                "yaml".to_string(),
                "toml".to_string(),
            ],
        }
    }
}

/// Knowledge base configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBaseConfig {
    pub index_path: String,
    pub max_results: usize,
    pub enable_fuzzy: bool,
    pub fuzzy_distance: u32,
}

impl Default for KnowledgeBaseConfig {
    fn default() -> Self {
        Self {
            index_path: "./knowledge_base_index".to_string(),
            max_results: 100,
            enable_fuzzy: true,
            fuzzy_distance: 2,
        }
    }
}

/// MCP v2 Protocol Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpV2Config {
    pub enable_compression: bool,
    pub compression_threshold: usize,
    pub max_message_size: usize,
    pub connection_timeout_ms: u64,
    pub enable_multiplexing: bool,
    pub enable_encryption: bool,
}

impl Default for McpV2Config {
    fn default() -> Self {
        Self {
            enable_compression: true,
            compression_threshold: 1024, // 1KB
            max_message_size: 10 * 1024 * 1024, // 10MB
            connection_timeout_ms: 5000,
            enable_multiplexing: true,
            enable_encryption: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::synthex::query::SubQuery;
    
    #[test]
    fn test_default_config() {
        let config = SynthexConfig::default();
        assert_eq!(config.max_parallel_searches, 10000);
        assert_eq!(config.cache_size_mb, 4096);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = SynthexConfig::default();
        config.max_parallel_searches = 0;
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("max_parallel_searches"));
    }
}