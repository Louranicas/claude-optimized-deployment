/*!
 * Configuration Management for Rust MCP Server
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_api_endpoint")]
    pub api_endpoint: String,
    
    #[serde(default)]
    pub api_key: String,
    
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    
    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,
    
    #[serde(default)]
    pub logging: LoggingConfig,
    
    #[serde(default)]
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    
    #[serde(default = "default_log_format")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
}

// Default value functions
fn default_api_endpoint() -> String {
    "https://api.example.com".to_string()
}

fn default_max_retries() -> u32 {
    3
}

fn default_cache_enabled() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_timeout() -> u64 {
    30000
}

fn default_max_concurrency() -> usize {
    100
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            api_endpoint: default_api_endpoint(),
            api_key: String::new(),
            max_retries: default_max_retries(),
            cache_enabled: default_cache_enabled(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout(),
            max_concurrency: default_max_concurrency(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from file
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        let mut config = if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            toml::from_str(&content)?
        } else {
            info!("Configuration file not found, using defaults");
            Self::default()
        };
        
        // Override with environment variables
        config.apply_env_overrides();
        
        info!("Configuration loaded successfully");
        Ok(config)
    }
    
    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        if let Ok(endpoint) = std::env::var("TEMPLATE_API_ENDPOINT") {
            self.api_endpoint = endpoint;
        }
        
        if let Ok(key) = std::env::var("TEMPLATE_API_KEY") {
            self.api_key = key;
        }
        
        if let Ok(retries) = std::env::var("TEMPLATE_MAX_RETRIES") {
            if let Ok(retries) = retries.parse() {
                self.max_retries = retries;
            }
        }
        
        if let Ok(cache) = std::env::var("TEMPLATE_CACHE_ENABLED") {
            self.cache_enabled = cache.to_lowercase() == "true";
        }
        
        if let Ok(level) = std::env::var("TEMPLATE_LOG_LEVEL") {
            self.logging.level = level;
        }
        
        if let Ok(timeout) = std::env::var("TEMPLATE_TIMEOUT_MS") {
            if let Ok(timeout) = timeout.parse() {
                self.performance.timeout_ms = timeout;
            }
        }
        
        if let Ok(concurrency) = std::env::var("TEMPLATE_MAX_CONCURRENCY") {
            if let Ok(concurrency) = concurrency.parse() {
                self.performance.max_concurrency = concurrency;
            }
        }
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.api_endpoint.is_empty() {
            anyhow::bail!("API endpoint cannot be empty");
        }
        
        if self.max_retries > 10 {
            anyhow::bail!("Max retries cannot exceed 10");
        }
        
        if self.performance.timeout_ms < 1000 {
            anyhow::bail!("Timeout must be at least 1000ms");
        }
        
        if self.performance.max_concurrency == 0 {
            anyhow::bail!("Max concurrency must be greater than 0");
        }
        
        Ok(())
    }
}