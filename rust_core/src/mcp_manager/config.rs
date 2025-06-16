//! MCP Server configuration with API key management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

/// MCP Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub server_type: ServerType,
    pub url: String,
    pub port: u16,
    pub auth: Option<AuthConfig>,
    pub capabilities: Vec<String>,
    pub max_connections: usize,
    pub timeout_ms: u64,
    pub retry_policy: RetryPolicy,
    pub priority: u8,
    pub tags: Vec<String>,
}

/// Server authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

/// Authentication type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    ApiKey,
    OAuth2,
    Bearer,
    Basic,
    None,
}

/// Server type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServerType {
    // DevOps
    Docker,
    Kubernetes,
    Git,
    GitHub,
    
    // Infrastructure
    Prometheus,
    S3,
    CloudStorage,
    Slack,
    Commander,
    
    // Security
    SAST,
    SecurityScanner,
    SupplyChain,
    
    // Search/Knowledge
    BraveSearch,
    
    // Communication
    Hub,
    
    // Special
    Smithery,
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub exponential_base: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            exponential_base: 2.0,
        }
    }
}

/// MCP Manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpManagerConfig {
    pub servers: Vec<ServerConfig>,
    pub default_timeout_ms: u64,
    pub max_concurrent_requests: usize,
    pub circuit_breaker_threshold: f64,
    pub circuit_breaker_timeout_ms: u64,
    pub deployment: DeploymentConfig,
}

impl Default for McpManagerConfig {
    fn default() -> Self {
        Self::load_with_env()
    }
}

impl McpManagerConfig {
    /// Load configuration with API keys from environment
    pub fn load_with_env() -> Self {
        // Load .env.mcp file if it exists
        let env_path = PathBuf::from(".env.mcp");
        if env_path.exists() {
            dotenv::from_path(&env_path).ok();
        }
        
        let mut servers = vec![
            // DevOps Servers
            ServerConfig {
                name: "docker".to_string(),
                server_type: ServerType::Docker,
                url: "http://localhost:8001".to_string(),
                port: 8001,
                auth: None,
                capabilities: vec![
                    "container.list".to_string(),
                    "container.create".to_string(),
                    "container.remove".to_string(),
                    "image.pull".to_string(),
                ],
                max_connections: 50,
                timeout_ms: 30000,
                retry_policy: RetryPolicy::default(),
                priority: 10,
                tags: vec!["devops".to_string(), "container".to_string()],
            },
            ServerConfig {
                name: "kubernetes".to_string(),
                server_type: ServerType::Kubernetes,
                url: "http://localhost:8002".to_string(),
                port: 8002,
                auth: None,
                capabilities: vec![
                    "pod.list".to_string(),
                    "deployment.create".to_string(),
                    "service.expose".to_string(),
                    "namespace.manage".to_string(),
                ],
                max_connections: 50,
                timeout_ms: 30000,
                retry_policy: RetryPolicy::default(),
                priority: 10,
                tags: vec!["devops".to_string(), "container".to_string()],
            },
            ServerConfig {
                name: "git".to_string(),
                server_type: ServerType::Git,
                url: "http://localhost:8003".to_string(),
                port: 8003,
                auth: None,
                capabilities: vec![
                    "repo.clone".to_string(),
                    "commit.create".to_string(),
                    "branch.manage".to_string(),
                    "merge.perform".to_string(),
                ],
                max_connections: 30,
                timeout_ms: 60000,
                retry_policy: RetryPolicy::default(),
                priority: 8,
                tags: vec!["devops".to_string(), "vcs".to_string()],
            },
        ];
        
        // GitHub with API key
        if let Ok(github_token) = env::var("GITHUB_TOKEN") {
            servers.push(ServerConfig {
                name: "github".to_string(),
                server_type: ServerType::GitHub,
                url: "https://api.github.com".to_string(),
                port: 443,
                auth: Some(AuthConfig {
                    auth_type: AuthType::Bearer,
                    credentials: {
                        let mut creds = HashMap::new();
                        creds.insert("token".to_string(), github_token);
                        creds
                    },
                }),
                capabilities: vec![
                    "pr.create".to_string(),
                    "issue.manage".to_string(),
                    "workflow.trigger".to_string(),
                    "release.create".to_string(),
                ],
                max_connections: 30,
                timeout_ms: 30000,
                retry_policy: RetryPolicy::default(),
                priority: 9,
                tags: vec!["devops".to_string(), "github".to_string()],
            });
        }
        
        // Infrastructure Servers
        servers.push(ServerConfig {
            name: "prometheus".to_string(),
            server_type: ServerType::Prometheus,
            url: env::var("PROMETHEUS_URL").unwrap_or_else(|_| "http://localhost:9090".to_string()),
            port: 9090,
            auth: None,
            capabilities: vec![
                "metrics.query".to_string(),
                "alerts.manage".to_string(),
                "targets.monitor".to_string(),
            ],
            max_connections: 20,
            timeout_ms: 10000,
            retry_policy: RetryPolicy::default(),
            priority: 7,
            tags: vec!["infrastructure".to_string(), "monitoring".to_string()],
        });
        
        // S3 with AWS credentials
        if let (Ok(access_key), Ok(secret_key)) = (
            env::var("AWS_ACCESS_KEY_ID"),
            env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            servers.push(ServerConfig {
                name: "s3".to_string(),
                server_type: ServerType::S3,
                url: "https://s3.amazonaws.com".to_string(),
                port: 443,
                auth: Some(AuthConfig {
                    auth_type: AuthType::Basic,
                    credentials: {
                        let mut creds = HashMap::new();
                        creds.insert("access_key".to_string(), access_key);
                        creds.insert("secret_key".to_string(), secret_key);
                        creds
                    },
                }),
                capabilities: vec![
                    "bucket.create".to_string(),
                    "object.upload".to_string(),
                    "object.download".to_string(),
                    "lifecycle.manage".to_string(),
                ],
                max_connections: 100,
                timeout_ms: 60000,
                retry_policy: RetryPolicy::default(),
                priority: 8,
                tags: vec!["infrastructure".to_string(), "storage".to_string()],
            });
        }
        
        // Brave Search with API key
        if let Ok(brave_key) = env::var("BRAVE_API_KEY") {
            servers.push(ServerConfig {
                name: "brave-search".to_string(),
                server_type: ServerType::BraveSearch,
                url: "https://api.search.brave.com".to_string(),
                port: 443,
                auth: Some(AuthConfig {
                    auth_type: AuthType::ApiKey,
                    credentials: {
                        let mut creds = HashMap::new();
                        creds.insert("api_key".to_string(), brave_key);
                        creds
                    },
                }),
                capabilities: vec![
                    "web.search".to_string(),
                    "news.search".to_string(),
                    "image.search".to_string(),
                ],
                max_connections: 20,
                timeout_ms: 15000,
                retry_policy: RetryPolicy::default(),
                priority: 6,
                tags: vec!["search".to_string(), "knowledge".to_string()],
            });
        }
        
        // Smithery with API key
        if let Ok(smithery_key) = env::var("SMITHERY_API_KEY") {
            servers.push(ServerConfig {
                name: "smithery".to_string(),
                server_type: ServerType::Smithery,
                url: "https://api.smithery.ai".to_string(),
                port: 443,
                auth: Some(AuthConfig {
                    auth_type: AuthType::ApiKey,
                    credentials: {
                        let mut creds = HashMap::new();
                        creds.insert("api_key".to_string(), smithery_key);
                        creds
                    },
                }),
                capabilities: vec![
                    "forge.create".to_string(),
                    "forge.deploy".to_string(),
                    "forge.monitor".to_string(),
                ],
                max_connections: 30,
                timeout_ms: 30000,
                retry_policy: RetryPolicy::default(),
                priority: 8,
                tags: vec!["smithery".to_string(), "ai".to_string()],
            });
        }
        
        // Security Servers
        servers.extend(vec![
            ServerConfig {
                name: "sast".to_string(),
                server_type: ServerType::SAST,
                url: "http://localhost:8020".to_string(),
                port: 8020,
                auth: None,
                capabilities: vec![
                    "code.scan".to_string(),
                    "vulnerability.detect".to_string(),
                    "compliance.check".to_string(),
                ],
                max_connections: 10,
                timeout_ms: 120000,
                retry_policy: RetryPolicy::default(),
                priority: 9,
                tags: vec!["security".to_string(), "sast".to_string()],
            },
            ServerConfig {
                name: "security-scanner".to_string(),
                server_type: ServerType::SecurityScanner,
                url: "http://localhost:8021".to_string(),
                port: 8021,
                auth: None,
                capabilities: vec![
                    "port.scan".to_string(),
                    "service.audit".to_string(),
                    "config.validate".to_string(),
                ],
                max_connections: 10,
                timeout_ms: 60000,
                retry_policy: RetryPolicy::default(),
                priority: 9,
                tags: vec!["security".to_string(), "scanner".to_string()],
            },
        ]);
        
        McpManagerConfig {
            servers,
            default_timeout_ms: 30000,
            max_concurrent_requests: 100,
            circuit_breaker_threshold: 0.5,
            circuit_breaker_timeout_ms: 60000,
            deployment: DeploymentConfig {
                max_concurrent_deployments: 10,
                deployment_timeout_ms: 300000,
                rollback_on_failure: true,
                auto_scaling: false,
                scale_up_threshold: 0.8,
                scale_down_threshold: 0.2,
                min_instances: 1,
                max_instances: 10,
                strategy: DeploymentStrategy::RollingUpdate,
            },
        }
    }
    
    /// Get server configuration by type
    pub fn get_server(&self, server_type: ServerType) -> Option<&ServerConfig> {
        self.servers.iter().find(|s| s.server_type == server_type)
    }
    
    /// Get all servers of a specific type category
    pub fn get_servers_by_category(&self, category: &str) -> Vec<&ServerConfig> {
        self.servers.iter().filter(|s| {
            match category {
                "devops" => matches!(s.server_type, ServerType::Docker | ServerType::Kubernetes | ServerType::Git | ServerType::GitHub),
                "infrastructure" => matches!(s.server_type, ServerType::Prometheus | ServerType::S3 | ServerType::CloudStorage | ServerType::Slack | ServerType::Commander),
                "security" => matches!(s.server_type, ServerType::SAST | ServerType::SecurityScanner | ServerType::SupplyChain),
                "search" => matches!(s.server_type, ServerType::BraveSearch),
                "communication" => matches!(s.server_type, ServerType::Hub),
                _ => false,
            }
        }).collect()
    }
}

/// Deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub max_concurrent_deployments: usize,
    pub deployment_timeout_ms: u64,
    pub rollback_on_failure: bool,
    pub auto_scaling: bool,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
    pub min_instances: usize,
    pub max_instances: usize,
    pub strategy: DeploymentStrategy,
}

/// Deployment strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStrategy {
    RollingUpdate,
    BlueGreen,
    Canary { percentage: u8 },
    Recreate,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_ms: u64,
    pub half_open_max_calls: u32,
}

/// Main MCP configuration (alias for McpManagerConfig)
pub type McpConfig = McpManagerConfig;