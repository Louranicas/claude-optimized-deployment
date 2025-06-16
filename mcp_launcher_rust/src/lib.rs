//! MCP Launcher Library
//! 
//! Shared functionality for the MCP launcher

pub mod config {
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ServerConfig {
        pub name: String,
        pub command: String,
        pub args: Vec<String>,
        pub port: u16,
        pub requires_auth: bool,
        pub auth_env_var: Option<String>,
    }
}

pub mod launcher {
    pub const VERSION: &str = "1.0.0";
    pub const DEFAULT_PORT_START: u16 = 8000;
}