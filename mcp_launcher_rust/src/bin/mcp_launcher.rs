//! MCP Server Launcher Binary
//! 
//! Production-grade launcher that actually spawns MCP server processes
//! with proper configuration, monitoring, and graceful shutdown.

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpServerConfig {
    name: String,
    category: String,
    command: String,
    args: Vec<String>,
    port: u16,
    requires_auth: bool,
    auth_env_var: Option<String>,
    capabilities: Vec<String>,
    health_check_url: Option<String>,
    restart_on_failure: bool,
    max_restarts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpServerInstance {
    config: McpServerConfig,
    status: ServerStatus,
    pid: Option<u32>,
    restart_count: u32,
    last_health_check: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum ServerStatus {
    Stopped,
    Starting,
    Running,
    Failed,
    MissingAuth,
    Restarting,
}

struct McpLauncher {
    servers: Arc<RwLock<HashMap<String, McpServerInstance>>>,
    processes: Arc<RwLock<HashMap<String, Child>>>,
    config_path: PathBuf,
}

impl McpLauncher {
    fn new() -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            processes: Arc::new(RwLock::new(HashMap::new())),
            config_path: PathBuf::from("mcp_servers.json"),
        }
    }

    async fn load_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Default MCP server configurations
        let default_configs = vec![
            // File system server
            McpServerConfig {
                name: "filesystem".to_string(),
                category: "core".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-filesystem".to_string(),
                    "/home/louranicas/projects".to_string(),
                ],
                port: 8001,
                requires_auth: false,
                auth_env_var: None,
                capabilities: vec!["file.read".to_string(), "file.write".to_string(), "dir.list".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // GitHub server
            McpServerConfig {
                name: "github".to_string(),
                category: "integration".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-github".to_string(),
                ],
                port: 8002,
                requires_auth: true,
                auth_env_var: Some("GITHUB_TOKEN".to_string()),
                capabilities: vec!["repo.read".to_string(), "pr.create".to_string(), "issue.manage".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // Memory server
            McpServerConfig {
                name: "memory".to_string(),
                category: "core".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-memory".to_string(),
                ],
                port: 8003,
                requires_auth: false,
                auth_env_var: None,
                capabilities: vec!["memory.store".to_string(), "memory.retrieve".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // Puppeteer server
            McpServerConfig {
                name: "puppeteer".to_string(),
                category: "automation".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-puppeteer".to_string(),
                ],
                port: 8004,
                requires_auth: false,
                auth_env_var: None,
                capabilities: vec!["browser.navigate".to_string(), "page.screenshot".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // Brave search server (if API key exists)
            McpServerConfig {
                name: "brave-search".to_string(),
                category: "search".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-brave-search".to_string(),
                ],
                port: 8005,
                requires_auth: true,
                auth_env_var: Some("BRAVE_API_KEY".to_string()),
                capabilities: vec!["search.web".to_string(), "search.news".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // Google Maps server (if API key exists)
            McpServerConfig {
                name: "google-maps".to_string(),
                category: "integration".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-google-maps".to_string(),
                ],
                port: 8006,
                requires_auth: true,
                auth_env_var: Some("GOOGLE_MAPS_API_KEY".to_string()),
                capabilities: vec!["maps.search".to_string(), "maps.directions".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
            
            // SQLite server
            McpServerConfig {
                name: "sqlite".to_string(),
                category: "database".to_string(),
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-sqlite".to_string(),
                    "./data/mcp.db".to_string(),
                ],
                port: 8007,
                requires_auth: false,
                auth_env_var: None,
                capabilities: vec!["db.query".to_string(), "db.execute".to_string()],
                health_check_url: None,
                restart_on_failure: true,
                max_restarts: 3,
            },
        ];

        // Convert to instances
        let mut servers = HashMap::new();
        for config in default_configs {
            let instance = McpServerInstance {
                config: config.clone(),
                status: ServerStatus::Stopped,
                pid: None,
                restart_count: 0,
                last_health_check: None,
            };
            servers.insert(config.name.clone(), instance);
        }

        *self.servers.write().await = servers;
        Ok(())
    }

    async fn check_auth(&self, server: &McpServerConfig) -> bool {
        if !server.requires_auth {
            return true;
        }

        if let Some(env_var) = &server.auth_env_var {
            env::var(env_var).is_ok()
        } else {
            false
        }
    }

    async fn launch_server(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut servers = self.servers.write().await;
        let server = servers.get_mut(name).ok_or("Server not found")?;

        // Check authentication
        if !self.check_auth(&server.config).await {
            server.status = ServerStatus::MissingAuth;
            if let Some(env_var) = &server.config.auth_env_var {
                warn!("⚠️  {} server skipped: {} not configured", name, env_var);
            }
            return Ok(());
        }

        server.status = ServerStatus::Starting;
        info!("🚀 Starting {} server...", name);

        // Set up environment
        let mut env_vars = std::env::vars().collect::<HashMap<_, _>>();
        env_vars.insert("MCP_SERVER_NAME".to_string(), name.to_string());
        env_vars.insert("MCP_SERVER_PORT".to_string(), server.config.port.to_string());

        // Create command
        let mut cmd = TokioCommand::new(&server.config.command);
        cmd.args(&server.config.args)
            .envs(env_vars)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn process
        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                server.pid = pid;
                server.status = ServerStatus::Running;
                
                // Store process handle
                let mut processes = self.processes.write().await;
                processes.insert(name.to_string(), child);
                
                info!("✅ {} server started (PID: {:?})", name, pid);
                Ok(())
            }
            Err(e) => {
                error!("❌ Failed to start {} server: {}", name, e);
                server.status = ServerStatus::Failed;
                Err(Box::new(e))
            }
        }
    }

    async fn launch_all(&self) {
        info!("{}", "=".repeat(60));
        info!("🦀 MCP Server Launcher - Process Manager Edition");
        info!("{}", "=".repeat(60));

        let server_names: Vec<String> = {
            let servers = self.servers.read().await;
            servers.keys().cloned().collect()
        };

        let mut launched = 0;
        let mut failed = 0;
        let mut skipped = 0;

        for name in server_names {
            match self.launch_server(&name).await {
                Ok(_) => {
                    let servers = self.servers.read().await;
                    if let Some(server) = servers.get(&name) {
                        match server.status {
                            ServerStatus::Running => launched += 1,
                            ServerStatus::MissingAuth => skipped += 1,
                            _ => failed += 1,
                        }
                    }
                }
                Err(_) => failed += 1,
            }
            
            // Small delay between launches
            sleep(Duration::from_millis(100)).await;
        }

        info!("\n{}", "=".repeat(60));
        info!("📊 Launch Summary:");
        info!("✅ Launched: {} servers", launched);
        if failed > 0 {
            info!("❌ Failed: {} servers", failed);
        }
        if skipped > 0 {
            info!("⚠️  Skipped: {} servers (missing auth)", skipped);
        }
        info!("{}", "=".repeat(60));
    }

    async fn monitor_servers(&self) {
        loop {
            sleep(Duration::from_secs(30)).await;
            
            let mut servers = self.servers.write().await;
            let mut processes = self.processes.write().await;
            
            let mut to_restart = Vec::new();
            
            for (name, server) in servers.iter_mut() {
                if server.status == ServerStatus::Running {
                    // Check if process is still alive
                    if let Some(mut child) = processes.remove(name) {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                // Process exited
                                warn!("⚠️  {} server exited with status: {:?}", name, status);
                                server.status = ServerStatus::Failed;
                                server.pid = None;
                                
                                if server.config.restart_on_failure && 
                                   server.restart_count < server.config.max_restarts {
                                    to_restart.push(name.clone());
                                }
                            }
                            Ok(None) => {
                                // Still running
                                processes.insert(name.clone(), child);
                            }
                            Err(e) => {
                                error!("❌ Error checking {} server status: {}", name, e);
                                processes.insert(name.clone(), child);
                            }
                        }
                    }
                }
            }
            
            drop(servers);
            drop(processes);
            
            // Restart failed servers
            for name in to_restart {
                info!("🔄 Attempting to restart {} server...", name);
                {
                    let mut servers = self.servers.write().await;
                    if let Some(server) = servers.get_mut(&name) {
                        server.restart_count += 1;
                        server.status = ServerStatus::Restarting;
                    }
                }
                
                sleep(Duration::from_secs(2)).await;
                
                if let Err(e) = self.launch_server(&name).await {
                    error!("❌ Failed to restart {} server: {}", name, e);
                }
            }
            
            // Log status
            let servers = self.servers.read().await;
            let running = servers.values().filter(|s| s.status == ServerStatus::Running).count();
            let total = servers.len();
            info!("📊 Health check: {}/{} servers running", running, total);
        }
    }

    async fn shutdown(&self) {
        info!("🛑 Shutting down MCP servers...");
        
        let mut processes = self.processes.write().await;
        let mut servers = self.servers.write().await;
        
        for (name, mut child) in processes.drain() {
            info!("  Stopping {} server...", name);
            
            // Try graceful shutdown first
            if let Some(pid) = child.id() {
                // Send SIGTERM
                let _ = Command::new("kill")
                    .args(&["-TERM", &pid.to_string()])
                    .output();
                
                // Wait a bit for graceful shutdown
                sleep(Duration::from_secs(2)).await;
                
                // Check if still running and force kill if needed
                match child.try_wait() {
                    Ok(None) => {
                        // Still running, force kill
                        let _ = child.kill().await;
                    }
                    _ => {}
                }
            }
            
            if let Some(server) = servers.get_mut(name) {
                server.status = ServerStatus::Stopped;
                server.pid = None;
            }
        }
        
        info!("✅ All servers shut down");
    }

    async fn status(&self) {
        let servers = self.servers.read().await;
        
        info!("\n{}", "=".repeat(60));
        info!("📊 MCP Server Status");
        info!("{}", "=".repeat(60));
        
        // Group by category
        let mut by_category: HashMap<&str, Vec<(&String, &McpServerInstance)>> = HashMap::new();
        
        for (name, server) in servers.iter() {
            by_category
                .entry(&server.config.category)
                .or_insert_with(Vec::new)
                .push((name, server));
        }
        
        for (category, servers) in by_category {
            info!("\n{} Servers:", category.to_uppercase());
            
            for (name, server) in servers {
                let status_icon = match server.status {
                    ServerStatus::Running => "🟢",
                    ServerStatus::Starting => "🟡",
                    ServerStatus::MissingAuth => "🔴",
                    ServerStatus::Failed => "❌",
                    ServerStatus::Stopped => "⭕",
                    ServerStatus::Restarting => "🔄",
                };
                
                let pid_info = server.pid
                    .map(|p| format!(" (PID: {})", p))
                    .unwrap_or_default();
                
                let restart_info = if server.restart_count > 0 {
                    format!(" [restarts: {}/{}]", server.restart_count, server.config.max_restarts)
                } else {
                    String::new()
                };
                
                info!("  {} {} - Port {}{}{}", 
                    status_icon, 
                    name, 
                    server.config.port,
                    pid_info,
                    restart_info
                );
                
                if server.status == ServerStatus::MissingAuth {
                    if let Some(env_var) = &server.config.auth_env_var {
                        info!("     ⚠️  Missing: {}", env_var);
                    }
                }
            }
        }
        
        info!("\n{}", "=".repeat(60));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter("mcp_launcher=debug")
        .init();

    // Load environment variables
    let env_files = vec![".env", ".env.local", ".env.mcp"];
    for env_file in env_files {
        let path = PathBuf::from(env_file);
        if path.exists() {
            dotenv::from_path(&path).ok();
            info!("✅ Loaded environment from {}", env_file);
        }
    }

    // Create launcher
    let launcher = McpLauncher::new();
    
    // Load configuration
    launcher.load_config().await?;
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    match args.get(1).map(|s| s.as_str()) {
        Some("status") => {
            launcher.status().await;
        }
        Some("stop") => {
            launcher.shutdown().await;
        }
        Some("launch") => {
            if let Some(server_name) = args.get(2) {
                launcher.launch_server(server_name).await?;
                launcher.status().await;
            } else {
                eprintln!("Usage: mcp_launcher launch <server_name>");
            }
        }
        _ => {
            // Default: launch all servers
            launcher.launch_all().await;
            launcher.status().await;
            
            info!("\n📡 MCP servers are running. Press Ctrl+C to stop.");
            
            // Start monitoring
            let monitor_task = tokio::spawn({
                let launcher_clone = launcher.clone();
                async move {
                    launcher_clone.monitor_servers().await;
                }
            });
            
            // Wait for shutdown signal
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            
            // Cleanup
            monitor_task.abort();
            launcher.shutdown().await;
        }
    }

    Ok(())
}

// Required for Arc<RwLock<>> to work with async
impl Clone for McpLauncher {
    fn clone(&self) -> Self {
        Self {
            servers: Arc::clone(&self.servers),
            processes: Arc::clone(&self.processes),
            config_path: self.config_path.clone(),
        }
    }
}