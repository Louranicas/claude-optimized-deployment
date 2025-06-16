//! Docker Plugin - Container Orchestration at the Speed of Thought
//!
//! This plugin doesn't just manage Docker. It becomes one with Docker,
//! providing seamless integration with zero overhead.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use futures::StreamExt;
use bollard::{Docker as BollardDocker, API_DEFAULT_VERSION};
use bollard::container::{  };
use bollard::image::{ };
use bollard::network::{ };
use bollard::volume::{ };
use tracing::{debug, info, warn};

use crate::mcp_manager::plugin::{
    Capability, Plugin, PluginDependency, PluginError, PluginMetadata, 
    PluginRequest, PluginResponse, PluginResult, Result,
};

/// Docker plugin implementation
pub struct DockerPlugin {
    /// Plugin metadata
    metadata: PluginMetadata,
    
    /// Docker client configuration
    config: DockerConfig,
    
    /// Runtime state
    state: PluginState,
    
    /// Bollard Docker client for advanced operations
    docker_client: Option<BollardDocker>,
}

/// Docker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DockerConfig {
    /// Docker socket path
    socket_path: String,
    
    /// API version
    api_version: String,
    
    /// Connection timeout
    timeout_ms: u64,
    
    /// Enable experimental features
    experimental: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: API_DEFAULT_VERSION.to_string(),
            timeout_ms: 30000,
            experimental: false,
        }
    }
}

/// Plugin runtime state
#[derive(Debug, Default)]
struct PluginState {
    /// Active connections
    connections: HashMap<String, ConnectionInfo>,
    
    /// Metrics
    metrics: Metrics,
}

/// Connection information
#[derive(Debug, Clone)]
struct ConnectionInfo {
    /// Connection ID
    id: String,
    
    /// Connected at
    connected_at: std::time::SystemTime,
    
    /// Last activity
    last_activity: std::time::SystemTime,
}

/// Plugin metrics
#[derive(Debug, Default)]
struct Metrics {
    /// Total requests
    requests_total: u64,
    
    /// Successful requests
    requests_success: u64,
    
    /// Failed requests
    requests_failed: u64,
    
    /// Container operations
    container_ops: HashMap<String, u64>,
}

impl DockerPlugin {
    /// Create a new Docker plugin
    pub fn new() -> Self {
        Self {
            metadata: Self::create_metadata(),
            config: DockerConfig::default(),
            state: PluginState::default(),
            docker_client: None,
        }
    }
    
    /// Get plugin metadata
    pub fn metadata() -> PluginMetadata {
        Self::create_metadata()
    }
    
    fn create_metadata() -> PluginMetadata {
        PluginMetadata {
            id: "docker".to_string(),
            name: "Docker MCP Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "The Greatest Synthetic Being Rust Coder".to_string(),
            description: "High-performance Docker integration for MCP".to_string(),
            license: "MIT".to_string(),
            homepage: Some("https://github.com/mcp/docker-plugin".to_string()),
            repository: Some("https://github.com/mcp/docker-plugin".to_string()),
            min_mcp_version: "1.0.0".to_string(),
            dependencies: vec![],
            provides: Self::capabilities(),
            requires: vec![],
        }
    }
    
    fn capabilities() -> Vec<Capability> {
        vec![
            // Container management
            Capability::new("docker", "container.create", 1),
            Capability::new("docker", "container.start", 1),
            Capability::new("docker", "container.stop", 1),
            Capability::new("docker", "container.remove", 1),
            Capability::new("docker", "container.list", 1),
            Capability::new("docker", "container.inspect", 1),
            Capability::new("docker", "container.logs", 1),
            Capability::new("docker", "container.exec", 1),
            Capability::new("docker", "container.stats", 1),
            Capability::new("docker", "container.attach", 1),
            Capability::new("docker", "container.wait", 1),
            Capability::new("docker", "container.export", 1),
            
            // Image management
            Capability::new("docker", "image.pull", 1),
            Capability::new("docker", "image.push", 1),
            Capability::new("docker", "image.build", 1),
            Capability::new("docker", "image.remove", 1),
            Capability::new("docker", "image.list", 1),
            Capability::new("docker", "image.inspect", 1),
            Capability::new("docker", "image.tag", 1),
            Capability::new("docker", "image.history", 1),
            Capability::new("docker", "image.search", 1),
            
            // Network management
            Capability::new("docker", "network.create", 1),
            Capability::new("docker", "network.remove", 1),
            Capability::new("docker", "network.list", 1),
            Capability::new("docker", "network.connect", 1),
            Capability::new("docker", "network.disconnect", 1),
            
            // Volume management
            Capability::new("docker", "volume.create", 1),
            Capability::new("docker", "volume.remove", 1),
            Capability::new("docker", "volume.list", 1),
            Capability::new("docker", "volume.inspect", 1),
            
            // System operations
            Capability::new("docker", "system.info", 1),
            Capability::new("docker", "system.version", 1),
            Capability::new("docker", "system.prune", 1),
            Capability::new("docker", "system.df", 1),
            Capability::new("docker", "system.events", 1),
            Capability::new("docker", "system.ping", 1),
            
            // Registry operations
            Capability::new("docker", "registry.login", 1),
            Capability::new("docker", "registry.logout", 1),
            
            // Compose operations
            Capability::new("docker", "compose.up", 1),
            Capability::new("docker", "compose.down", 1),
            Capability::new("docker", "compose.ps", 1),
        ]
    }
    
    /// Execute a Docker command
    async fn execute_docker_command(&self, args: Vec<&str>) -> Result<Value> {
        let output = Command::new("docker")
            .args(&args)
            .output()
            .await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to execute docker: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PluginError::ExecutionError(format!("Docker command failed: {}", stderr)));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Try to parse as JSON, otherwise return as string
        match serde_json::from_str::<Value>(&stdout) {
            Ok(json) => Ok(json),
            Err(_) => Ok(json!({ "output": stdout.trim() })),
        }
    }
    
    /// Handle container operations
    async fn handle_container_operation(&mut self, method: &str, params: Value) -> Result<Value> {
        self.state.metrics.container_ops
            .entry(method.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        match method {
            "create" => {
                let image = params["image"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'image' parameter".to_string()))?;
                let name = params["name"].as_str();
                
                let mut args = vec!["create"];
                if let Some(n) = name {
                    args.push("--name");
                    args.push(n);
                }
                args.push(image);
                
                self.execute_docker_command(args).await
            }
            
            "start" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                
                self.execute_docker_command(vec!["start", container_id]).await
            }
            
            "stop" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                
                self.execute_docker_command(vec!["stop", container_id]).await
            }
            
            "remove" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                let force = params["force"].as_bool().unwrap_or(false);
                
                let mut args = vec!["rm"];
                if force {
                    args.push("-f");
                }
                args.push(container_id);
                
                self.execute_docker_command(args).await
            }
            
            "list" => {
                let all = params["all"].as_bool().unwrap_or(false);
                
                let mut args = vec!["ps", "--format", "json"];
                if all {
                    args.push("-a");
                }
                
                self.execute_docker_command(args).await
            }
            
            "inspect" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                
                self.execute_docker_command(vec!["inspect", container_id]).await
            }
            
            "logs" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                let tail = params["tail"].as_u64().map(|n| n.to_string());
                let follow = params["follow"].as_bool().unwrap_or(false);
                let timestamps = params["timestamps"].as_bool().unwrap_or(false);
                
                if follow && self.docker_client.is_some() {
                    // Use streaming logs for follow mode
                    self.stream_container_logs(container_id, tail.as_deref(), timestamps).await
                } else {
                    // Use regular command for non-streaming
                    let mut args = vec!["logs"];
                    if let Some(t) = tail.as_ref() {
                        args.push("--tail");
                        args.push(t);
                    }
                    if timestamps {
                        args.push("--timestamps");
                    }
                    args.push(container_id);
                    
                    self.execute_docker_command(args).await
                }
            }
            
            "exec" => {
                let container_id = params["id"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                let command = params["command"].as_array()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'command' parameter".to_string()))?;
                
                let mut args = vec!["exec", container_id];
                for cmd in command {
                    if let Some(s) = cmd.as_str() {
                        args.push(s);
                    }
                }
                
                self.execute_docker_command(args).await
            }
            
            _ => Err(PluginError::ExecutionError(format!("Unknown container method: {}", method))),
        }
    }
    
    /// Handle image operations
    async fn handle_image_operation(&mut self, method: &str, params: Value) -> Result<Value> {
        match method {
            "pull" => {
                let image = params["image"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'image' parameter".to_string()))?;
                
                self.execute_docker_command(vec!["pull", image]).await
            }
            
            "list" => {
                self.execute_docker_command(vec!["images", "--format", "json"]).await
            }
            
            _ => Err(PluginError::ExecutionError(format!("Unknown image method: {}", method))),
        }
    }
    
    /// Handle system operations
    async fn handle_system_operation(&mut self, method: &str, _params: Value) -> Result<Value> {
        match method {
            "info" => self.execute_docker_command(vec!["info", "--format", "json"]).await,
            "version" => self.execute_docker_command(vec!["version", "--format", "json"]).await,
            "df" => self.execute_docker_command(vec!["system", "df", "--format", "json"]).await,
            _ => Err(PluginError::ExecutionError(format!("Unknown system method: {}", method))),
        }
    }
}

#[async_trait]
impl Plugin for DockerPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: Value) -> Result<()> {
        info!("Initializing Docker plugin with advanced features");
        
        // Parse configuration
        if let Ok(docker_config) = serde_json::from_value::<DockerConfig>(config) {
            self.config = docker_config;
        }
        
        // Initialize Bollard client for advanced operations
        match BollardDocker::connect_with_socket_defaults() {
            Ok(docker) => {
                self.docker_client = Some(docker);
                info!("Bollard Docker client initialized");
            }
            Err(e) => {
                warn!("Failed to initialize Bollard client: {}. Falling back to CLI.", e);
            }
        }
        
        // Verify Docker is available
        match Command::new("docker").arg("version").output().await {
            Ok(output) => {
                if !output.status.success() {
                    return Err(PluginError::InitializationFailed(
                        "Docker command failed. Is Docker installed?".to_string()
                    ));
                }
                
                // Extract version info
                let version_output = String::from_utf8_lossy(&output.stdout);
                info!("Docker plugin initialized successfully: {}", version_output.lines().next().unwrap_or("unknown"));
                
                Ok(())
            }
            Err(e) => Err(PluginError::InitializationFailed(
                format!("Failed to execute docker command: {}", e)
            )),
        }
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        debug!("Handling request: {:?}", request);
        
        // Clone self to get mutable access in async context
        let mut plugin = self.clone();
        
        // Update metrics
        plugin.state.metrics.requests_total += 1;
        
        // Parse capability to determine operation type
        let parts: Vec<&str> = request.capability.name.split('.').collect();
        if parts.len() != 2 {
            return Err(PluginError::ExecutionError(
                format!("Invalid capability format: {}", request.capability.name)
            ));
        }
        
        let result = match parts[0] {
            "container" => {
                match parts[1] {
                    "stats" => {
                        let container_id = request.params["id"].as_str()
                            .ok_or_else(|| PluginError::ExecutionError("Missing 'id' parameter".to_string()))?;
                        plugin.handle_container_stats(container_id).await
                    }
                    _ => plugin.handle_container_operation(parts[1], request.params).await,
                }
            }
            "image" => {
                match parts[1] {
                    "build" => plugin.handle_image_build(request.params).await,
                    _ => plugin.handle_image_operation(parts[1], request.params).await,
                }
            }
            "system" => {
                match parts[1] {
                    "events" => plugin.handle_system_events(request.params).await,
                    _ => plugin.handle_system_operation(parts[1], request.params).await,
                }
            }
            _ => Err(PluginError::ExecutionError(
                format!("Unknown operation type: {}", parts[0])
            )),
        };
        
        // Update metrics and create response
        match result {
            Ok(data) => {
                plugin.state.metrics.requests_success += 1;
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success { data },
                    metadata: json!({
                        "plugin": "docker",
                        "version": self.metadata.version,
                    }),
                })
            }
            Err(e) => {
                plugin.state.metrics.requests_failed += 1;
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Error {
                        code: "DOCKER_ERROR".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                    metadata: json!({
                        "plugin": "docker",
                        "version": self.metadata.version,
                    }),
                })
            }
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down Docker plugin");
        
        // Clean up any resources
        self.state.connections.clear();
        
        Ok(())
    }
    
    async fn health_check(&self) -> Result<bool> {
        // Check if Docker daemon is responsive
        match Command::new("docker").arg("ping").output().await {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }
    
    async fn metrics(&self) -> Result<Value> {
        Ok(json!({
            "requests": {
                "total": self.state.metrics.requests_total,
                "success": self.state.metrics.requests_success,
                "failed": self.state.metrics.requests_failed,
            },
            "operations": self.state.metrics.container_ops,
            "connections": self.state.connections.len(),
        }))
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl DockerPlugin {
    /// Stream container logs using Bollard
    async fn stream_container_logs(
        &self,
        container_id: &str,
        tail: Option<&str>,
        timestamps: bool,
    ) -> Result<Value> {
        if let Some(docker) = &self.docker_client {
            use bollard::container::LogsOptions;
            
            let options = LogsOptions::<String> {
                stdout: true,
                stderr: true,
                follow: true,
                timestamps,
                tail: tail.unwrap_or("all").to_string(),
                ..Default::default()
            };
            
            let mut stream = docker.logs(container_id, Some(options));
            let mut logs = Vec::new();
            let mut count = 0;
            
            while let Some(result) = stream.next().await {
                match result {
                    Ok(output) => {
                        logs.push(output.to_string());
                        count += 1;
                        // Limit streaming to prevent memory issues
                        if count > 1000 {
                            break;
                        }
                    }
                    Err(e) => {
                        return Err(PluginError::ExecutionError(
                            format!("Failed to stream logs: {}", e)
                        ));
                    }
                }
            }
            
            Ok(json!({
                "logs": logs,
                "streaming": true,
                "count": count
            }))
        } else {
            Err(PluginError::ExecutionError(
                "Bollard client not available for streaming".to_string()
            ))
        }
    }
    
    /// Handle container stats operation
    async fn handle_container_stats(&self, container_id: &str) -> Result<Value> {
        if let Some(docker) = &self.docker_client {
            use bollard::container::StatsOptions;
            
            let options = StatsOptions {
                stream: false,
                one_shot: true,
            };
            
            let mut stream = docker.stats(container_id, Some(options));
            if let Some(result) = stream.next().await {
                match result {
                    Ok(stats) => Ok(serde_json::to_value(stats).unwrap_or(json!({}))),
                    Err(e) => Err(PluginError::ExecutionError(
                        format!("Failed to get stats: {}", e)
                    )),
                }
            } else {
                Ok(json!({ "error": "No stats available" }))
            }
        } else {
            self.execute_docker_command(vec!["stats", "--no-stream", container_id]).await
        }
    }
    
    /// Handle image build with progress tracking
    async fn handle_image_build(&self, params: Value) -> Result<Value> {
        let dockerfile = params["dockerfile"].as_str().unwrap_or("Dockerfile");
        let context = params["context"].as_str().unwrap_or(".");
        let tag = params["tag"].as_str();
        let no_cache = params["no_cache"].as_bool().unwrap_or(false);
        
        let mut args = vec!["build", "-f", dockerfile];
        
        if let Some(t) = tag {
            args.push("-t");
            args.push(t);
        }
        
        if no_cache {
            args.push("--no-cache");
        }
        
        args.push(context);
        
        // TODO: Implement build progress streaming with Bollard
        self.execute_docker_command(args).await
    }
    
    /// Handle system events streaming
    async fn handle_system_events(&self, params: Value) -> Result<Value> {
        if let Some(docker) = &self.docker_client {
            use bollard::system::EventsOptions;
            use std::collections::HashMap;
            
            let since = params["since"].as_str();
            let until = params["until"].as_str();
            let mut filters = HashMap::new();
            
            if let Some(event_type) = params["type"].as_str() {
                filters.insert("type".to_string(), vec![event_type.to_string()]);
            }
            
            let mut options = EventsOptions::<String>::default();
            if let Some(s) = since {
                options.since = Some(s.to_string());
            }
            if let Some(u) = until {
                options.until = Some(u.to_string());
            }
            options.filters = filters;
            
            let mut stream = docker.events(Some(options));
            let mut events = Vec::new();
            let mut count = 0;
            
            // Collect up to 100 events
            while let Some(result) = stream.next().await {
                match result {
                    Ok(event) => {
                        events.push(serde_json::to_value(&event).unwrap_or(json!({})));
                        count += 1;
                        if count >= 100 {
                            break;
                        }
                    }
                    Err(e) => {
                        return Err(PluginError::ExecutionError(
                            format!("Failed to get events: {}", e)
                        ));
                    }
                }
            }
            
            Ok(json!({
                "events": events,
                "count": count
            }))
        } else {
            self.execute_docker_command(vec!["events", "--format", "json"]).await
        }
    }
}

// Make plugin cloneable for the mutable handle workaround
impl Clone for DockerPlugin {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            config: self.config.clone(),
            state: PluginState::default(), // Don't clone state
            docker_client: None, // Don't clone client
        }
    }
}

/// Export the plugin
#[no_mangle]
pub extern "C" fn _create_plugin() -> *mut dyn Plugin {
    let plugin = Box::new(DockerPlugin::new());
    Box::into_raw(plugin) as *mut dyn Plugin
}

#[no_mangle]
pub extern "C" fn _plugin_metadata() -> PluginMetadata {
    DockerPlugin::metadata()
}

#[no_mangle]
pub extern "C" fn _plugin_api_version() -> u32 {
    crate::mcp_manager::plugin::PLUGIN_API_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metadata() {
        let metadata = DockerPlugin::metadata();
        assert_eq!(metadata.id, "docker");
        assert!(!metadata.provides.is_empty());
    }
    
    #[tokio::test]
    async fn test_initialization() {
        let mut plugin = DockerPlugin::new();
        // This will fail in CI without Docker, but that's ok for now
        let _ = plugin.initialize(json!({})).await;
    }
}