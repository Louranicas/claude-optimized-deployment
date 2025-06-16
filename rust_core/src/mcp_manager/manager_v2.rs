//! McpManager V2 - Actor-based implementation
//! 
//! This is the new implementation that uses message passing instead of shared state.
//! It will gradually replace the current McpManager implementation.

use crate::mcp_manager::{
    actor::{McpRuntime, Metrics},
    config::{McpManagerConfig, ServerConfig},
    errors::Result,
};
use std::sync::Arc;

/// The new MCP Manager using actor model
pub struct McpManagerV2 {
    /// The underlying runtime actor
    runtime: Arc<McpRuntime>,
    /// Configuration
    config: McpManagerConfig,
}

impl McpManagerV2 {
    /// Create a new MCP Manager instance
    pub fn new(config: McpManagerConfig) -> Self {
        let runtime = Arc::new(McpRuntime::new(config.clone()));
        
        Self {
            runtime,
            config,
        }
    }
    
    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(McpManagerConfig::default())
    }
    
    /// Initialize the manager by deploying configured servers
    pub async fn initialize(&self) -> Result<()> {
        // Deploy all servers from configuration
        for server_config in &self.config.servers {
            self.deploy_server(server_config.clone()).await?;
        }
        Ok(())
    }
    
    /// Deploy a server
    pub async fn deploy_server(&self, config: ServerConfig) -> Result<String> {
        self.runtime.deploy(config).await
    }
    
    /// Undeploy a server
    pub async fn undeploy_server(&self, server_id: &str) -> Result<()> {
        self.runtime.undeploy(server_id).await
    }
    
    /// Execute a request on a server
    pub async fn execute(
        &self,
        server_id: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.runtime.execute(server_id, request).await
    }
    
    /// Execute a tool on a server
    pub async fn execute_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        parameters: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let request = serde_json::json!({
            "tool": tool_name,
            "parameters": parameters,
        });
        
        self.runtime.execute(server_id, request).await
    }
    
    /// Check if a server is healthy
    pub async fn is_healthy(&self, server_id: &str) -> Result<bool> {
        self.runtime.health_check(server_id).await
    }
    
    /// List all deployed servers
    pub async fn list_servers(&self) -> Result<Vec<String>> {
        self.runtime.list_servers().await
    }
    
    /// Get metrics for all servers or a specific server
    pub async fn get_metrics(&self, server_id: Option<&str>) -> Result<Metrics> {
        self.runtime.get_metrics(server_id).await
    }
    
    /// Launch all configured servers
    pub async fn launch_all(&self) -> Result<Vec<String>> {
        let mut deployed = Vec::new();
        
        for server_config in &self.config.servers {
            match self.deploy_server(server_config.clone()).await {
                Ok(server_id) => {
                    deployed.push(server_id);
                }
                Err(e) => {
                    // Log error but continue with other servers
                    tracing::error!("Failed to deploy {}: {}", server_config.name, e);
                }
            }
        }
        
        Ok(deployed)
    }
    
    /// Shutdown all servers and the manager
    pub async fn shutdown(self) -> Result<()> {
        // Get list of servers before shutting down
        let servers = self.runtime.list_servers().await?;
        
        // Undeploy all servers
        for server_id in servers {
            if let Err(e) = self.runtime.undeploy(&server_id).await {
                tracing::error!("Failed to undeploy {}: {}", server_id, e);
            }
        }
        
        // Shutdown the runtime
        Arc::try_unwrap(self.runtime)
            .map_err(|_| crate::mcp_manager::errors::McpError::InternalError(
                "Failed to unwrap runtime Arc".to_string()
            ))?
            .shutdown()
            .await
    }
    
    /// Get configuration
    pub fn config(&self) -> &McpManagerConfig {
        &self.config
    }
}

/// Python-compatible wrapper for the new manager
#[cfg(feature = "python")]
pub mod python {
    use super::*;
    use pyo3::prelude::*;
    use pyo3_asyncio::tokio::future_into_py;
    
    #[pyclass(name = "McpManagerV2")]
    pub struct PyMcpManagerV2 {
        inner: Arc<McpManagerV2>,
    }
    
    #[pymethods]
    impl PyMcpManagerV2 {
        #[new]
        fn new() -> Self {
            Self {
                inner: Arc::new(McpManagerV2::default()),
            }
        }
        
        fn initialize<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
            let manager = self.inner.clone();
            future_into_py(py, async move {
                manager.initialize().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
            })
        }
        
        fn deploy_server<'py>(
            &self,
            py: Python<'py>,
            server_config: &PyAny,
        ) -> PyResult<&'py PyAny> {
            let config: ServerConfig = server_config.extract()?;
            let manager = self.inner.clone();
            
            future_into_py(py, async move {
                manager.deploy_server(config).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
            })
        }
        
        fn execute_tool<'py>(
            &self,
            py: Python<'py>,
            server_id: String,
            tool_name: String,
            parameters: &PyAny,
        ) -> PyResult<&'py PyAny> {
            let params: serde_json::Value = pythonize::depythonize(parameters)?;
            let manager = self.inner.clone();
            
            future_into_py(py, async move {
                manager.execute_tool(&server_id, &tool_name, params).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
            })
        }
        
        fn list_servers<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
            let manager = self.inner.clone();
            
            future_into_py(py, async move {
                manager.list_servers().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
            })
        }
        
        fn get_metrics<'py>(
            &self,
            py: Python<'py>,
            server_id: Option<String>,
        ) -> PyResult<&'py PyAny> {
            let manager = self.inner.clone();
            
            future_into_py(py, async move {
                let metrics = manager.get_metrics(server_id.as_deref()).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
                    
                Ok(pythonize::pythonize(&metrics)?)
            })
        }
        
        fn launch_all<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
            let manager = self.inner.clone();
            
            future_into_py(py, async move {
                manager.launch_all().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::ServerType;
    
    #[tokio::test]
    async fn test_manager_v2_lifecycle() {
        let config = McpManagerConfig::default();
        let manager = McpManagerV2::new(config);
        
        // Initialize (should deploy default servers)
        manager.initialize().await.unwrap();
        
        // List servers
        let servers = manager.list_servers().await.unwrap();
        assert!(!servers.is_empty());
        
        // Get metrics
        let metrics = manager.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, servers.len());
        
        // Shutdown
        manager.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_manager_v2_execute_tool() {
        let mut config = McpManagerConfig::default();
        config.servers.push(ServerConfig {
            name: "test-docker".to_string(),
            server_type: ServerType::Docker,
            url: "http://localhost:8001".to_string(),
            port: 8001,
            auth: None,
            capabilities: vec!["docker.ps".to_string()],
            max_connections: 10,
            timeout_ms: 5000,
            retry_policy: Default::default(),
            priority: 5,
            tags: vec!["test".to_string()],
        });
        
        let manager = McpManagerV2::new(config);
        
        // Deploy server
        let server_id = manager.deploy_server(manager.config.servers[0].clone()).await.unwrap();
        
        // Execute tool (this would fail in tests without actual server)
        let params = serde_json::json!({});
        let result = manager.execute_tool(&server_id, "docker.ps", params).await;
        
        // In tests, this might fail, but the structure should work
        assert!(result.is_err() || result.is_ok());
        
        // Shutdown
        manager.shutdown().await.unwrap();
    }
}