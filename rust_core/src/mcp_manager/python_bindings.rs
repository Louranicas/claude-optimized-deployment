//! Python FFI bindings for MCP Manager

use crate::mcp_manager::{
    McpManager,
    config::{McpConfig, ServerConfig}, 
};
use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Python wrapper for MCP Manager
#[pyclass]
pub struct PyMcpManager {
    inner: Arc<McpManager>,
    runtime: Arc<Runtime>,
}

#[pymethods]
impl PyMcpManager {
    /// Create a new MCP Manager
    #[new]
    pub fn new(config_path: Option<String>) -> PyResult<Self> {
        let runtime = Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
        
        let config = if let Some(path) = config_path {
            // For now, create a default config - in production, would load from file
            McpConfig::default()
        } else {
            McpConfig::default()
        };
        
        let manager = McpManager::new(config);
        
        Ok(Self {
            inner: Arc::new(manager),
            runtime: Arc::new(runtime),
        })
    }

    /// Start the MCP Manager
    pub fn start(&self) -> PyResult<()> {
        self.runtime.block_on(async {
            self.inner.start().await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to start manager: {}", e)))
        })
    }

    /// Stop the MCP Manager
    pub fn stop(&self) -> PyResult<()> {
        self.runtime.block_on(async {
            self.inner.stop().await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to stop manager: {}", e)))
        })
    }

    /// Deploy a server
    pub fn deploy_server(&self, server_id: String, config_json: String) -> PyResult<()> {
        let config: ServerConfig = serde_json::from_str(&config_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid server config: {}", e)))?;
        
        self.runtime.block_on(async {
            self.inner.deployment_manager()
                .deploy_server(server_id, config)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to deploy server: {}", e)))?;
            Ok(())
        })
    }

    /// Undeploy a server
    pub fn undeploy_server(&self, server_id: String) -> PyResult<()> {
        self.runtime.block_on(async {
            self.inner.deployment_manager()
                .undeploy_server(&server_id)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to undeploy server: {}", e)))
        })
    }

    /// Get server state
    pub fn get_server_state(&self, server_id: String) -> PyResult<String> {
        self.runtime.block_on(async {
            let registry = self.inner.registry().read().await;
            if let Some(server) = registry.get(&server_id) {
                let state = server.state().await;
                Ok(format!("{:?}", state))
            } else {
                Err(PyValueError::new_err(format!("Server {} not found", server_id)))
            }
        })
    }

    /// Get health status
    pub fn get_health_status(&self) -> PyResult<PyHealthStatus> {
        self.runtime.block_on(async {
            let status = self.inner.health_monitor().status().await;
            Ok(PyHealthStatus {
                total_servers: status.total_servers,
                healthy_servers: status.healthy_servers,
                degraded_servers: status.degraded_servers,
                unhealthy_servers: status.unhealthy_servers,
                avg_response_time_ms: status.avg_response_time.as_millis() as u64,
            })
        })
    }

    /// Get metrics
    pub fn get_metrics(&self) -> PyResult<String> {
        self.runtime.block_on(async {
            Ok(self.inner.metrics_collector().export_prometheus())
        })
    }

    /// Execute request on server
    pub fn execute(&self, server_id: String, request_json: String) -> PyResult<String> {
        self.runtime.block_on(async {
            let registry = self.inner.registry().read().await;
            if let Some(server) = registry.get(&server_id) {
                let request: serde_json::Value = serde_json::from_str(&request_json)
                    .map_err(|e| PyValueError::new_err(format!("Invalid request: {}", e)))?;
                
                let response: serde_json::Value = server.execute(request).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Execution failed: {}", e)))?;
                
                Ok(serde_json::to_string(&response)?)
            } else {
                Err(PyValueError::new_err(format!("Server {} not found", server_id)))
            }
        })
    }

    /// List all servers
    pub fn list_servers(&self) -> PyResult<Vec<PyServerInfo>> {
        self.runtime.block_on(async {
            let registry = self.inner.registry().read().await;
            let mut servers = Vec::new();
            
            for server in registry.all() {
                servers.push(PyServerInfo {
                    id: server.id().to_string(),
                    name: server.name().to_string(),
                    server_type: format!("{:?}", server.server_type()),
                    state: format!("{:?}", server.state().await),
                    priority: server.priority(),
                });
            }
            
            Ok(servers)
        })
    }

    /// Scale server
    pub fn scale_server(&self, server_id: String, instances: usize) -> PyResult<()> {
        self.runtime.block_on(async {
            self.inner.deployment_manager()
                .scale_server(&server_id, instances)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to scale server: {}", e)))
        })
    }


    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(&self) -> PyResult<String> {
        Ok(self.inner.metrics_collector().export_prometheus())
    }

    // Async versions for Python asyncio support
    
    /// Async version of start
    pub fn start_async<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let inner = self.inner.clone();
        
        future_into_py(py, async move {
            inner.start().await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to start manager: {}", e)))
        })
    }

    /// Async version of execute
    pub fn execute_async<'p>(&self, py: Python<'p>, server_id: String, request_json: String) -> PyResult<&'p PyAny> {
        let inner = self.inner.clone();
        
        future_into_py(py, async move {
            let registry = inner.registry().read().await;
            if let Some(server) = registry.get(&server_id) {
                let request: serde_json::Value = serde_json::from_str(&request_json)
                    .map_err(|e| PyValueError::new_err(format!("Invalid request: {}", e)))?;
                
                let response: serde_json::Value = server.execute(request).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Execution failed: {}", e)))?;
                
                Ok(serde_json::to_string(&response)?)
            } else {
                Err(PyValueError::new_err(format!("Server {} not found", server_id)))
            }
        })
    }

    /// Async version of deploy_server
    pub fn deploy_server_async<'p>(&self, py: Python<'p>, server_id: String, config_json: String) -> PyResult<&'p PyAny> {
        let config: ServerConfig = serde_json::from_str(&config_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid server config: {}", e)))?;
        
        let inner = self.inner.clone();
        
        future_into_py(py, async move {
            inner.deployment_manager()
                .deploy_server(server_id, config)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to deploy server: {}", e)))?;
            Ok(())
        })
    }
}

/// Python-friendly health status
#[pyclass]
#[derive(Clone)]
pub struct PyHealthStatus {
    #[pyo3(get)]
    pub total_servers: usize,
    #[pyo3(get)]
    pub healthy_servers: usize,
    #[pyo3(get)]
    pub degraded_servers: usize,
    #[pyo3(get)]
    pub unhealthy_servers: usize,
    #[pyo3(get)]
    pub avg_response_time_ms: u64,
}

/// Python-friendly server info
#[pyclass]
#[derive(Clone)]
pub struct PyServerInfo {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub server_type: String,
    #[pyo3(get)]
    pub state: String,
    #[pyo3(get)]
    pub priority: u8,
}


/// Register the MCP Manager module with Python
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMcpManager>()?;
    m.add_class::<PyHealthStatus>()?;
    m.add_class::<PyServerInfo>()?;
    
    // Add constants
    m.add("SERVER_STATE_HEALTHY", "Healthy")?;
    m.add("SERVER_STATE_DEGRADED", "Degraded")?;
    m.add("SERVER_STATE_UNHEALTHY", "Unhealthy")?;
    m.add("CIRCUIT_STATE_CLOSED", "Closed")?;
    m.add("CIRCUIT_STATE_OPEN", "Open")?;
    m.add("CIRCUIT_STATE_HALF_OPEN", "HalfOpen")?;
    
    // Add version info
    m.add("__version__", "0.1.0")?;
    
    Ok(())
}

// Example Python usage:
// 
// ```python
// import json
// import asyncio
// from claude_optimized_deployment_rust import mcp_manager
// 
// # Synchronous usage
// def sync_example():
//     # Create manager with optional config file
//     manager = mcp_manager.PyMcpManager()
//     
//     # Start the manager
//     manager.start()
//     
//     # Deploy a server
//     server_config = {
//         "name": "my-server",
//         "server_type": "infrastructure",
//         "url": "http://localhost:8080",
//         "auth": {"type": "api_key", "key": "secret"},
//         "priority": 10,
//         "tags": ["production"]
//     }
//     manager.deploy_server("server-1", json.dumps(server_config))
//     
//     # Get server state
//     state = manager.get_server_state("server-1")
//     print(f"Server state: {state}")
//     
//     # Get health status
//     health = manager.get_health_status()
//     print(f"Healthy servers: {health.healthy_servers}/{health.total_servers}")
//     
//     # Execute request
//     request = {"method": "ping"}
//     response = manager.execute("server-1", json.dumps(request))
//     print(f"Response: {response}")
//     
//     # List all servers
//     servers = manager.list_servers()
//     for server in servers:
//         print(f"{server.id}: {server.name} ({server.state})")
//     
//     # Export Prometheus metrics
//     metrics = manager.export_prometheus_metrics()
//     print(f"Metrics:\n{metrics}")
//     
//     # Scale server
//     manager.scale_server("server-1", 3)
//     
//     # Stop the manager
//     manager.stop()
// 
// # Asynchronous usage
// async def async_example():
//     manager = mcp_manager.PyMcpManager()
//     
//     # Use async methods
//     await manager.start_async()
//     
//     server_config = {
//         "name": "async-server",
//         "server_type": "infrastructure",
//         "url": "http://localhost:8081",
//         "auth": {"type": "bearer", "token": "secret-token"},
//         "priority": 5,
//         "tags": ["async", "test"]
//     }
//     
//     await manager.deploy_server_async("async-1", json.dumps(server_config))
//     
//     # Execute async request
//     request = {"method": "health_check"}
//     response = await manager.execute_async("async-1", json.dumps(request))
//     print(f"Async response: {response}")
//     
//     await manager.stop()
// 
// # Run examples
// if __name__ == "__main__":
//     # Run sync example
//     sync_example()
//     
//     # Run async example
//     asyncio.run(async_example())
// ```