pub mod memory;
pub mod command_engine;
pub mod system_state;
pub mod safety;
pub mod optimization;
pub mod server;

use pyo3::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;

use crate::server::BashGodMCPServer;

#[pyclass]
pub struct PyBashGodServer {
    inner: Arc<BashGodMCPServer>,
    runtime: Arc<Runtime>,
}

#[pymethods]
impl PyBashGodServer {
    #[new]
    fn new() -> PyResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create runtime: {}", e))
        })?;
        
        let server = runtime.block_on(async {
            BashGodMCPServer::new().await
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create server: {}", e))
        })?;
        
        Ok(Self {
            inner: Arc::new(server),
            runtime: Arc::new(runtime),
        })
    }
    
    fn generate_command(&self, request: &str) -> PyResult<String> {
        let server = self.inner.clone();
        self.runtime.block_on(async move {
            server.generate_command_from_json(request).await
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Command generation failed: {}", e))
        })
    }
    
    fn learn_pattern(&self, execution_data: &str) -> PyResult<()> {
        let server = self.inner.clone();
        self.runtime.block_on(async move {
            server.learn_from_execution_json(execution_data).await
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Learning failed: {}", e))
        })?;
        Ok(())
    }
    
    fn get_system_info(&self) -> PyResult<String> {
        let server = self.inner.clone();
        self.runtime.block_on(async move {
            server.get_system_info_json().await
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to get system info: {}", e))
        })
    }
    
    fn validate_command(&self, command: &str) -> PyResult<String> {
        let server = self.inner.clone();
        self.runtime.block_on(async move {
            server.validate_command_json(command).await
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Validation failed: {}", e))
        })
    }
}

#[pymodule]
fn bash_god_mcp(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyBashGodServer>()?;
    Ok(())
}