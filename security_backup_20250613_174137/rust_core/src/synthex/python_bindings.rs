// Python bindings for SYNTHEX engine
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::sync::Arc;
use tokio::runtime::Runtime;
use crate::synthex::{SynthexEngine, SynthexConfig, SearchResult};

/// Python wrapper for SYNTHEX engine
#[pyclass]
pub struct PySynthexEngine {
    engine: Arc<SynthexEngine>,
    runtime: Arc<Runtime>,
}

#[pymethods]
impl PySynthexEngine {
    /// Create new SYNTHEX engine instance
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&PyDict>) -> PyResult<Self> {
        let runtime = Runtime::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to create runtime: {}", e)
            ))?;
        
        let synthex_config = if let Some(cfg) = config {
            parse_config(cfg)?
        } else {
            SynthexConfig::default()
        };
        
        let engine = runtime.block_on(async {
            SynthexEngine::new(synthex_config).await
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to create engine: {}", e)
        ))?;
        
        Ok(Self {
            engine: Arc::new(engine),
            runtime: Arc::new(runtime),
        })
    }
    
    /// Execute a search query
    fn search(&self, py: Python, query: &str) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        let query = query.to_string();
        
        let result = py.allow_threads(|| {
            self.runtime.block_on(async move {
                engine.search(&query).await
            })
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Search failed: {}", e)
        ))?;
        
        // Convert SearchResult to Python dict
        search_result_to_pydict(py, result)
    }
    
    /// Register a custom search agent
    fn register_agent(&self, name: String, agent_type: String) -> PyResult<()> {
        // This would need to be implemented based on how Python agents interact
        Ok(())
    }
    
    /// Get engine metrics
    fn get_metrics(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        // Add metrics here
        Ok(dict.into())
    }
}

/// Parse Python config dict into SynthexConfig
fn parse_config(config: &PyDict) -> PyResult<SynthexConfig> {
    let mut synthex_config = SynthexConfig::default();
    
    if let Some(max_parallel) = config.get_item("max_parallel_searches") {
        synthex_config.max_parallel_searches = max_parallel.extract()?;
    }
    
    if let Some(pool_size) = config.get_item("connection_pool_size") {
        synthex_config.connection_pool_size = pool_size.extract()?;
    }
    
    if let Some(cache_size) = config.get_item("cache_size_mb") {
        synthex_config.cache_size_mb = cache_size.extract()?;
    }
    
    if let Some(timeout) = config.get_item("query_timeout_ms") {
        synthex_config.query_timeout_ms = timeout.extract()?;
    }
    
    if let Some(enable_opt) = config.get_item("enable_query_optimization") {
        synthex_config.enable_query_optimization = enable_opt.extract()?;
    }
    
    // Parse MCP v2 config
    if let Some(mcp_config) = config.get_item("mcp_v2_config") {
        if let Ok(mcp_dict) = mcp_config.downcast::<PyDict>() {
            if let Some(compression) = mcp_dict.get_item("compression") {
                synthex_config.mcp_v2_config.compression = compression.extract()?;
            }
            if let Some(max_msg_size) = mcp_dict.get_item("max_message_size") {
                synthex_config.mcp_v2_config.max_message_size = max_msg_size.extract()?;
            }
            if let Some(conn_timeout) = mcp_dict.get_item("connection_timeout_ms") {
                synthex_config.mcp_v2_config.connection_timeout_ms = conn_timeout.extract()?;
            }
            if let Some(enable_mux) = mcp_dict.get_item("enable_multiplexing") {
                synthex_config.mcp_v2_config.enable_multiplexing = enable_mux.extract()?;
            }
        }
    }
    
    Ok(synthex_config)
}

/// Convert SearchResult to Python dict
fn search_result_to_pydict(py: Python, result: SearchResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("query_id", result.query_id)?;
    dict.set_item("total_results", result.total_results)?;
    dict.set_item("execution_time_ms", result.execution_time_ms)?;
    
    // Convert result groups
    let groups_list = PyList::empty(py);
    for group in result.results {
        let group_dict = PyDict::new(py);
        group_dict.set_item("category", group.category)?;
        group_dict.set_item("relevance", group.relevance)?;
        
        let items_list = PyList::empty(py);
        for item in group.items {
            let item_dict = PyDict::new(py);
            item_dict.set_item("id", item.id)?;
            item_dict.set_item("title", item.title)?;
            item_dict.set_item("snippet", item.snippet)?;
            item_dict.set_item("source", item.source)?;
            item_dict.set_item("score", item.score)?;
            
            // Convert metadata
            let metadata_dict = PyDict::new(py);
            for (key, value) in item.metadata {
                let py_value = serde_json_to_pyobject(py, value)?;
                metadata_dict.set_item(key, py_value)?;
            }
            item_dict.set_item("metadata", metadata_dict)?;
            
            items_list.append(item_dict)?;
        }
        group_dict.set_item("items", items_list)?;
        groups_list.append(group_dict)?;
    }
    dict.set_item("results", groups_list)?;
    
    // Convert metadata
    let metadata_dict = PyDict::new(py);
    metadata_dict.set_item("sources_searched", result.metadata.sources_searched)?;
    metadata_dict.set_item("optimizations_applied", result.metadata.optimizations_applied)?;
    metadata_dict.set_item("cache_hit_rate", result.metadata.cache_hit_rate)?;
    metadata_dict.set_item("parallel_searches", result.metadata.parallel_searches)?;
    dict.set_item("metadata", metadata_dict)?;
    
    Ok(dict.into())
}

/// Convert serde_json::Value to Python object
fn serde_json_to_pyobject(py: Python, value: serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_py(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(n.to_string().into_py(py))
            }
        }
        serde_json::Value::String(s) => Ok(s.into_py(py)),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(serde_json_to_pyobject(py, item)?)?;
            }
            Ok(list.into())
        }
        serde_json::Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (key, value) in obj {
                dict.set_item(key, serde_json_to_pyobject(py, value)?)?;
            }
            Ok(dict.into())
        }
    }
}

/// Register SYNTHEX module with Python
pub fn register_module(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySynthexEngine>()?;
    
    // Add module constants
    m.add("VERSION", "1.0.0")?;
    m.add("MAX_PARALLEL_SEARCHES", 10000)?;
    
    Ok(())
}