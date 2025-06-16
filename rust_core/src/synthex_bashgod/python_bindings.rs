//! Python bindings for SYNTHEX-BashGod
//! 
//! Provides PyO3 bindings for Python integration

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::sync::Arc;
use std::path::PathBuf;
use tokio::runtime::Runtime;

use crate::synthex_bashgod::{
    BashGodService, BashGodConfig, CommandChain, ChainResult, BashIntent,
    LearningInsight, InsightType, BashCommand, ExecutionResult,
    ResourceLimits, ExecutionMetrics, ExecutionStatus, ChainMetadata,
    Priority, ResourceEstimate, ExecutionStrategy, SuccessCriteria,
    CommandResult, ResourceUsage, OptimizationSuggestion, PerformanceMetrics,
    ExecutionInsights, OptimizationType, RiskLevel,
};

/// Python wrapper for SYNTHEX-BashGod
#[pyclass]
pub struct PySynthexBashGod {
    /// Rust implementation
    inner: Arc<dyn BashGodService>,
    
    /// Tokio runtime
    runtime: Runtime,
}

#[pymethods]
impl PySynthexBashGod {
    /// Create new instance
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&PyDict>) -> PyResult<Self> {
        let rust_config = if let Some(py_config) = config {
            parse_config(py_config)?
        } else {
            BashGodConfig::default()
        };
        
        // Create runtime
        let runtime = Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
        
        // Create service
        let service = runtime.block_on(async {
            crate::synthex_bashgod::create_bashgod_service(rust_config).await
        }).map_err(|e| PyRuntimeError::new_err(format!("Failed to create service: {}", e)))?;
        
        Ok(Self {
            inner: service,
            runtime,
        })
    }
    
    /// Execute command chain
    fn execute_chain(&self, py: Python, chain: &PyDict) -> PyResult<PyObject> {
        let rust_chain = parse_command_chain(chain)?;
        
        let result = self.runtime.block_on(async {
            self.inner.execute_chain(rust_chain).await
        }).map_err(|e| PyRuntimeError::new_err(format!("Execution failed: {}", e)))?;
        
        chain_result_to_python(py, result)
    }
    
    /// Optimize command chain
    fn optimize_chain(&self, py: Python, chain: &PyDict) -> PyResult<PyObject> {
        let rust_chain = parse_command_chain(chain)?;
        
        let optimized = self.runtime.block_on(async {
            self.inner.optimize_chain(rust_chain).await
        }).map_err(|e| PyRuntimeError::new_err(format!("Optimization failed: {}", e)))?;
        
        command_chain_to_python(py, optimized)
    }
    
    /// Generate chain from intent
    fn generate_chain(&self, py: Python, intent: &PyDict) -> PyResult<PyObject> {
        let rust_intent = parse_bash_intent(intent)?;
        
        let chain = self.runtime.block_on(async {
            self.inner.generate_chain(rust_intent).await
        }).map_err(|e| PyRuntimeError::new_err(format!("Generation failed: {}", e)))?;
        
        command_chain_to_python(py, chain)
    }
    
    /// Get learning insights
    fn get_insights(&self, py: Python) -> PyResult<PyObject> {
        let insights = self.runtime.block_on(async {
            self.inner.get_insights(None).await
        }).map_err(|e| PyRuntimeError::new_err(format!("Failed to get insights: {}", e)))?;
        
        insights_to_python(py, insights)
    }
    
    /// Get performance statistics
    fn get_stats(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        
        // Get metrics from the service
        let stats = self.runtime.block_on(async {
            self.inner.get_metrics().await
        });
        
        match stats {
            Ok(metrics) => {
                dict.set_item("total_commands", metrics.total_commands)?;
                dict.set_item("successful_commands", metrics.successful_commands)?;
                dict.set_item("failed_commands", metrics.failed_commands)?;
                dict.set_item("avg_execution_time_ms", metrics.avg_execution_time_ms)?;
            }
            Err(_) => {
                dict.set_item("error", "Failed to get metrics")?;
            }
        }
        
        Ok(dict.into())
    }
}

/// Parse configuration from Python dict
fn parse_config(py_config: &PyDict) -> PyResult<BashGodConfig> {
    let mut config = BashGodConfig::default();
    
    if let Ok(Some(cores)) = py_config.get_item("executor_pool_size") {
        config.executor_pool_size = cores.extract()?;
    }
    
    // MCP config
    if let Ok(Some(mcp_timeout)) = py_config.get_item("mcp_server_timeout_ms") {
        config.mcp_config.server_timeout_ms = mcp_timeout.extract()?;
    }
    
    if let Ok(Some(mcp_retries)) = py_config.get_item("mcp_max_retries") {
        config.mcp_config.max_retries = mcp_retries.extract()?;
    }
    
    if let Ok(Some(mcp_cache)) = py_config.get_item("mcp_enable_caching") {
        config.mcp_config.enable_caching = mcp_cache.extract()?;
    }
    
    
    Ok(config)
}

/// Parse command chain from Python dict
fn parse_command_chain(py_chain: &PyDict) -> PyResult<CommandChain> {
    let id = py_chain.get_item("id")
        .ok()
        .flatten()
        .and_then(|i| i.extract().ok())
        .unwrap_or_else(|| "chain-".to_string() + &uuid::Uuid::new_v4().to_string());
    
    let description = py_chain.get_item("description")
        .ok()
        .flatten()
        .and_then(|d| d.extract().ok())
        .unwrap_or_else(|| String::new());
    
    // Parse commands
    let commands = if let Ok(Some(py_commands)) = py_chain.get_item("commands") {
        let py_list: &PyList = py_commands.downcast()?;
        let mut rust_commands = Vec::new();
        
        for py_cmd in py_list {
            let cmd_dict: &PyDict = py_cmd.downcast()?;
            rust_commands.push(parse_bash_command(cmd_dict)?);
        }
        
        rust_commands
    } else {
        Vec::new()
    };
    
    // Parse dependencies
    let dependencies = if let Ok(Some(py_deps)) = py_chain.get_item("dependencies") {
        py_deps.extract()?  
    } else {
        HashMap::new()
    };
    
    // Parse strategy
    let strategy = if let Ok(Some(py_strategy)) = py_chain.get_item("strategy") {
        let strategy_str: String = py_strategy.extract()?;
        match strategy_str.as_str() {
            "parallel" => ExecutionStrategy::Parallel { max_concurrent: 10 },
            _ => ExecutionStrategy::Sequential,
        }
    } else {
        ExecutionStrategy::Sequential
    };
    
    Ok(CommandChain {
        id,
        commands,
        dependencies,
        strategy,
        metadata: ChainMetadata {
            intent: description.clone(),
            tags: Vec::new(),
            expected_resources: ResourceEstimate::default(),
            priority: Priority::Normal,
        },
    })
}

/// Parse bash command from Python dict
fn parse_bash_command(py_cmd: &PyDict) -> PyResult<BashCommand> {
    let id = py_cmd.get_item("id")
        .ok()
        .flatten()
        .and_then(|i| i.extract().ok())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    let command = py_cmd.get_item("command")
        .ok()
        .flatten()
        .ok_or_else(|| PyRuntimeError::new_err("Missing 'command' field"))?
        .extract()?;
    
    let args = if let Ok(Some(py_args)) = py_cmd.get_item("args") {
        py_args.extract()?
    } else {
        Vec::new()
    };
    
    let env = if let Ok(Some(py_env)) = py_cmd.get_item("env") {
        py_env.extract()?
    } else {
        HashMap::new()
    };
    
    let working_dir = py_cmd.get_item("working_dir")
        .ok()
        .flatten()
        .and_then(|d| d.extract::<String>().ok());
    
    let resources = if let Ok(Some(py_resources)) = py_cmd.get_item("resources") {
        parse_resource_estimate(py_resources.downcast()?)?
    } else {
        ResourceEstimate::default()
    };
    
    let timeout = py_cmd.get_item("timeout")
        .ok()
        .flatten()
        .and_then(|t| t.extract::<u64>().ok());
    
    Ok(BashCommand {
        id,
        command,
        args,
        env,
        working_dir,
        resources,
        timeout,
        success_criteria: SuccessCriteria::default(),
    })
}

/// Parse resource limits from Python dict
fn parse_resource_limits(py_resources: &PyDict) -> PyResult<ResourceLimits> {
    let mut limits = ResourceLimits::default();
    
    if let Ok(Some(cpu)) = py_resources.get_item("max_cpu_cores") {
        limits.max_cpu_cores = cpu.extract()?;
    }
    
    if let Ok(Some(memory)) = py_resources.get_item("max_memory_mb") {
        let memory_mb: u64 = memory.extract()?;
        limits.max_memory = (memory_mb * 1024 * 1024) as usize;
    }
    
    if let Ok(Some(time)) = py_resources.get_item("max_time_seconds") {
        limits.max_time_seconds = time.extract()?;
    }
    
    if let Ok(Some(io)) = py_resources.get_item("max_disk_io_mbps") {
        limits.max_disk_io_mbps = io.extract()?;
    }
    
    if let Ok(Some(disk)) = py_resources.get_item("max_disk_space_mb") {
        let disk_mb: u64 = disk.extract()?;
        limits.max_disk_space = Some((disk_mb * 1024 * 1024) as usize);
    }
    
    if let Ok(Some(network)) = py_resources.get_item("network_rate_limit_mbps") {
        let network_mbps: f64 = network.extract()?;
        limits.network_rate_limit = Some((network_mbps * 1024.0 * 1024.0 / 8.0) as usize);
    }
    
    Ok(limits)
}

/// Parse resource estimate from Python dict
fn parse_resource_estimate(py_resources: &PyDict) -> PyResult<ResourceEstimate> {
    let mut estimate = ResourceEstimate::default();
    
    if let Ok(Some(cpu)) = py_resources.get_item("cpu_cores") {
        estimate.cpu_cores = Some(cpu.extract()?);
    }
    
    if let Ok(Some(memory)) = py_resources.get_item("memory_mb") {
        estimate.memory_mb = Some(memory.extract()?);
    }
    
    if let Ok(Some(disk)) = py_resources.get_item("disk_mb") {
        estimate.disk_mb = Some(disk.extract()?);
    }
    
    if let Ok(Some(io)) = py_resources.get_item("disk_io_mbps") {
        estimate.disk_io_mbps = Some(io.extract()?);
    }
    
    if let Ok(Some(network)) = py_resources.get_item("network_mbps") {
        estimate.network_mbps = Some(network.extract()?);
    }
    
    if let Ok(Some(gpu)) = py_resources.get_item("gpu") {
        estimate.gpu = gpu.extract()?;
    }
    
    Ok(estimate)
}

/// Parse bash intent from Python dict
fn parse_bash_intent(py_intent: &PyDict) -> PyResult<BashIntent> {
    let description: String = py_intent.get_item("description")
        .ok()
        .flatten()
        .ok_or_else(|| PyRuntimeError::new_err("Missing 'description' field"))?
        .extract()?;
    
    let category = py_intent.get_item("category")
        .ok()
        .flatten()
        .and_then(|c| c.extract().ok())
        .unwrap_or_else(|| "general".to_string());
    
    let goals = if let Ok(Some(py_goals)) = py_intent.get_item("goals") {
        py_goals.extract()?
    } else {
        vec![description.clone()]
    };
    
    let constraints: Vec<String> = if let Ok(Some(py_constraints)) = py_intent.get_item("constraints") {
        py_constraints.extract()?
    } else {
        vec![]
    };
    
    Ok(BashIntent {
        description,
        category,
        goals,
        constraints: vec![],
    })
}

/// Convert chain result to Python object
fn chain_result_to_python(py: Python, result: ChainResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("chain_id", result.chain_id)?;
    dict.set_item("success", result.success)?;
    
    // Convert command results
    let py_results = PyList::new(py, Vec::<PyObject>::new());
    for cmd_result in result.command_results {
        py_results.append(command_result_to_python(py, cmd_result)?)?;
    }
    dict.set_item("command_results", py_results)?;
    
    dict.set_item("total_duration_ms", result.total_duration_ms)?;
    
    // Convert resource usage
    let resource_dict = PyDict::new(py);
    resource_dict.set_item("cpu_percent", result.resource_usage.cpu_percent)?;
    resource_dict.set_item("memory_mb", result.resource_usage.memory_mb)?;
    resource_dict.set_item("disk_read_mb", result.resource_usage.disk_read_mb)?;
    resource_dict.set_item("disk_write_mb", result.resource_usage.disk_write_mb)?;
    dict.set_item("resource_usage", resource_dict)?;
    
    // Convert insights
    let py_insights = PyList::new(py, Vec::<PyObject>::new());
    for insight in result.insights {
        py_insights.append(learning_insight_to_python(py, insight)?)?;
    }
    dict.set_item("insights", py_insights)?;
    
    Ok(dict.into())
}

/// Convert command result to Python object
fn command_result_to_python(py: Python, result: CommandResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("command_id", result.command_id)?;
    dict.set_item("exit_code", result.exit_code)?;
    dict.set_item("stdout", result.stdout)?;
    dict.set_item("stderr", result.stderr)?;
    dict.set_item("duration_ms", result.duration_ms)?;
    
    // Convert resource usage
    let resource_dict = PyDict::new(py);
    resource_dict.set_item("cpu_percent", result.resource_usage.cpu_percent)?;
    resource_dict.set_item("memory_mb", result.resource_usage.memory_mb)?;
    dict.set_item("resource_usage", resource_dict)?;
    
    Ok(dict.into())
}

/// Convert execution result to Python object
fn execution_result_to_python(py: Python, result: ExecutionResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("success", result.success)?;
    dict.set_item("exit_code", result.exit_code)?;
    dict.set_item("output", result.output)?;
    dict.set_item("error", result.error)?;
    
    // Convert metrics
    dict.set_item("metrics", execution_metrics_to_python(py, result.metrics)?)?;
    
    Ok(dict.into())
}

/// Convert learning insight to Python object
fn learning_insight_to_python(py: Python, insight: LearningInsight) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("insight_type", format!("{:?}", insight.insight_type))?;
    dict.set_item("confidence", insight.confidence)?;
    dict.set_item("description", insight.description)?;
    dict.set_item("recommendation", insight.recommendation)?;
    
    // Convert related patterns
    let py_patterns = PyList::new(py, Vec::<PyObject>::new());
    for pattern in insight.related_patterns {
        py_patterns.append(pattern)?;
    }
    dict.set_item("related_patterns", py_patterns)?;
    
    Ok(dict.into())
}

/// Convert execution metrics to Python object
fn execution_metrics_to_python(py: Python, metrics: ExecutionMetrics) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("total_commands", metrics.total_commands)?;
    dict.set_item("successful_commands", metrics.successful_commands)?;
    dict.set_item("failed_commands", metrics.failed_commands)?;
    dict.set_item("avg_execution_time_ms", metrics.avg_execution_time_ms)?;
    
    // Convert resource usage
    let resource_dict = PyDict::new(py);
    resource_dict.set_item("cpu_percent", metrics.peak_resource_usage.cpu_percent)?;
    resource_dict.set_item("memory_mb", metrics.peak_resource_usage.memory_mb)?;
    resource_dict.set_item("disk_read_mb", metrics.peak_resource_usage.disk_read_mb)?;
    resource_dict.set_item("disk_write_mb", metrics.peak_resource_usage.disk_write_mb)?;
    resource_dict.set_item("network_sent_mb", metrics.peak_resource_usage.network_sent_mb)?;
    resource_dict.set_item("network_recv_mb", metrics.peak_resource_usage.network_recv_mb)?;
    dict.set_item("peak_resource_usage", resource_dict)?;
    
    Ok(dict.into())
}

/// Convert command chain to Python object
fn command_chain_to_python(py: Python, chain: CommandChain) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("id", chain.id)?;
    
    // Convert commands
    let py_commands = PyList::new(py, Vec::<PyObject>::new());
    for cmd in chain.commands {
        py_commands.append(bash_command_to_python(py, cmd)?)?;
    }
    dict.set_item("commands", py_commands)?;
    
    // Convert strategy
    dict.set_item("strategy", format!("{:?}", chain.strategy))?;
    
    Ok(dict.into())
}

/// Convert bash command to Python object
fn bash_command_to_python(py: Python, cmd: BashCommand) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("id", cmd.id)?;
    dict.set_item("command", cmd.command)?;
    dict.set_item("args", cmd.args)?;
    dict.set_item("env", cmd.env)?;
    dict.set_item("working_dir", cmd.working_dir)?;
    dict.set_item("resources", resource_estimate_to_python(py, cmd.resources)?)?;
    dict.set_item("timeout", cmd.timeout)?;
    
    Ok(dict.into())
}

/// Convert resource estimate to Python object
fn resource_estimate_to_python(py: Python, estimate: ResourceEstimate) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("cpu_cores", estimate.cpu_cores)?;
    dict.set_item("memory_mb", estimate.memory_mb)?;
    dict.set_item("disk_mb", estimate.disk_mb)?;
    dict.set_item("disk_io_mbps", estimate.disk_io_mbps)?;
    dict.set_item("network_mbps", estimate.network_mbps)?;
    dict.set_item("gpu", estimate.gpu)?;
    
    Ok(dict.into())
}

/// Convert resource limits to Python object
fn resource_limits_to_python(py: Python, limits: ResourceLimits) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("max_cpu_cores", limits.max_cpu_cores)?;
    dict.set_item("max_memory_mb", (limits.max_memory / 1024 / 1024) as u64)?;
    dict.set_item("max_time_seconds", limits.max_time_seconds)?;
    dict.set_item("max_disk_io_mbps", limits.max_disk_io_mbps)?;
    dict.set_item("max_disk_space_mb", limits.max_disk_space.map(|d| (d / 1024 / 1024) as u64))?;
    dict.set_item("network_rate_limit_mbps", limits.network_rate_limit.map(|r| (r as f64 * 8.0 / 1024.0 / 1024.0)))?;
    
    Ok(dict.into())
}

/// Convert insights to Python object
fn insights_to_python(py: Python, insights: Vec<LearningInsight>) -> PyResult<PyObject> {
    let py_list = PyList::new(py, Vec::<PyObject>::new());
    
    for insight in insights {
        py_list.append(learning_insight_to_python(py, insight)?)?;
    }
    
    Ok(py_list.into())
}

/// Python module initialization
#[pymodule]
fn synthex_bashgod(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySynthexBashGod>()?;
    
    // Add version info
    m.add("__version__", "0.1.0")?;
    
    // Add constants
    m.add("DEFAULT_TIMEOUT_MS", 30000)?;
    m.add("DEFAULT_POOL_SIZE", 4)?;
    m.add("MAX_CHAIN_LENGTH", 100)?;
    
    Ok(())
}

/// Register module function for main lib.rs
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySynthexBashGod>()?;
    
    // Add version info
    m.add("__version__", "0.1.0")?;
    
    // Add constants
    m.add("DEFAULT_TIMEOUT_MS", 30000)?;
    m.add("DEFAULT_POOL_SIZE", 4)?;
    m.add("MAX_CHAIN_LENGTH", 100)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_python_module() {
        pyo3::prepare_freethreaded_python();
        
        Python::with_gil(|py| {
            let module = PyModule::new(py, "test_synthex_bashgod").unwrap();
            synthex_bashgod(py, module).unwrap();
            
            assert!(module.hasattr("PySynthexBashGod").unwrap());
            assert!(module.hasattr("__version__").unwrap());
        });
    }
}