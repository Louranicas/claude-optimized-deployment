// ============================================================================
// SYNTHEX BASH GOD - Python Bindings
// ============================================================================
// Comprehensive Python bindings for the SynthexBashGod module using PyO3
// ============================================================================

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use futures::StreamExt;

use super::{SynthexBashGod, SBGConfig, ExecutionResult, PerformanceMetrics, LearningInsights};
use super::command_chain::CommandChain;
use super::streaming_interface::{ExecutionStream, MetricsStream};

/// Python wrapper for SynthexBashGod
#[pyclass(name = "SynthexBashGod")]
pub struct PySynthexBashGod {
    inner: Arc<SynthexBashGod>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PySynthexBashGod {
    /// Create a new SynthexBashGod instance
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&PyDict>) -> PyResult<Self> {
        let config = if let Some(dict) = config {
            py_dict_to_config(dict)?
        } else {
            SBGConfig::default()
        };

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;

        let sbg = runtime.block_on(async {
            SynthexBashGod::new(config)
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to create SynthexBashGod: {}", e)))
        })?;

        Ok(Self {
            inner: Arc::new(sbg),
            runtime: Arc::new(runtime),
        })
    }

    /// Execute a command chain
    fn execute_chain<'py>(&self, py: Python<'py>, chain: PyCommandChain) -> PyResult<&'py PyAny> {
        let sbg = self.inner.clone();
        let chain = chain.inner;

        future_into_py(py, async move {
            let result = sbg.execute_chain(chain).await
                .map_err(|e| PyRuntimeError::new_err(format!("Execution failed: {}", e)))?;
            
            Ok(PyExecutionResult::from(result))
        })
    }

    /// Execute a raw bash command chain string
    fn execute<'py>(&self, py: Python<'py>, command: String) -> PyResult<&'py PyAny> {
        let sbg = self.inner.clone();

        future_into_py(py, async move {
            let chain = CommandChain::from_string(&command)
                .map_err(|e| PyValueError::new_err(format!("Invalid command chain: {}", e)))?;
            
            let result = sbg.execute_chain(chain).await
                .map_err(|e| PyRuntimeError::new_err(format!("Execution failed: {}", e)))?;
            
            Ok(PyExecutionResult::from(result))
        })
    }

    /// Get learning insights
    fn get_insights<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let sbg = self.inner.clone();

        future_into_py(py, async move {
            let insights = sbg.get_insights().await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get insights: {}", e)))?;
            
            Ok(PyLearningInsights::from(insights))
        })
    }

    /// Get performance metrics
    fn get_metrics<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let sbg = self.inner.clone();

        future_into_py(py, async move {
            let metrics = sbg.get_metrics().await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get metrics: {}", e)))?;
            
            Ok(PyPerformanceMetrics::from(metrics))
        })
    }

    /// Create an execution stream for real-time monitoring
    fn create_execution_stream(&self, chain: PyCommandChain) -> PyResult<PyExecutionStream> {
        let stream = self.runtime.block_on(async {
            ExecutionStream::new(self.inner.clone(), chain.inner)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to create stream: {}", e)))
        })?;

        Ok(PyExecutionStream {
            inner: Arc::new(Mutex::new(stream)),
            runtime: self.runtime.clone(),
        })
    }

    /// Create a metrics stream for performance monitoring
    fn create_metrics_stream(&self) -> PyResult<PyMetricsStream> {
        let stream = self.runtime.block_on(async {
            MetricsStream::new(self.inner.clone())
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to create metrics stream: {}", e)))
        })?;

        Ok(PyMetricsStream {
            inner: Arc::new(Mutex::new(stream)),
            runtime: self.runtime.clone(),
        })
    }
}

/// Python wrapper for CommandChain
#[pyclass(name = "CommandChain")]
#[derive(Clone)]
pub struct PyCommandChain {
    inner: CommandChain,
}

#[pymethods]
impl PyCommandChain {
    /// Create a new command chain
    #[new]
    fn new() -> Self {
        Self {
            inner: CommandChain::new(),
        }
    }

    /// Add a command to the chain
    fn add_command(&mut self, command: String) -> PyResult<()> {
        self.inner.add_command(command);
        Ok(())
    }

    /// Add a pipe to connect commands
    fn pipe(&mut self) -> PyResult<()> {
        self.inner.pipe();
        Ok(())
    }

    /// Add an AND operator (&&)
    fn and(&mut self) -> PyResult<()> {
        self.inner.and();
        Ok(())
    }

    /// Add an OR operator (||)
    fn or(&mut self) -> PyResult<()> {
        self.inner.or();
        Ok(())
    }

    /// Set environment variables
    fn set_env(&mut self, key: String, value: String) -> PyResult<()> {
        self.inner.set_env(key, value);
        Ok(())
    }

    /// Set working directory
    fn set_cwd(&mut self, path: String) -> PyResult<()> {
        self.inner.set_cwd(path);
        Ok(())
    }

    /// Build the command chain string
    fn build(&self) -> String {
        self.inner.to_string()
    }

    /// Create from a command string
    #[staticmethod]
    fn from_string(command: String) -> PyResult<Self> {
        let chain = CommandChain::from_string(&command)
            .map_err(|e| PyValueError::new_err(format!("Invalid command chain: {}", e)))?;
        
        Ok(Self { inner: chain })
    }
}

/// Python wrapper for ExecutionResult
#[pyclass(name = "ExecutionResult")]
pub struct PyExecutionResult {
    #[pyo3(get)]
    output: String,
    #[pyo3(get)]
    error: Option<String>,
    #[pyo3(get)]
    exit_code: i32,
    #[pyo3(get)]
    metrics: PyPerformanceMetrics,
    #[pyo3(get)]
    optimizations_applied: Vec<String>,
}

impl From<ExecutionResult> for PyExecutionResult {
    fn from(result: ExecutionResult) -> Self {
        Self {
            output: result.output,
            error: result.error,
            exit_code: result.exit_code,
            metrics: PyPerformanceMetrics::from(result.metrics),
            optimizations_applied: result.optimizations_applied,
        }
    }
}

/// Python wrapper for PerformanceMetrics
#[pyclass(name = "PerformanceMetrics")]
#[derive(Clone)]
pub struct PyPerformanceMetrics {
    #[pyo3(get)]
    total_duration_ms: u64,
    #[pyo3(get)]
    cpu_usage_percent: f64,
    #[pyo3(get)]
    memory_usage_mb: f64,
    #[pyo3(get)]
    io_operations: u64,
    #[pyo3(get)]
    network_bytes: u64,
    command_timings: HashMap<String, u64>,
}

#[pymethods]
impl PyPerformanceMetrics {
    /// Get command timings as a Python dict
    fn get_command_timings(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        for (cmd, timing) in &self.command_timings {
            dict.set_item(cmd, timing)?;
        }
        Ok(dict.into())
    }
}

impl From<PerformanceMetrics> for PyPerformanceMetrics {
    fn from(metrics: PerformanceMetrics) -> Self {
        Self {
            total_duration_ms: metrics.total_duration_ms,
            cpu_usage_percent: metrics.cpu_usage_percent,
            memory_usage_mb: metrics.memory_usage_mb,
            io_operations: metrics.io_operations,
            network_bytes: metrics.network_bytes,
            command_timings: metrics.command_timings,
        }
    }
}

/// Python wrapper for LearningInsights
#[pyclass(name = "LearningInsights")]
pub struct PyLearningInsights {
    inner: LearningInsights,
}

#[pymethods]
impl PyLearningInsights {
    /// Get common patterns
    fn get_common_patterns(&self, py: Python) -> PyResult<PyObject> {
        let list = PyList::empty(py);
        for pattern in &self.inner.common_patterns {
            let dict = PyDict::new(py);
            dict.set_item("pattern", &pattern.pattern)?;
            dict.set_item("frequency", pattern.frequency)?;
            dict.set_item("avg_performance", pattern.avg_performance)?;
            list.append(dict)?;
        }
        Ok(list.into())
    }

    /// Get optimization suggestions
    fn get_optimization_suggestions(&self, py: Python) -> PyResult<PyObject> {
        let list = PyList::empty(py);
        for suggestion in &self.inner.optimization_suggestions {
            let dict = PyDict::new(py);
            dict.set_item("original", &suggestion.original)?;
            dict.set_item("optimized", &suggestion.optimized)?;
            dict.set_item("expected_improvement", suggestion.expected_improvement)?;
            dict.set_item("confidence", suggestion.confidence)?;
            list.append(dict)?;
        }
        Ok(list.into())
    }

    /// Get performance trends
    fn get_performance_trends(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        for (metric, trend) in &self.inner.performance_trends {
            let trend_dict = PyDict::new(py);
            trend_dict.set_item("metric", &trend.metric)?;
            trend_dict.set_item("trend", &trend.trend)?;
            trend_dict.set_item("change_percent", trend.change_percent)?;
            dict.set_item(metric, trend_dict)?;
        }
        Ok(dict.into())
    }

    /// Get failure patterns
    fn get_failure_patterns(&self, py: Python) -> PyResult<PyObject> {
        let list = PyList::empty(py);
        for pattern in &self.inner.failure_patterns {
            let dict = PyDict::new(py);
            dict.set_item("pattern", &pattern.pattern)?;
            dict.set_item("failure_rate", pattern.failure_rate)?;
            let errors_list = PyList::new(py, &pattern.common_errors);
            dict.set_item("common_errors", errors_list)?;
            list.append(dict)?;
        }
        Ok(list.into())
    }
}

impl From<LearningInsights> for PyLearningInsights {
    fn from(insights: LearningInsights) -> Self {
        Self { inner: insights }
    }
}

/// Python wrapper for ExecutionStream
#[pyclass(name = "ExecutionStream")]
pub struct PyExecutionStream {
    inner: Arc<Mutex<ExecutionStream>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyExecutionStream {
    /// Get the next item from the stream
    fn next<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let stream = self.inner.clone();

        future_into_py(py, async move {
            let mut stream_guard = stream.lock().await;
            match stream_guard.next().await {
                Some(Ok(event)) => Ok(Some(event.to_py_dict())),
                Some(Err(e)) => Err(PyRuntimeError::new_err(format!("Stream error: {}", e))),
                None => Ok(None),
            }
        })
    }

    /// Close the stream
    fn close(&self) -> PyResult<()> {
        self.runtime.block_on(async {
            let mut stream = self.inner.lock().await;
            stream.close().await;
        });
        Ok(())
    }
}

/// Python wrapper for MetricsStream
#[pyclass(name = "MetricsStream")]
pub struct PyMetricsStream {
    inner: Arc<Mutex<MetricsStream>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyMetricsStream {
    /// Get the next metrics update
    fn next<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let stream = self.inner.clone();

        future_into_py(py, async move {
            let mut stream_guard = stream.lock().await;
            match stream_guard.next().await {
                Some(Ok(metrics)) => Ok(Some(PyPerformanceMetrics::from(metrics))),
                Some(Err(e)) => Err(PyRuntimeError::new_err(format!("Stream error: {}", e))),
                None => Ok(None),
            }
        })
    }

    /// Close the stream
    fn close(&self) -> PyResult<()> {
        self.runtime.block_on(async {
            let mut stream = self.inner.lock().await;
            stream.close().await;
        });
        Ok(())
    }
}

/// Helper function to convert Python dict to SBGConfig
fn py_dict_to_config(dict: &PyDict) -> PyResult<SBGConfig> {
    let mut config = SBGConfig::default();
    
    // Parse execution config
    if let Ok(Some(exec_dict)) = dict.get_item("execution_config") {
        if let Ok(exec_dict) = exec_dict.downcast::<PyDict>() {
            // Parse execution config fields
            if let Ok(Some(val)) = exec_dict.get_item("max_parallel") {
                if let Ok(val) = val.extract::<usize>() {
                    config.execution_config.max_parallel = val;
                }
            }
        }
    }
    
    // Parse other config sections similarly...
    
    Ok(config)
}

/// Register the Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySynthexBashGod>()?;
    m.add_class::<PyCommandChain>()?;
    m.add_class::<PyExecutionResult>()?;
    m.add_class::<PyPerformanceMetrics>()?;
    m.add_class::<PyLearningInsights>()?;
    m.add_class::<PyExecutionStream>()?;
    m.add_class::<PyMetricsStream>()?;
    
    Ok(())
}