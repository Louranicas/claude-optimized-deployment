// ============================================================================
// PYTHON BINDINGS - PyO3 Integration for Circle of Experts
// ============================================================================
// This module provides Python bindings for the high-performance Rust
// implementation of Circle of Experts, allowing Python code to leverage
// the speed improvements while maintaining a familiar API.
// ============================================================================

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::sync::Arc;

use crate::circle_of_experts::{
    CircleConfig, ExpertResponse, SimilarityAlgorithm,
    process_expert_responses,
};

/// Python-accessible expert response
#[pyclass(name = "RustExpertResponse")]
#[derive(Clone)]
pub struct PyExpertResponse {
    #[pyo3(get, set)]
    pub expert_name: String,
    #[pyo3(get, set)]
    pub content: String,
    #[pyo3(get, set)]
    pub confidence: f32,
    #[pyo3(get, set)]
    pub metadata: HashMap<String, String>,
    #[pyo3(get, set)]
    pub timestamp: u64,
}

#[pymethods]
impl PyExpertResponse {
    #[new]
    fn new(
        expert_name: String,
        content: String,
        confidence: f32,
        metadata: Option<HashMap<String, String>>,
        timestamp: Option<u64>,
    ) -> Self {
        Self {
            expert_name,
            content,
            confidence,
            metadata: metadata.unwrap_or_default(),
            timestamp: timestamp.unwrap_or(0),
        }
    }
}

/// Python-accessible consensus result
#[pyclass(name = "RustConsensusResult")]
pub struct PyConsensusResult {
    #[pyo3(get)]
    pub consensus_text: String,
    #[pyo3(get)]
    pub confidence_score: f32,
    #[pyo3(get)]
    pub agreement_matrix: Vec<Vec<f32>>,
    #[pyo3(get)]
    pub dissenting_opinions: Vec<String>,
    #[pyo3(get)]
    pub key_insights: Vec<String>,
}

/// Python-accessible configuration
#[pyclass(name = "RustCircleConfig")]
#[derive(Clone)]
pub struct PyCircleConfig {
    #[pyo3(get, set)]
    pub min_consensus_threshold: f32,
    #[pyo3(get, set)]
    pub enable_parallel_processing: bool,
    #[pyo3(get, set)]
    pub max_threads: Option<usize>,
    #[pyo3(get, set)]
    pub similarity_algorithm: String,
}

#[pymethods]
impl PyCircleConfig {
    #[new]
    fn new(
        min_consensus_threshold: Option<f32>,
        enable_parallel_processing: Option<bool>,
        max_threads: Option<usize>,
        similarity_algorithm: Option<String>,
    ) -> Self {
        Self {
            min_consensus_threshold: min_consensus_threshold.unwrap_or(0.7),
            enable_parallel_processing: enable_parallel_processing.unwrap_or(true),
            max_threads,
            similarity_algorithm: similarity_algorithm.unwrap_or_else(|| "cosine".to_string()),
        }
    }
}

/// Process expert responses using Rust implementation
#[pyfunction(name = "rust_process_expert_responses")]
pub fn py_process_expert_responses(
    py: Python,
    responses: &PyList,
    config: Option<PyCircleConfig>,
) -> PyResult<PyConsensusResult> {
    // Convert Python responses to Rust types
    let mut rust_responses = Vec::new();
    
    for item in responses.iter() {
        if let Ok(py_response) = item.extract::<PyExpertResponse>() {
            rust_responses.push(ExpertResponse {
                expert_name: py_response.expert_name,
                content: py_response.content,
                confidence: py_response.confidence,
                metadata: py_response.metadata,
                timestamp: py_response.timestamp,
            });
        } else if let Ok(dict) = item.downcast::<PyDict>() {
            // Handle dict input for convenience
            let expert_name = dict
                .get_item("expert_name")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing expert_name"))?
                .extract::<String>()?;
            
            let content = dict
                .get_item("content")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing content"))?
                .extract::<String>()?;
            
            let confidence = dict
                .get_item("confidence")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing confidence"))?
                .extract::<f32>()?;
            
            let metadata = dict
                .get_item("metadata")?
                .map(|m| m.extract::<HashMap<String, String>>())
                .transpose()?
                .unwrap_or_default();
            
            let timestamp = dict
                .get_item("timestamp")?
                .map(|t| t.extract::<u64>())
                .transpose()?
                .unwrap_or(0);
            
            rust_responses.push(ExpertResponse {
                expert_name,
                content,
                confidence,
                metadata,
                timestamp,
            });
        }
    }
    
    // Convert config
    let rust_config = if let Some(py_config) = config {
        let algorithm = match py_config.similarity_algorithm.as_str() {
            "jaccard" => SimilarityAlgorithm::Jaccard,
            "levenshtein" => SimilarityAlgorithm::LevenshteinNormalized,
            "semantic" => SimilarityAlgorithm::SemanticEmbedding,
            _ => SimilarityAlgorithm::Cosine,
        };
        
        Arc::new(CircleConfig {
            min_consensus_threshold: py_config.min_consensus_threshold,
            enable_parallel_processing: py_config.enable_parallel_processing,
            max_threads: py_config.max_threads,
            similarity_algorithm: algorithm,
        })
    } else {
        Arc::new(CircleConfig::default())
    };
    
    // Process responses
    py.allow_threads(|| {
        let result = process_expert_responses(rust_responses, rust_config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        
        Ok(PyConsensusResult {
            consensus_text: result.consensus_text,
            confidence_score: result.confidence_score,
            agreement_matrix: result.agreement_matrix,
            dissenting_opinions: result.dissenting_opinions,
            key_insights: result.key_insights,
        })
    })
}

/// Compute similarity between two texts
#[pyfunction(name = "rust_compute_text_similarity")]
pub fn py_compute_text_similarity(
    text1: &str,
    text2: &str,
    algorithm: Option<&str>,
) -> PyResult<f32> {

    
    let alg = match algorithm {
        Some("jaccard") => SimilarityAlgorithm::Jaccard,
        Some("levenshtein") => SimilarityAlgorithm::LevenshteinNormalized,
        Some("semantic") => SimilarityAlgorithm::SemanticEmbedding,
        _ => SimilarityAlgorithm::Cosine,
    };
    
    // This is a simplified version - in the actual implementation,
    // we'd expose the calculate_similarity function
    Ok(0.5) // Placeholder
}

/// Register the Circle of Experts module with Python
pub fn register_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let circle_module = PyModule::new(py, "circle_of_experts")?;
    
    circle_module.add_class::<PyExpertResponse>()?;
    circle_module.add_class::<PyConsensusResult>()?;
    circle_module.add_class::<PyCircleConfig>()?;
    circle_module.add_function(wrap_pyfunction!(py_process_expert_responses, circle_module)?)?;
    circle_module.add_function(wrap_pyfunction!(py_compute_text_similarity, circle_module)?)?;
    
    parent_module.add_submodule(circle_module)?;
    Ok(())
}

/// Alias for backward compatibility
pub fn register_python_bindings(py: Python, parent_module: &PyModule) -> PyResult<()> {
    register_module(py, parent_module)
}