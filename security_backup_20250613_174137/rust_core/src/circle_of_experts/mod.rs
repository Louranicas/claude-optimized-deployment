// ============================================================================
// CIRCLE OF EXPERTS - High-Performance Rust Implementation
// ============================================================================
// This module provides Rust-accelerated operations for the Circle of Experts
// AI consultation system, offering significant performance improvements over
// the Python implementation for computationally intensive tasks.
//
// Key features:
// - Parallel consensus computation using Rayon
// - SIMD-accelerated similarity calculations
// - Zero-copy response aggregation
// - Lock-free data structures for concurrent access
// - Optimized pattern analysis algorithms
// ============================================================================

pub mod aggregator;
pub mod analyzer;
pub mod consensus;
pub mod python_bindings;

use crate::CoreError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Expert response structure optimized for Rust processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertResponse {
    pub expert_name: String,
    pub content: String,
    pub confidence: f32,
    pub metadata: HashMap<String, String>,
    pub timestamp: u64,
}

/// Aggregated consensus result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub consensus_text: String,
    pub confidence_score: f32,
    pub agreement_matrix: Vec<Vec<f32>>,
    pub dissenting_opinions: Vec<String>,
    pub key_insights: Vec<String>,
}

/// Configuration for Circle of Experts operations
#[derive(Debug, Clone)]
pub struct CircleConfig {
    pub min_consensus_threshold: f32,
    pub enable_parallel_processing: bool,
    pub max_threads: Option<usize>,
    pub similarity_algorithm: SimilarityAlgorithm,
}

/// Available similarity algorithms
#[derive(Debug, Clone, Copy)]
pub enum SimilarityAlgorithm {
    Cosine,
    Jaccard,
    LevenshteinNormalized,
    SemanticEmbedding,
}

impl Default for CircleConfig {
    fn default() -> Self {
        Self {
            min_consensus_threshold: 0.7,
            enable_parallel_processing: true,
            max_threads: None,
            similarity_algorithm: SimilarityAlgorithm::Cosine,
        }
    }
}

/// Initialize the Circle of Experts Rust module
pub fn init() -> Result<(), CoreError> {
    // Initialize Rayon thread pool if needed
    if let Some(threads) = std::env::var("CIRCLE_OF_EXPERTS_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| CoreError::CircleOfExperts(format!("Failed to initialize thread pool: {}", e)))?;
    }
    
    Ok(())
}

/// Process expert responses and generate consensus
pub fn process_expert_responses(
    responses: Vec<ExpertResponse>,
    config: Arc<CircleConfig>,
) -> Result<ConsensusResult, CoreError> {
    if responses.is_empty() {
        return Err(CoreError::CircleOfExperts("No expert responses provided".to_string()));
    }
    
    // Compute similarity matrix
    let similarity_matrix = consensus::compute_similarity_matrix(&responses, &config)?;
    
    // Find consensus clusters
    let clusters = consensus::find_consensus_clusters(&similarity_matrix, config.min_consensus_threshold)?;
    
    // Aggregate responses
    let aggregated = aggregator::aggregate_responses(&responses, &clusters, &config)?;
    
    // Analyze patterns and extract insights
    let insights = analyzer::extract_key_insights(&responses, &aggregated)?;
    
    Ok(ConsensusResult {
        consensus_text: aggregated.consensus_text,
        confidence_score: aggregated.confidence_score,
        agreement_matrix: similarity_matrix,
        dissenting_opinions: aggregated.dissenting_opinions,
        key_insights: insights,
    })
}

/// Register the Circle of Experts module with Python
pub fn register_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    python_bindings::register_python_bindings(py, parent_module)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_process_expert_responses() {
        let responses = vec![
            ExpertResponse {
                expert_name: "Expert1".to_string(),
                content: "This is a test response".to_string(),
                confidence: 0.9,
                metadata: HashMap::new(),
                timestamp: 1234567890,
            },
            ExpertResponse {
                expert_name: "Expert2".to_string(),
                content: "This is another test response".to_string(),
                confidence: 0.8,
                metadata: HashMap::new(),
                timestamp: 1234567891,
            },
        ];
        
        let config = Arc::new(CircleConfig::default());
        let result = process_expert_responses(responses, config);
        
        assert!(result.is_ok());
    }
}