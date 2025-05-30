// ============================================================================
// TEST MODULE - Verify Circle of Experts Rust Implementation
// ============================================================================
// A simple test module to verify that our Circle of Experts Rust modules
// compile correctly without external dependencies issues.
// ============================================================================

#[cfg(test)]
mod tests {
    use crate::circle_of_experts::{
        CircleConfig, ExpertResponse, process_expert_responses,
        consensus, aggregator, analyzer,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_basic_consensus() {
        let responses = vec![
            ExpertResponse {
                expert_name: "TestExpert1".to_string(),
                content: "This is a test response about artificial intelligence".to_string(),
                confidence: 0.85,
                metadata: HashMap::new(),
                timestamp: 1234567890,
            },
            ExpertResponse {
                expert_name: "TestExpert2".to_string(),
                content: "This is another test response about artificial intelligence systems".to_string(),
                confidence: 0.90,
                metadata: HashMap::new(),
                timestamp: 1234567891,
            },
            ExpertResponse {
                expert_name: "TestExpert3".to_string(),
                content: "A different perspective on machine learning and AI".to_string(),
                confidence: 0.75,
                metadata: HashMap::new(),
                timestamp: 1234567892,
            },
        ];

        let config = Arc::new(CircleConfig::default());
        let result = process_expert_responses(responses, config);
        
        assert!(result.is_ok());
        let consensus = result.unwrap();
        assert!(!consensus.consensus_text.is_empty());
        assert!(consensus.confidence_score > 0.0 && consensus.confidence_score <= 1.0);
    }

    #[test]
    fn test_similarity_matrix() {
        let responses = vec![
            ExpertResponse {
                expert_name: "Expert1".to_string(),
                content: "Hello world".to_string(),
                confidence: 0.8,
                metadata: HashMap::new(),
                timestamp: 0,
            },
            ExpertResponse {
                expert_name: "Expert2".to_string(),
                content: "Hello universe".to_string(),
                confidence: 0.9,
                metadata: HashMap::new(),
                timestamp: 1,
            },
        ];

        let config = CircleConfig::default();
        let matrix = consensus::compute_similarity_matrix(&responses, &config).unwrap();
        
        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].len(), 2);
        assert_eq!(matrix[0][0], 1.0); // Self-similarity
        assert!(matrix[0][1] > 0.0 && matrix[0][1] < 1.0); // Partial similarity
    }

    #[test]
    fn test_parallel_vs_sequential() {
        let responses: Vec<ExpertResponse> = (0..10)
            .map(|i| ExpertResponse {
                expert_name: format!("Expert{}", i),
                content: format!("Response number {} with some content", i),
                confidence: 0.7 + (i as f32 * 0.02),
                metadata: HashMap::new(),
                timestamp: i as u64,
            })
            .collect();

        // Test parallel processing
        let config_parallel = Arc::new(CircleConfig {
            enable_parallel_processing: true,
            ..Default::default()
        });
        let result_parallel = process_expert_responses(responses.clone(), config_parallel);
        assert!(result_parallel.is_ok());

        // Test sequential processing
        let config_sequential = Arc::new(CircleConfig {
            enable_parallel_processing: false,
            ..Default::default()
        });
        let result_sequential = process_expert_responses(responses, config_sequential);
        assert!(result_sequential.is_ok());
    }
}