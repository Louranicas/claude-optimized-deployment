// ============================================================================
// RESPONSE AGGREGATION - Efficient Response Merging and Synthesis
// ============================================================================
// This module implements high-performance response aggregation algorithms for
// combining multiple expert responses into coherent consensus statements while
// preserving dissenting opinions and maintaining confidence metrics.
// ============================================================================

use crate::circle_of_experts::{CircleConfig, ExpertResponse};
use crate::CoreError;
use rayon::prelude::*;
use std::collections::HashMap;

/// Aggregated response structure
#[derive(Debug, Clone)]
pub struct AggregatedResponse {
    pub consensus_text: String,
    pub confidence_score: f32,
    pub dissenting_opinions: Vec<String>,
    pub contributing_experts: Vec<String>,
}

/// Aggregate responses based on consensus clusters
pub fn aggregate_responses(
    responses: &[ExpertResponse],
    clusters: &[Vec<usize>],
    config: &CircleConfig,
) -> Result<AggregatedResponse, CoreError> {
    if clusters.is_empty() {
        return Err(CoreError::CircleOfExperts("No consensus clusters found".to_string()));
    }
    
    // Find the largest cluster (primary consensus)
    let (largest_cluster_idx, largest_cluster) = clusters
        .iter()
        .enumerate()
        .max_by_key(|(_, cluster)| cluster.len())
        .ok_or_else(|| CoreError::CircleOfExperts("Failed to find largest cluster".to_string()))?;
    
    // Process main consensus
    let consensus_responses: Vec<&ExpertResponse> = largest_cluster
        .iter()
        .map(|&idx| &responses[idx])
        .collect();
    
    let consensus_text = if config.enable_parallel_processing {
        synthesize_consensus_parallel(&consensus_responses)?
    } else {
        synthesize_consensus_sequential(&consensus_responses)?
    };
    
    // Calculate confidence score
    let confidence_score = calculate_aggregate_confidence(&consensus_responses);
    
    // Collect dissenting opinions from other clusters
    let dissenting_opinions = collect_dissenting_opinions(
        responses,
        clusters,
        largest_cluster_idx,
        config.enable_parallel_processing,
    )?;
    
    // Extract contributing experts
    let contributing_experts: Vec<String> = consensus_responses
        .iter()
        .map(|r| r.expert_name.clone())
        .collect();
    
    Ok(AggregatedResponse {
        consensus_text,
        confidence_score,
        dissenting_opinions,
        contributing_experts,
    })
}

/// Synthesize consensus text from multiple responses (parallel version)
fn synthesize_consensus_parallel(responses: &[&ExpertResponse]) -> Result<String, CoreError> {
    if responses.is_empty() {
        return Err(CoreError::CircleOfExperts("No responses to synthesize".to_string()));
    }
    
    // Extract key phrases in parallel
    let key_phrases: Vec<HashMap<String, usize>> = responses
        .par_iter()
        .map(|response| extract_key_phrases(&response.content))
        .collect();
    
    // Merge key phrases with frequency counts
    let mut merged_phrases: HashMap<String, usize> = HashMap::new();
    for phrase_map in key_phrases {
        for (phrase, count) in phrase_map {
            *merged_phrases.entry(phrase).or_insert(0) += count;
        }
    }
    
    // Sort phrases by frequency and relevance
    let mut sorted_phrases: Vec<(String, usize)> = merged_phrases.into_iter().collect();
    sorted_phrases.sort_by(|a, b| b.1.cmp(&a.1));
    
    // Build consensus text from most frequent phrases
    build_consensus_text(&sorted_phrases, responses)
}

/// Synthesize consensus text from multiple responses (sequential version)
fn synthesize_consensus_sequential(responses: &[&ExpertResponse]) -> Result<String, CoreError> {
    if responses.is_empty() {
        return Err(CoreError::CircleOfExperts("No responses to synthesize".to_string()));
    }
    
    let mut merged_phrases: HashMap<String, usize> = HashMap::new();
    
    for response in responses {
        let phrases = extract_key_phrases(&response.content);
        for (phrase, count) in phrases {
            *merged_phrases.entry(phrase).or_insert(0) += count;
        }
    }
    
    let mut sorted_phrases: Vec<(String, usize)> = merged_phrases.into_iter().collect();
    sorted_phrases.sort_by(|a, b| b.1.cmp(&a.1));
    
    build_consensus_text(&sorted_phrases, responses)
}

/// Extract key phrases from text
fn extract_key_phrases(text: &str) -> HashMap<String, usize> {
    let mut phrases = HashMap::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    
    // Extract single words (excluding common stop words)
    for word in &words {
        let normalized = word.to_lowercase();
        if !is_stop_word(&normalized) && normalized.len() > 3 {
            *phrases.entry(normalized).or_insert(0) += 1;
        }
    }
    
    // Extract bigrams
    for window in words.windows(2) {
        let bigram = format!("{} {}", window[0], window[1]).to_lowercase();
        if !contains_stop_word(&bigram) {
            *phrases.entry(bigram).or_insert(0) += 1;
        }
    }
    
    // Extract trigrams
    for window in words.windows(3) {
        let trigram = format!("{} {} {}", window[0], window[1], window[2]).to_lowercase();
        if !contains_stop_word(&trigram) {
            *phrases.entry(trigram).or_insert(0) += 1;
        }
    }
    
    phrases
}

/// Check if a word is a stop word
fn is_stop_word(word: &str) -> bool {
    const STOP_WORDS: &[&str] = &[
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "as", "is", "was", "are", "were", "be",
        "been", "being", "have", "has", "had", "do", "does", "did", "will",
        "would", "could", "should", "may", "might", "must", "can", "this",
        "that", "these", "those", "i", "you", "he", "she", "it", "we", "they",
    ];
    
    STOP_WORDS.contains(&word)
}

/// Check if a phrase contains stop words
fn contains_stop_word(phrase: &str) -> bool {
    phrase.split_whitespace().all(|word| is_stop_word(word))
}

/// Build consensus text from sorted phrases
fn build_consensus_text(
    sorted_phrases: &[(String, usize)],
    responses: &[&ExpertResponse],
) -> Result<String, CoreError> {
    // Take the most representative response as a base
    let base_response = responses
        .iter()
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
        .ok_or_else(|| CoreError::CircleOfExperts("No responses available".to_string()))?;
    
    // For now, return the highest confidence response
    // In a production system, this would use more sophisticated text generation
    Ok(format!(
        "{}\n\n[Consensus based on {} expert responses with key themes: {}]",
        base_response.content,
        responses.len(),
        sorted_phrases
            .iter()
            .take(5)
            .map(|(phrase, _)| phrase.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Calculate aggregate confidence score
fn calculate_aggregate_confidence(responses: &[&ExpertResponse]) -> f32 {
    if responses.is_empty() {
        return 0.0;
    }
    
    let total_confidence: f32 = responses.iter().map(|r| r.confidence).sum();
    let avg_confidence = total_confidence / responses.len() as f32;
    
    // Boost confidence based on agreement
    let agreement_boost = (responses.len() as f32 / 10.0).min(0.2);
    
    (avg_confidence + agreement_boost).min(1.0)
}

/// Collect dissenting opinions from non-consensus clusters
fn collect_dissenting_opinions(
    responses: &[ExpertResponse],
    clusters: &[Vec<usize>],
    consensus_cluster_idx: usize,
    parallel: bool,
) -> Result<Vec<String>, CoreError> {
    let dissenting_clusters: Vec<&Vec<usize>> = clusters
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != consensus_cluster_idx)
        .map(|(_, cluster)| cluster)
        .collect();
    
    if parallel {
        Ok(dissenting_clusters
            .par_iter()
            .map(|cluster| {
                let cluster_responses: Vec<&ExpertResponse> = cluster
                    .iter()
                    .map(|&idx| &responses[idx])
                    .collect();
                
                format!(
                    "Alternative view ({} experts): {}",
                    cluster.len(),
                    summarize_cluster(&cluster_responses)
                )
            })
            .collect())
    } else {
        Ok(dissenting_clusters
            .iter()
            .map(|cluster| {
                let cluster_responses: Vec<&ExpertResponse> = cluster
                    .iter()
                    .map(|&idx| &responses[idx])
                    .collect();
                
                format!(
                    "Alternative view ({} experts): {}",
                    cluster.len(),
                    summarize_cluster(&cluster_responses)
                )
            })
            .collect())
    }
}

/// Summarize a cluster of responses
fn summarize_cluster(responses: &[&ExpertResponse]) -> String {
    if responses.is_empty() {
        return String::new();
    }
    
    // Return the highest confidence response from the cluster
    responses
        .iter()
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
        .map(|r| r.content.clone())
        .unwrap_or_else(String::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_key_phrases() {
        let text = "The quick brown fox jumps over the lazy dog";
        let phrases = extract_key_phrases(text);
        
        assert!(phrases.contains_key("quick"));
        assert!(phrases.contains_key("brown"));
        assert!(phrases.contains_key("lazy"));
        assert!(!phrases.contains_key("the"));
    }
    
    #[test]
    fn test_calculate_aggregate_confidence() {
        let responses = vec![
            ExpertResponse {
                expert_name: "Expert1".to_string(),
                content: "Test".to_string(),
                confidence: 0.8,
                metadata: HashMap::new(),
                timestamp: 0,
            },
            ExpertResponse {
                expert_name: "Expert2".to_string(),
                content: "Test".to_string(),
                confidence: 0.9,
                metadata: HashMap::new(),
                timestamp: 0,
            },
        ];
        
        let response_refs: Vec<&ExpertResponse> = responses.iter().collect();
        let confidence = calculate_aggregate_confidence(&response_refs);
        
        assert!(confidence > 0.8 && confidence <= 1.0);
    }
}