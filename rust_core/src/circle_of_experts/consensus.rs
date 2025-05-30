// ============================================================================
// CONSENSUS ALGORITHMS - Fast Parallel Consensus Computation
// ============================================================================
// This module implements high-performance consensus algorithms for the Circle
// of Experts system, utilizing parallel processing and optimized similarity
// calculations to achieve significant speedups over Python implementations.
// ============================================================================

use crate::circle_of_experts::{CircleConfig, ExpertResponse, SimilarityAlgorithm};
use crate::CoreError;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

/// Compute similarity matrix between all expert responses
pub fn compute_similarity_matrix(
    responses: &[ExpertResponse],
    config: &CircleConfig,
) -> Result<Vec<Vec<f32>>, CoreError> {
    let n = responses.len();
    let mut matrix = vec![vec![0.0; n]; n];
    
    if config.enable_parallel_processing {
        // Parallel computation of similarity matrix
        matrix.par_iter_mut().enumerate().for_each(|(i, row)| {
            for j in 0..n {
                if i == j {
                    row[j] = 1.0;
                } else if j > i {
                    let similarity = calculate_similarity(
                        &responses[i].content,
                        &responses[j].content,
                        config.similarity_algorithm,
                    );
                    row[j] = similarity;
                }
            }
        });
        
        // Fill lower triangle (matrix is symmetric)
        for i in 0..n {
            for j in 0..i {
                matrix[i][j] = matrix[j][i];
            }
        }
    } else {
        // Sequential computation
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    matrix[i][j] = 1.0;
                } else if j > i {
                    let similarity = calculate_similarity(
                        &responses[i].content,
                        &responses[j].content,
                        config.similarity_algorithm,
                    );
                    matrix[i][j] = similarity;
                    matrix[j][i] = similarity;
                }
            }
        }
    }
    
    Ok(matrix)
}

/// Calculate similarity between two text strings
fn calculate_similarity(text1: &str, text2: &str, algorithm: SimilarityAlgorithm) -> f32 {
    match algorithm {
        SimilarityAlgorithm::Cosine => cosine_similarity(text1, text2),
        SimilarityAlgorithm::Jaccard => jaccard_similarity(text1, text2),
        SimilarityAlgorithm::LevenshteinNormalized => levenshtein_normalized(text1, text2),
        SimilarityAlgorithm::SemanticEmbedding => {
            // Placeholder for semantic embedding similarity
            // In production, this would use pre-computed embeddings
            cosine_similarity(text1, text2)
        }
    }
}

/// Cosine similarity between two texts (TF-IDF based)
fn cosine_similarity(text1: &str, text2: &str) -> f32 {
    let words1: HashSet<&str> = text1.split_whitespace().collect();
    let words2: HashSet<&str> = text2.split_whitespace().collect();
    
    // Create vocabulary
    let mut vocabulary: HashSet<&str> = words1.clone();
    vocabulary.extend(&words2);
    
    // Create term frequency vectors
    let vec1: Vec<f32> = vocabulary
        .iter()
        .map(|word| if words1.contains(word) { 1.0 } else { 0.0 })
        .collect();
    
    let vec2: Vec<f32> = vocabulary
        .iter()
        .map(|word| if words2.contains(word) { 1.0 } else { 0.0 })
        .collect();
    
    // Calculate cosine similarity
    let dot_product: f32 = vec1.iter().zip(vec2.iter()).map(|(a, b)| a * b).sum();
    let norm1: f32 = vec1.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm2: f32 = vec2.iter().map(|x| x * x).sum::<f32>().sqrt();
    
    if norm1 == 0.0 || norm2 == 0.0 {
        0.0
    } else {
        dot_product / (norm1 * norm2)
    }
}

/// Jaccard similarity between two texts
fn jaccard_similarity(text1: &str, text2: &str) -> f32 {
    let words1: HashSet<&str> = text1.split_whitespace().collect();
    let words2: HashSet<&str> = text2.split_whitespace().collect();
    
    let intersection = words1.intersection(&words2).count() as f32;
    let union = words1.union(&words2).count() as f32;
    
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Normalized Levenshtein distance (1 - normalized_distance)
fn levenshtein_normalized(text1: &str, text2: &str) -> f32 {
    let len1 = text1.chars().count();
    let len2 = text2.chars().count();
    
    if len1 == 0 || len2 == 0 {
        return if len1 == len2 { 1.0 } else { 0.0 };
    }
    
    let max_len = len1.max(len2);
    let distance = levenshtein_distance(text1, text2);
    
    1.0 - (distance as f32 / max_len as f32)
}

/// Basic Levenshtein distance implementation
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let v1: Vec<char> = s1.chars().collect();
    let v2: Vec<char> = s2.chars().collect();
    let len1 = v1.len();
    let len2 = v2.len();
    
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];
    
    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    
    for j in 0..=len2 {
        matrix[0][j] = j;
    }
    
    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if v1[i - 1] == v2[j - 1] { 0 } else { 1 };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }
    
    matrix[len1][len2]
}

/// Cluster responses based on similarity threshold
pub fn find_consensus_clusters(
    similarity_matrix: &[Vec<f32>],
    threshold: f32,
) -> Result<Vec<Vec<usize>>, CoreError> {
    let n = similarity_matrix.len();
    let mut visited = vec![false; n];
    let mut clusters = Vec::new();
    
    for i in 0..n {
        if !visited[i] {
            let mut cluster = vec![i];
            visited[i] = true;
            
            // Find all responses similar to this one
            for j in (i + 1)..n {
                if !visited[j] && similarity_matrix[i][j] >= threshold {
                    cluster.push(j);
                    visited[j] = true;
                }
            }
            
            clusters.push(cluster);
        }
    }
    
    Ok(clusters)
}

/// Advanced clustering using DBSCAN-like algorithm
pub fn find_density_clusters(
    similarity_matrix: &[Vec<f32>],
    min_similarity: f32,
    min_cluster_size: usize,
) -> Result<Vec<Vec<usize>>, CoreError> {
    let n = similarity_matrix.len();
    let mut labels = vec![-1i32; n];
    let mut cluster_id = 0;
    
    for i in 0..n {
        if labels[i] != -1 {
            continue;
        }
        
        // Find neighbors
        let neighbors: Vec<usize> = (0..n)
            .filter(|&j| i != j && similarity_matrix[i][j] >= min_similarity)
            .collect();
        
        if neighbors.len() >= min_cluster_size - 1 {
            // Start new cluster
            labels[i] = cluster_id;
            let mut seeds = neighbors.clone();
            let mut seed_idx = 0;
            
            while seed_idx < seeds.len() {
                let q = seeds[seed_idx];
                if labels[q] == -1 {
                    labels[q] = cluster_id;
                    
                    let q_neighbors: Vec<usize> = (0..n)
                        .filter(|&j| q != j && similarity_matrix[q][j] >= min_similarity)
                        .collect();
                    
                    if q_neighbors.len() >= min_cluster_size - 1 {
                        for &neighbor in &q_neighbors {
                            if labels[neighbor] == -1 && !seeds.contains(&neighbor) {
                                seeds.push(neighbor);
                            }
                        }
                    }
                }
                seed_idx += 1;
            }
            
            cluster_id += 1;
        }
    }
    
    // Group by cluster labels
    let mut clusters: HashMap<i32, Vec<usize>> = HashMap::new();
    for (idx, &label) in labels.iter().enumerate() {
        if label != -1 {
            clusters.entry(label).or_insert_with(Vec::new).push(idx);
        }
    }
    
    Ok(clusters.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cosine_similarity() {
        let text1 = "the quick brown fox";
        let text2 = "the quick brown dog";
        let similarity = cosine_similarity(text1, text2);
        assert!(similarity > 0.5 && similarity < 1.0);
    }
    
    #[test]
    fn test_jaccard_similarity() {
        let text1 = "hello world test";
        let text2 = "hello world example";
        let similarity = jaccard_similarity(text1, text2);
        assert!((similarity - 0.5).abs() < 0.01); // Should be approximately 0.5
    }
    
    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("hello", "hallo"), 1);
        assert_eq!(levenshtein_distance("saturday", "sunday"), 3);
    }
    
    #[test]
    fn test_find_consensus_clusters() {
        let matrix = vec![
            vec![1.0, 0.9, 0.2, 0.1],
            vec![0.9, 1.0, 0.1, 0.2],
            vec![0.2, 0.1, 1.0, 0.8],
            vec![0.1, 0.2, 0.8, 1.0],
        ];
        
        let clusters = find_consensus_clusters(&matrix, 0.7).unwrap();
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].len(), 2);
        assert_eq!(clusters[1].len(), 2);
    }
}