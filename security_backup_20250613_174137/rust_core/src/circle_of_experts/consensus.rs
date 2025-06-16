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
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

#[cfg(feature = "simd")]
use crate::simd_ops::{simd_dot_product, simd_sum_f32};

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

/// High-performance consensus computation with caching and optimizations
pub struct OptimizedConsensusEngine {
    similarity_cache: Arc<DashMap<(usize, usize), f32>>,
    word_vectors: Arc<RwLock<HashMap<String, Vec<f32>>>>,
    config: Arc<CircleConfig>,
}

impl OptimizedConsensusEngine {
    pub fn new(config: CircleConfig) -> Self {
        Self {
            similarity_cache: Arc::new(DashMap::new()),
            word_vectors: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
        }
    }
    
    /// Compute similarity matrix with aggressive caching and parallelization
    pub fn compute_similarity_matrix_optimized(
        &self,
        responses: &[ExpertResponse],
    ) -> Result<Vec<Vec<f32>>, CoreError> {
        let n = responses.len();
        
        if n == 0 {
            return Ok(Vec::new());
        }
        
        if n == 1 {
            return Ok(vec![vec![1.0]]);
        }
        
        // Pre-compute text features in parallel
        let text_features: Vec<_> = responses
            .par_iter()
            .enumerate()
            .map(|(i, response)| {
                (i, self.extract_text_features(&response.content))
            })
            .collect();
        
        // Compute similarity matrix in parallel chunks
        let chunk_size = ((n * n) / rayon::current_num_threads()).max(1);
        let pairs: Vec<(usize, usize)> = (0..n)
            .flat_map(|i| (i..n).map(move |j| (i, j)))
            .collect();
        
        let similarities: Vec<_> = pairs
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk.iter().map(|&(i, j)| {
                    let similarity = if i == j {
                        1.0
                    } else if let Some(&cached) = self.similarity_cache.get(&(i, j)) {
                        cached
                    } else if let Some(&cached) = self.similarity_cache.get(&(j, i)) {
                        cached
                    } else {
                        let sim = self.calculate_similarity_optimized(
                            &text_features[i].1,
                            &text_features[j].1,
                        );
                        self.similarity_cache.insert((i, j), sim);
                        sim
                    };
                    ((i, j), similarity)
                }).collect::<Vec<_>>()
            })
            .collect();
        
        // Build matrix from computed similarities
        let mut matrix = vec![vec![0.0; n]; n];
        for ((i, j), similarity) in similarities {
            matrix[i][j] = similarity;
            if i != j {
                matrix[j][i] = similarity;
            }
        }
        
        Ok(matrix)
    }
    
    /// Extract optimized text features for fast similarity computation
    fn extract_text_features(&self, text: &str) -> TextFeatures {
        let words: Vec<&str> = text.split_whitespace().collect();
        let word_counts = self.compute_word_counts(&words);
        let ngrams = self.extract_ngrams(text, 2);
        
        TextFeatures {
            words: words.into_iter().map(String::from).collect(),
            word_counts,
            ngrams,
            length: text.len(),
        }
    }
    
    /// Compute word frequency counts
    fn compute_word_counts(&self, words: &[&str]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for word in words {
            *counts.entry(word.to_lowercase()).or_insert(0) += 1;
        }
        counts
    }
    
    /// Extract n-grams for enhanced similarity
    fn extract_ngrams(&self, text: &str, n: usize) -> HashSet<String> {
        let chars: Vec<char> = text.chars().collect();
        chars
            .windows(n)
            .map(|window| window.iter().collect())
            .collect()
    }
    
    /// High-performance similarity calculation
    fn calculate_similarity_optimized(&self, features1: &TextFeatures, features2: &TextFeatures) -> f32 {
        match self.config.similarity_algorithm {
            SimilarityAlgorithm::Cosine => self.cosine_similarity_optimized(features1, features2),
            SimilarityAlgorithm::Jaccard => self.jaccard_similarity_optimized(features1, features2),
            SimilarityAlgorithm::LevenshteinNormalized => {
                self.levenshtein_similarity_optimized(features1, features2)
            }
            SimilarityAlgorithm::SemanticEmbedding => {
                self.semantic_similarity_optimized(features1, features2)
            }
        }
    }
    
    /// Optimized cosine similarity using pre-computed features
    fn cosine_similarity_optimized(&self, features1: &TextFeatures, features2: &TextFeatures) -> f32 {
        let mut vocabulary: HashSet<String> = features1.word_counts.keys().cloned().collect();
        vocabulary.extend(features2.word_counts.keys().cloned());
        
        let vec1: Vec<f32> = vocabulary
            .iter()
            .map(|word| *features1.word_counts.get(word).unwrap_or(&0) as f32)
            .collect();
        
        let vec2: Vec<f32> = vocabulary
            .iter()
            .map(|word| *features2.word_counts.get(word).unwrap_or(&0) as f32)
            .collect();
        
        #[cfg(feature = "simd")]
        {
            if let (Ok(dot_product), Ok(norm1_sq), Ok(norm2_sq)) = (
                simd_dot_product(&vec1, &vec2),
                simd_dot_product(&vec1, &vec1),
                simd_dot_product(&vec2, &vec2)
            ) {
                let norm1 = norm1_sq.sqrt();
                let norm2 = norm2_sq.sqrt();
                
                if norm1 == 0.0 || norm2 == 0.0 {
                    return 0.0;
                }
                
                return dot_product / (norm1 * norm2);
            }
        }
        
        // Fallback to scalar computation
        let dot_product: f32 = vec1.iter().zip(vec2.iter()).map(|(a, b)| a * b).sum();
        let norm1: f32 = vec1.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm2: f32 = vec2.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        if norm1 == 0.0 || norm2 == 0.0 {
            0.0
        } else {
            dot_product / (norm1 * norm2)
        }
    }
    
    /// Optimized Jaccard similarity
    fn jaccard_similarity_optimized(&self, features1: &TextFeatures, features2: &TextFeatures) -> f32 {
        let set1: HashSet<&String> = features1.words.iter().collect();
        let set2: HashSet<&String> = features2.words.iter().collect();
        
        let intersection = set1.intersection(&set2).count() as f32;
        let union = set1.union(&set2).count() as f32;
        
        if union == 0.0 {
            0.0
        } else {
            intersection / union
        }
    }
    
    /// Optimized Levenshtein similarity
    fn levenshtein_similarity_optimized(&self, features1: &TextFeatures, features2: &TextFeatures) -> f32 {
        // Use n-gram overlap as a fast approximation for similar texts
        let ngram_intersection = features1.ngrams.intersection(&features2.ngrams).count() as f32;
        let ngram_union = features1.ngrams.union(&features2.ngrams).count() as f32;
        
        if ngram_union == 0.0 {
            0.0
        } else {
            ngram_intersection / ngram_union
        }
    }
    
    /// Semantic similarity using cached embeddings
    fn semantic_similarity_optimized(&self, features1: &TextFeatures, features2: &TextFeatures) -> f32 {
        // Placeholder for semantic embeddings - would use pre-computed vectors
        // For now, fallback to enhanced cosine similarity
        self.cosine_similarity_optimized(features1, features2)
    }
    
    /// Parallel clustering with hierarchical approach
    pub fn find_hierarchical_clusters(
        &self,
        similarity_matrix: &[Vec<f32>],
        threshold: f32,
    ) -> Result<Vec<Vec<usize>>, CoreError> {
        let n = similarity_matrix.len();
        
        if n <= 1 {
            return Ok(if n == 0 { Vec::new() } else { vec![vec![0]] });
        }
        
        // Use parallel union-find for clustering
        let mut parent: Vec<usize> = (0..n).collect();
        let mut rank = vec![0; n];
        
        // Find strongly connected components in parallel
        let edges: Vec<(usize, usize, f32)> = (0..n)
            .into_par_iter()
            .flat_map(|i| {
                (i + 1..n).into_par_iter().filter_map(move |j| {
                    let similarity = similarity_matrix[i][j];
                    if similarity >= threshold {
                        Some((i, j, similarity))
                    } else {
                        None
                    }
                })
            })
            .collect();
        
        // Sort edges by similarity (strongest first)
        let mut sorted_edges = edges;
        sorted_edges.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        
        // Union-find operations
        for (u, v, _) in sorted_edges {
            self.union(&mut parent, &mut rank, u, v);
        }
        
        // Group by root
        let mut clusters: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let root = self.find(&mut parent, i);
            clusters.entry(root).or_insert_with(Vec::new).push(i);
        }
        
        Ok(clusters.into_values().collect())
    }
    
    fn find(&self, parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            parent[x] = self.find(parent, parent[x]); // Path compression
        }
        parent[x]
    }
    
    fn union(&self, parent: &mut [usize], rank: &mut [usize], x: usize, y: usize) {
        let root_x = self.find(parent, x);
        let root_y = self.find(parent, y);
        
        if root_x != root_y {
            // Union by rank
            if rank[root_x] < rank[root_y] {
                parent[root_x] = root_y;
            } else if rank[root_x] > rank[root_y] {
                parent[root_y] = root_x;
            } else {
                parent[root_y] = root_x;
                rank[root_x] += 1;
            }
        }
    }
    
    /// Clear caches to free memory
    pub fn clear_caches(&self) {
        self.similarity_cache.clear();
        self.word_vectors.write().clear();
    }
    
    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        (
            self.similarity_cache.len(),
            self.word_vectors.read().len(),
        )
    }
}

/// Pre-computed text features for fast similarity calculation
#[derive(Debug, Clone)]
struct TextFeatures {
    words: Vec<String>,
    word_counts: HashMap<String, usize>,
    ngrams: HashSet<String>,
    length: usize,
}

/// Parallel consensus voting with weighted expertise
pub fn parallel_weighted_consensus(
    responses: &[ExpertResponse],
    similarity_matrix: &[Vec<f32>],
    expert_weights: &[f32],
) -> Result<f32, CoreError> {
    if responses.len() != similarity_matrix.len() || responses.len() != expert_weights.len() {
        return Err(CoreError::CircleOfExperts("Mismatched input sizes".to_string()));
    }
    
    let n = responses.len();
    if n == 0 {
        return Ok(0.0);
    }
    
    // Compute weighted consensus scores in parallel
    let consensus_scores: Vec<f32> = (0..n)
        .into_par_iter()
        .map(|i| {
            let mut weighted_score = 0.0;
            let mut total_weight = 0.0;
            
            for j in 0..n {
                let similarity = similarity_matrix[i][j];
                let weight = expert_weights[j];
                let confidence = responses[j].confidence;
                
                weighted_score += similarity * weight * confidence;
                total_weight += weight;
            }
            
            if total_weight > 0.0 {
                weighted_score / total_weight
            } else {
                0.0
            }
        })
        .collect();
    
    // Return the maximum consensus score
    consensus_scores
        .into_iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .ok_or_else(|| CoreError::CircleOfExperts("Failed to compute consensus".to_string()))
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