// Result Aggregator - Intelligent result aggregation and ranking
use super::*;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use ordered_float::OrderedFloat;
use std::cmp::Ordering;
use rayon::prelude::*;

/// Result aggregator with deduplication and ranking
pub struct ResultAggregator {
    config: Arc<SynthexConfig>,
    deduplicator: Deduplicator,
    ranker: ResultRanker,
    clusterer: SemanticClusterer,
}

impl ResultAggregator {
    pub fn new(config: Arc<SynthexConfig>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            config,
            deduplicator: Deduplicator::new(),
            ranker: ResultRanker::new(),
            clusterer: SemanticClusterer::new(),
        })
    }
    
    /// Aggregate raw results into final search results
    pub async fn aggregate(&self, raw_results: Vec<RawSearchResults>) -> Result<SearchResult, Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();
        
        // Flatten all results
        let mut all_results: Vec<(RawResult, String)> = raw_results
            .par_iter()
            .flat_map(|raw| {
                raw.results
                    .iter()
                    .map(|r| (r.clone(), raw.source.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        
        // Deduplicate results
        let unique_results = self.deduplicator.deduplicate(&mut all_results);
        
        // Rank results
        let ranked_results = self.ranker.rank(unique_results);
        
        // Cluster results semantically
        let clustered_results = self.clusterer.cluster(ranked_results)?;
        
        // Create result groups
        let result_groups = self.create_result_groups(clustered_results);
        
        // Calculate metadata
        let metadata = self.calculate_metadata(&raw_results, &result_groups);
        
        Ok(SearchResult {
            query_id: uuid::Uuid::new_v4().to_string(),
            total_results: result_groups.iter().map(|g| g.items.len()).sum(),
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            results: result_groups,
            metadata,
        })
    }
    
    /// Create result groups from clusters
    fn create_result_groups(&self, clusters: Vec<ResultCluster>) -> Vec<ResultGroup> {
        clusters
            .into_par_iter()
            .map(|cluster| {
                let items = cluster
                    .results
                    .into_iter()
                    .map(|(result, source)| ResultItem {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: self.extract_title(&result.content),
                        snippet: self.create_snippet(&result.content),
                        source,
                        score: result.score,
                        metadata: result.metadata,
                    })
                    .collect();
                
                ResultGroup {
                    category: cluster.label,
                    relevance: cluster.avg_score,
                    items,
                }
            })
            .collect()
    }
    
    /// Extract title from content
    fn extract_title(&self, content: &str) -> String {
        // Simple implementation - take first line or 50 chars
        content
            .lines()
            .next()
            .unwrap_or(content)
            .chars()
            .take(50)
            .collect()
    }
    
    /// Create snippet from content
    fn create_snippet(&self, content: &str) -> String {
        // Take first 200 characters
        content.chars().take(200).collect::<String>() + "..."
    }
    
    /// Calculate search metadata
    fn calculate_metadata(&self, raw_results: &[RawSearchResults], result_groups: &[ResultGroup]) -> SearchMetadata {
        let sources_searched: HashSet<_> = raw_results
            .iter()
            .flat_map(|r| r.source.split(','))
            .map(|s| s.to_string())
            .collect();
        
        let total_queries = raw_results.len();
        let cache_hits = 0; // TODO: Implement cache tracking
        
        SearchMetadata {
            sources_searched: sources_searched.into_iter().collect(),
            optimizations_applied: vec!["deduplication".to_string(), "semantic_clustering".to_string()],
            cache_hit_rate: cache_hits as f64 / total_queries as f64,
            parallel_searches: total_queries,
        }
    }
}

/// Result deduplicator using multiple strategies
struct Deduplicator {
    similarity_threshold: f64,
}

impl Deduplicator {
    fn new() -> Self {
        Self {
            similarity_threshold: 0.85,
        }
    }
    
    fn deduplicate(&self, results: &mut [(RawResult, String)]) -> Vec<(RawResult, String)> {
        let mut unique_results = Vec::new();
        let mut seen_hashes = HashSet::new();
        let mut seen_contents = Vec::new();
        
        for (result, source) in results.drain(..) {
            // Check exact hash match
            let content_hash = self.hash_content(&result.content);
            if seen_hashes.contains(&content_hash) {
                continue;
            }
            
            // Check fuzzy similarity
            let mut is_duplicate = false;
            for seen_content in &seen_contents {
                if self.calculate_similarity(&result.content, seen_content) > self.similarity_threshold {
                    is_duplicate = true;
                    break;
                }
            }
            
            if !is_duplicate {
                seen_hashes.insert(content_hash);
                seen_contents.push(result.content.clone());
                unique_results.push((result, source));
            }
        }
        
        unique_results
    }
    
    fn hash_content(&self, content: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }
    
    fn calculate_similarity(&self, content1: &str, content2: &str) -> f64 {
        // Simple Jaccard similarity on words
        let words1: HashSet<_> = content1.split_whitespace().collect();
        let words2: HashSet<_> = content2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
}

/// Result ranker using multiple signals
struct ResultRanker {
    weights: RankingWeights,
}

#[derive(Clone)]
struct RankingWeights {
    relevance: f64,
    freshness: f64,
    source_trust: f64,
    user_feedback: f64,
}

impl Default for RankingWeights {
    fn default() -> Self {
        Self {
            relevance: 0.5,
            freshness: 0.2,
            source_trust: 0.2,
            user_feedback: 0.1,
        }
    }
}

impl ResultRanker {
    fn new() -> Self {
        Self {
            weights: RankingWeights::default(),
        }
    }
    
    fn rank(&self, mut results: Vec<(RawResult, String)>) -> Vec<(RawResult, String)> {
        let current_time = chrono::Utc::now().timestamp_millis() as u64;
        
        // Calculate composite scores
        results.par_sort_by(|a, b| {
            let score_a = self.calculate_composite_score(&a.0, &a.1, current_time);
            let score_b = self.calculate_composite_score(&b.0, &b.1, current_time);
            
            OrderedFloat(score_b).cmp(&OrderedFloat(score_a))
        });
        
        results
    }
    
    fn calculate_composite_score(&self, result: &RawResult, source: &str, current_time: u64) -> f64 {
        let relevance_score = result.score * self.weights.relevance;
        
        // Freshness score (exponential decay)
        let age_ms = current_time.saturating_sub(result.timestamp) as f64;
        let freshness_score = (-age_ms / (24.0 * 3600.0 * 1000.0)).exp() * self.weights.freshness;
        
        // Source trust score
        let source_trust = self.get_source_trust(source) * self.weights.source_trust;
        
        // User feedback (placeholder)
        let user_feedback = 0.5 * self.weights.user_feedback;
        
        relevance_score + freshness_score + source_trust + user_feedback
    }
    
    fn get_source_trust(&self, source: &str) -> f64 {
        match source {
            "database" => 0.95,
            "knowledge_base" => 0.9,
            "api" => 0.85,
            "web" => 0.7,
            _ => 0.5,
        }
    }
}

/// Semantic clusterer for grouping related results
struct SemanticClusterer {
    min_cluster_size: usize,
    max_clusters: usize,
}

impl SemanticClusterer {
    fn new() -> Self {
        Self {
            min_cluster_size: 3,
            max_clusters: 10,
        }
    }
    
    fn cluster(&self, results: Vec<(RawResult, String)>) -> Result<Vec<ResultCluster>, Box<dyn std::error::Error>> {
        if results.is_empty() {
            return Ok(vec![]);
        }
        
        // Simple clustering by content similarity
        let mut clusters = Vec::new();
        let mut unassigned = results;
        
        while !unassigned.is_empty() && clusters.len() < self.max_clusters {
            // Take first unassigned as cluster center
            let center = unassigned.remove(0);
            let mut cluster_members = vec![center.clone()];
            
            // Find similar results
            let mut i = 0;
            while i < unassigned.len() {
                if self.is_similar(&center.0.content, &unassigned[i].0.content) {
                    cluster_members.push(unassigned.remove(i));
                } else {
                    i += 1;
                }
            }
            
            // Create cluster if large enough
            if cluster_members.len() >= self.min_cluster_size {
                let avg_score = cluster_members.iter().map(|(r, _)| r.score).sum::<f64>() 
                    / cluster_members.len() as f64;
                
                clusters.push(ResultCluster {
                    label: self.generate_cluster_label(&cluster_members),
                    results: cluster_members,
                    avg_score,
                });
            } else {
                // Put back if cluster too small
                unassigned.extend(cluster_members);
            }
        }
        
        // Create misc cluster for remaining results
        if !unassigned.is_empty() {
            let avg_score = unassigned.iter().map(|(r, _)| r.score).sum::<f64>() 
                / unassigned.len() as f64;
            
            clusters.push(ResultCluster {
                label: "Other Results".to_string(),
                results: unassigned,
                avg_score,
            });
        }
        
        // Sort clusters by average score
        clusters.sort_by(|a, b| OrderedFloat(b.avg_score).cmp(&OrderedFloat(a.avg_score)));
        
        Ok(clusters)
    }
    
    fn is_similar(&self, content1: &str, content2: &str) -> bool {
        // Simple similarity check - in production would use embeddings
        let words1: HashSet<_> = content1.split_whitespace().take(20).collect();
        let words2: HashSet<_> = content2.split_whitespace().take(20).collect();
        
        let intersection = words1.intersection(&words2).count();
        intersection > 5 // Arbitrary threshold
    }
    
    fn generate_cluster_label(&self, cluster: &[(RawResult, String)]) -> String {
        // Extract common words for label
        let all_words: Vec<_> = cluster
            .iter()
            .flat_map(|(r, _)| r.content.split_whitespace().take(10))
            .collect();
        
        // Find most common word (simple approach)
        let mut word_counts = HashMap::new();
        for word in all_words {
            *word_counts.entry(word).or_insert(0) += 1;
        }
        
        word_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(word, _)| word.to_string())
            .unwrap_or_else(|| "General".to_string())
    }
}

/// Result cluster
struct ResultCluster {
    label: String,
    results: Vec<(RawResult, String)>,
    avg_score: f64,
}

// External dependencies
use ordered_float;
use rayon;