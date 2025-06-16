//! Graph-based memory for dependency tracking and relationship analysis
//! 
//! Uses petgraph for efficient graph operations and community detection

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::memory::{
    CommandPattern, ExecutionResult, MemoryStats, OptimizationResult,
};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::{tarjan_scc, dijkstra};
use petgraph::visit::EdgeRef;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Graph-based memory for command relationships
pub struct GraphMemory {
    /// Dependency graph
    graph: Arc<RwLock<DiGraph<GraphNode, GraphEdge>>>,
    
    /// Node index mapping
    node_index: Arc<DashMap<String, NodeIndex>>,
    
    /// Reverse index (NodeIndex -> pattern ID)
    reverse_index: Arc<DashMap<NodeIndex, String>>,
    
    /// Community detection results
    communities: Arc<RwLock<Vec<Community>>>,
    
    /// Configuration
    config: GraphMemoryConfig,
}

/// Graph node representing a command or pattern
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// Node ID (pattern or command ID)
    pub id: String,
    
    /// Node type
    pub node_type: NodeType,
    
    /// Node weight (importance)
    pub weight: f32,
    
    /// Metadata
    pub metadata: NodeMetadata,
}

/// Node types in the graph
#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    /// Command pattern node
    Pattern,
    
    /// Individual command node
    Command,
    
    /// Resource node (file, network, etc.)
    Resource,
    
    /// Environment node
    Environment,
}

/// Node metadata
#[derive(Debug, Clone)]
pub struct NodeMetadata {
    /// Creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Last accessed
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    
    /// Access count
    pub access_count: u64,
    
    /// Success rate
    pub success_rate: f32,
}

/// Graph edge representing relationships
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// Edge type
    pub edge_type: EdgeType,
    
    /// Edge weight (strength of relationship)
    pub weight: f32,
    
    /// Metadata
    pub metadata: EdgeMetadata,
}

/// Edge types in the graph
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeType {
    /// Dependency relationship
    DependsOn,
    
    /// Sequence relationship (A followed by B)
    Sequence,
    
    /// Parallel execution
    Parallel,
    
    /// Resource access
    AccessesResource,
    
    /// Similarity relationship
    Similar,
}

/// Edge metadata
#[derive(Debug, Clone)]
pub struct EdgeMetadata {
    /// Number of times this edge was traversed
    pub traversal_count: u64,
    
    /// Average traversal time
    pub avg_traversal_time_ms: f64,
    
    /// Success rate of traversal
    pub success_rate: f32,
}

/// Community of related nodes
#[derive(Debug, Clone)]
pub struct Community {
    /// Community ID
    pub id: String,
    
    /// Member node IDs
    pub members: Vec<String>,
    
    /// Community type
    pub community_type: CommunityType,
    
    /// Community score
    pub score: f32,
}

/// Types of communities
#[derive(Debug, Clone)]
pub enum CommunityType {
    /// Workflow community (related commands)
    Workflow,
    
    /// Resource community (commands accessing same resources)
    Resource,
    
    /// Temporal community (commands executed together)
    Temporal,
}

/// Graph memory configuration
#[derive(Debug, Clone)]
pub struct GraphMemoryConfig {
    /// Maximum nodes in graph
    pub max_nodes: usize,
    
    /// Maximum edges per node
    pub max_edges_per_node: usize,
    
    /// Edge weight threshold for pruning
    pub edge_weight_threshold: f32,
    
    /// Community detection interval
    pub community_detection_interval: std::time::Duration,
}

impl Default for GraphMemoryConfig {
    fn default() -> Self {
        Self {
            max_nodes: 50_000,
            max_edges_per_node: 100,
            edge_weight_threshold: 0.1,
            community_detection_interval: std::time::Duration::from_secs(300),
        }
    }
}

impl GraphMemory {
    /// Create a new graph memory
    pub fn new(config: GraphMemoryConfig) -> Self {
        Self {
            graph: Arc::new(RwLock::new(DiGraph::new())),
            node_index: Arc::new(DashMap::new()),
            reverse_index: Arc::new(DashMap::new()),
            communities: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }
    
    /// Add a pattern to the graph
    pub async fn add_pattern(&self, pattern: &CommandPattern) -> Result<()> {
        let mut graph = self.graph.write().await;
        
        // Add pattern node
        let pattern_node = GraphNode {
            id: pattern.id.clone(),
            node_type: NodeType::Pattern,
            weight: 1.0,
            metadata: NodeMetadata {
                created_at: pattern.context.created_at,
                last_accessed: pattern.context.last_accessed,
                access_count: pattern.metrics.execution_count,
                success_rate: pattern.metrics.success_rate,
            },
        };
        
        let pattern_idx = graph.add_node(pattern_node);
        self.node_index.insert(pattern.id.clone(), pattern_idx);
        self.reverse_index.insert(pattern_idx, pattern.id.clone());
        
        // Add command nodes and edges
        for (i, command) in pattern.commands.iter().enumerate() {
            let command_id = format!("{}:cmd:{}", pattern.id, i);
            
            let command_node = GraphNode {
                id: command_id.clone(),
                node_type: NodeType::Command,
                weight: 0.5,
                metadata: NodeMetadata {
                    created_at: chrono::Utc::now(),
                    last_accessed: chrono::Utc::now(),
                    access_count: 1,
                    success_rate: 1.0,
                },
            };
            
            let cmd_idx = graph.add_node(command_node);
            self.node_index.insert(command_id.clone(), cmd_idx);
            self.reverse_index.insert(cmd_idx, command_id);
            
            // Add edge from pattern to command
            graph.add_edge(
                pattern_idx,
                cmd_idx,
                GraphEdge {
                    edge_type: EdgeType::DependsOn,
                    weight: 1.0,
                    metadata: EdgeMetadata {
                        traversal_count: 1,
                        avg_traversal_time_ms: 0.0,
                        success_rate: 1.0,
                    },
                },
            );
            
            // Add sequence edges between commands
            if i > 0 {
                let prev_cmd_id = format!("{}:cmd:{}", pattern.id, i - 1);
                if let Some(prev_idx_ref) = self.node_index.get(&prev_cmd_id) {
                    let prev_idx = *prev_idx_ref;
                    graph.add_edge(
                        prev_idx,
                        cmd_idx,
                        GraphEdge {
                            edge_type: EdgeType::Sequence,
                            weight: 1.0,
                            metadata: EdgeMetadata {
                                traversal_count: 1,
                                avg_traversal_time_ms: 0.0,
                                success_rate: 1.0,
                            },
                        },
                    );
                }
            }
        }
        
        // Add dependency edges
        for (from, to) in &pattern.dependencies {
            let from_id = format!("{}:cmd:{}", pattern.id, from);
            let to_id = format!("{}:cmd:{}", pattern.id, to);
            
            if let (Some(from_idx_ref), Some(to_idx_ref)) = 
                (self.node_index.get(&from_id), self.node_index.get(&to_id)) {
                let from_idx = *from_idx_ref;
                let to_idx = *to_idx_ref;
                graph.add_edge(
                    from_idx,
                    to_idx,
                    GraphEdge {
                        edge_type: EdgeType::DependsOn,
                        weight: 1.0,
                        metadata: EdgeMetadata {
                            traversal_count: 1,
                            avg_traversal_time_ms: 0.0,
                            success_rate: 1.0,
                        },
                    },
                );
            }
        }
        
        // Check if we need to prune
        if graph.node_count() > self.config.max_nodes {
            self.prune_graph(&mut graph).await?;
        }
        
        debug!("Added pattern {} to graph", pattern.id);
        
        Ok(())
    }
    
    /// Find related patterns using graph traversal
    pub async fn find_related(
        &self,
        pattern_id: &str,
        max_distance: u32,
    ) -> Result<Vec<(String, f32)>> {
        let graph = self.graph.read().await;
        
        let start_idx = match self.node_index.get(pattern_id) {
            Some(idx_ref) => *idx_ref,
            None => return Ok(Vec::new()),
        };
        
        // Use Dijkstra's algorithm to find shortest paths
        let distances = dijkstra(
            &*graph,
            start_idx,
            None,
            |edge| 1.0 / edge.weight().weight, // Inverse weight for distance
        );
        
        let mut related = Vec::new();
        
        for (node_idx, distance) in distances {
            if distance <= max_distance as f32 && node_idx != start_idx {
                if let Some(id) = self.reverse_index.get(&node_idx) {
                    if let Some(node) = graph.node_weight(node_idx) {
                        if node.node_type == NodeType::Pattern {
                            // Calculate relatedness score
                            let score = 1.0 / (1.0 + distance);
                            related.push((id.clone(), score));
                        }
                    }
                }
            }
        }
        
        // Sort by score descending
        related.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(related)
    }
    
    /// Update edge statistics
    pub async fn update_edge_stats(
        &self,
        from_id: &str,
        to_id: &str,
        execution_result: &ExecutionResult,
    ) -> Result<()> {
        let mut graph = self.graph.write().await;
        
        if let (Some(from_idx_ref), Some(to_idx_ref)) = 
            (self.node_index.get(from_id), self.node_index.get(to_id)) {
            let from_idx = *from_idx_ref;
            let to_idx = *to_idx_ref;
            
            // Find edge
            if let Some(edge_idx) = graph.find_edge(from_idx, to_idx) {
                if let Some(edge) = graph.edge_weight_mut(edge_idx) {
                    let metadata = &mut edge.metadata;
                    
                    // Update traversal statistics
                    let n = metadata.traversal_count as f64;
                    metadata.avg_traversal_time_ms = 
                        (metadata.avg_traversal_time_ms * n + execution_result.execution_time_ms as f64) / (n + 1.0);
                    
                    // Update success rate
                    let successes = (metadata.success_rate * n as f32) as u64;
                    let new_successes = if execution_result.success { successes + 1 } else { successes };
                    metadata.success_rate = new_successes as f32 / (n + 1.0) as f32;
                    
                    metadata.traversal_count += 1;
                    
                    // Update edge weight based on success rate and usage
                    edge.weight = metadata.success_rate * (metadata.traversal_count as f32).ln();
                }
            }
            
            // Update node access statistics
            if let Some(node) = graph.node_weight_mut(to_idx) {
                node.metadata.last_accessed = chrono::Utc::now();
                node.metadata.access_count += 1;
            }
        }
        
        Ok(())
    }
    
    /// Detect communities in the graph
    pub async fn detect_communities(&self) -> Result<Vec<Community>> {
        let graph = self.graph.read().await;
        
        // Find strongly connected components
        let sccs = tarjan_scc(&*graph);
        
        let mut communities = Vec::new();
        
        for (i, scc) in sccs.iter().enumerate() {
            if scc.len() > 1 {
                // Create community from SCC
                let mut members = Vec::new();
                let mut total_weight = 0.0;
                
                for &node_idx in scc {
                    if let Some(id) = self.reverse_index.get(&node_idx) {
                        if let Some(node) = graph.node_weight(node_idx) {
                            if node.node_type == NodeType::Pattern {
                                members.push(id.clone());
                                total_weight += node.weight;
                            }
                        }
                    }
                }
                
                if !members.is_empty() {
                    communities.push(Community {
                        id: format!("community_{}", i),
                        members,
                        community_type: CommunityType::Workflow,
                        score: total_weight / scc.len() as f32,
                    });
                }
            }
        }
        
        // Update stored communities
        *self.communities.write().await = communities.clone();
        
        info!("Detected {} communities", communities.len());
        
        Ok(communities)
    }
    
    /// Get graph statistics
    pub async fn get_stats(&self) -> (u64, u64, u64) {
        let graph = self.graph.read().await;
        
        let node_count = graph.node_count() as u64;
        let edge_count = graph.edge_count() as u64;
        let pattern_count = graph.node_indices()
            .filter(|&idx| {
                graph.node_weight(idx)
                    .map(|n| n.node_type == NodeType::Pattern)
                    .unwrap_or(false)
            })
            .count() as u64;
        
        (pattern_count, node_count, edge_count)
    }
    
    /// Prune low-weight edges and isolated nodes
    async fn prune_graph(&self, graph: &mut DiGraph<GraphNode, GraphEdge>) -> Result<()> {
        let mut edges_to_remove = Vec::new();
        
        // Find low-weight edges
        for edge_idx in graph.edge_indices() {
            if let Some(edge) = graph.edge_weight(edge_idx) {
                if edge.weight < self.config.edge_weight_threshold {
                    edges_to_remove.push(edge_idx);
                }
            }
        }
        
        // Remove low-weight edges
        for edge_idx in edges_to_remove {
            graph.remove_edge(edge_idx);
        }
        
        // Find isolated nodes
        let mut nodes_to_remove = Vec::new();
        for node_idx in graph.node_indices() {
            if graph.edges(node_idx).count() == 0 {
                nodes_to_remove.push(node_idx);
            }
        }
        
        // Remove isolated nodes
        for node_idx in nodes_to_remove {
            if let Some(id) = self.reverse_index.remove(&node_idx) {
                self.node_index.remove(&id.1);
            }
            graph.remove_node(node_idx);
        }
        
        Ok(())
    }
    
    /// Optimize graph memory
    pub async fn optimize(&self) -> Result<OptimizationResult> {
        let start = std::time::Instant::now();
        let mut graph = self.graph.write().await;
        
        let initial_nodes = graph.node_count();
        let initial_edges = graph.edge_count();
        
        // Prune graph
        self.prune_graph(&mut graph).await?;
        
        // Remove old nodes
        let cutoff_time = chrono::Utc::now() - chrono::Duration::days(30);
        let mut old_nodes = Vec::new();
        
        for node_idx in graph.node_indices() {
            if let Some(node) = graph.node_weight(node_idx) {
                if node.metadata.last_accessed < cutoff_time {
                    old_nodes.push(node_idx);
                }
            }
        }
        
        for node_idx in old_nodes {
            if let Some(id) = self.reverse_index.remove(&node_idx) {
                self.node_index.remove(&id.1);
            }
            graph.remove_node(node_idx);
        }
        
        let nodes_pruned = initial_nodes - graph.node_count();
        let edges_pruned = initial_edges - graph.edge_count();
        
        Ok(OptimizationResult {
            memory_freed_mb: (nodes_pruned * 100 + edges_pruned * 50) as u64 / 1024,
            patterns_evicted: 0,
            nodes_pruned: nodes_pruned as u64,
            optimization_time_ms: start.elapsed().as_millis() as u64,
        })
    }
    
    /// Find optimal execution path between patterns
    pub async fn find_optimal_path(
        &self,
        from_pattern: &str,
        to_pattern: &str,
    ) -> Result<Vec<String>> {
        let graph = self.graph.read().await;
        
        let from_idx = match self.node_index.get(from_pattern) {
            Some(idx_ref) => *idx_ref,
            None => return Ok(Vec::new()),
        };
        
        let to_idx = match self.node_index.get(to_pattern) {
            Some(idx_ref) => *idx_ref,
            None => return Ok(Vec::new()),
        };
        
        // Use Dijkstra to find shortest path
        let predecessors = dijkstra(
            &*graph,
            from_idx,
            Some(to_idx),
            |edge| 1.0 / edge.weight().weight,
        );
        
        // Reconstruct path
        let mut path = Vec::new();
        let mut current = to_idx;
        
        while current != from_idx {
            if let Some(id) = self.reverse_index.get(&current) {
                path.push(id.clone());
            }
            
            // Find predecessor
            let mut found = false;
            for edge in graph.edges_directed(current, petgraph::Direction::Incoming) {
                let source = edge.source();
                if predecessors.contains_key(&source) {
                    current = source;
                    found = true;
                    break;
                }
            }
            
            if !found {
                break;
            }
        }
        
        path.push(from_pattern.to_string());
        path.reverse();
        
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthex_bashgod::memory::PatternContext;
    
    #[tokio::test]
    async fn test_graph_memory_pattern_addition() {
        let memory = GraphMemory::new(GraphMemoryConfig::default());
        
        let pattern = CommandPattern {
            id: "test-pattern".to_string(),
            commands: vec![
                "ls -la".to_string(),
                "grep test".to_string(),
                "wc -l".to_string(),
            ],
            features: vec![],
            dependencies: vec![(0, 1), (1, 2)],
            context: PatternContext {
                environment: "test".to_string(),
                user: "test".to_string(),
                tags: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: crate::synthex_bashgod::memory::PatternMetrics {
                avg_execution_time_ms: 100.0,
                success_rate: 1.0,
                execution_count: 1,
                avg_cpu_usage: 0.1,
                avg_memory_mb: 10,
            },
        };
        
        memory.add_pattern(&pattern).await.unwrap();
        
        let (patterns, nodes, edges) = memory.get_stats().await;
        assert_eq!(patterns, 1);
        assert_eq!(nodes, 4); // 1 pattern + 3 commands
        assert!(edges >= 5); // Pattern->commands + sequence + dependencies
    }
    
    #[tokio::test]
    async fn test_find_related_patterns() {
        let memory = GraphMemory::new(GraphMemoryConfig::default());
        
        // Add first pattern
        let pattern1 = CommandPattern {
            id: "pattern1".to_string(),
            commands: vec!["echo start".to_string()],
            features: vec![],
            dependencies: vec![],
            context: PatternContext {
                environment: "test".to_string(),
                user: "test".to_string(),
                tags: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: Default::default(),
        };
        
        memory.add_pattern(&pattern1).await.unwrap();
        
        // Add second pattern with connection
        let pattern2 = CommandPattern {
            id: "pattern2".to_string(),
            commands: vec!["echo end".to_string()],
            features: vec![],
            dependencies: vec![],
            context: PatternContext {
                environment: "test".to_string(),
                user: "test".to_string(),
                tags: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: Default::default(),
        };
        
        memory.add_pattern(&pattern2).await.unwrap();
        
        // Manually add connection between patterns
        let mut graph = memory.graph.write().await;
        if let (Some(&idx1), Some(&idx2)) = 
            (memory.node_index.get("pattern1"), memory.node_index.get("pattern2")) {
            graph.add_edge(
                idx1,
                idx2,
                GraphEdge {
                    edge_type: EdgeType::Sequence,
                    weight: 1.0,
                    metadata: EdgeMetadata {
                        traversal_count: 1,
                        avg_traversal_time_ms: 0.0,
                        success_rate: 1.0,
                    },
                },
            );
        }
        drop(graph);
        
        // Find related patterns
        let related = memory.find_related("pattern1", 2).await.unwrap();
        
        assert!(related.iter().any(|(id, _)| id == "pattern2"));
    }
    
    #[tokio::test]
    async fn test_community_detection() {
        let memory = GraphMemory::new(GraphMemoryConfig::default());
        
        // Add interconnected patterns
        for i in 0..3 {
            let pattern = CommandPattern {
                id: format!("pattern{}", i),
                commands: vec![format!("echo {}", i)],
                features: vec![],
                dependencies: vec![],
                context: PatternContext {
                    environment: "test".to_string(),
                    user: "test".to_string(),
                    tags: vec![],
                    created_at: chrono::Utc::now(),
                    last_accessed: chrono::Utc::now(),
                },
                metrics: Default::default(),
            };
            
            memory.add_pattern(&pattern).await.unwrap();
        }
        
        // Add connections to form a cycle
        let mut graph = memory.graph.write().await;
        let idx0 = memory.node_index.get("pattern0").unwrap();
        let idx1 = memory.node_index.get("pattern1").unwrap();
        let idx2 = memory.node_index.get("pattern2").unwrap();
        
        for (from, to) in &[(*idx0, *idx1), (*idx1, *idx2), (*idx2, *idx0)] {
            graph.add_edge(
                *from,
                *to,
                GraphEdge {
                    edge_type: EdgeType::Sequence,
                    weight: 1.0,
                    metadata: EdgeMetadata {
                        traversal_count: 1,
                        avg_traversal_time_ms: 0.0,
                        success_rate: 1.0,
                    },
                },
            );
        }
        drop(graph);
        
        // Detect communities
        let communities = memory.detect_communities().await.unwrap();
        
        // Should detect at least one community
        assert!(!communities.is_empty());
    }
}