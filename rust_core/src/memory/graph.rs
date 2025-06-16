// ============================================================================
// Graph-based Dependency Tracking Memory
// ============================================================================
// Models command dependencies as directed graphs with support for
// efficient traversal, cycle detection, and resource conflict analysis.
// ============================================================================

use super::*;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::{toposort, is_cyclic_directed, dijkstra};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet, VecDeque};
use parking_lot::RwLock;
use chrono::{DateTime, Utc, Duration};

/// Node in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub command_id: String,
    pub command: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u64,
    pub resources: HashSet<String>,
}

/// Edge in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub dependency_type: DependencyType,
    pub strength: f32,
    pub created_at: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub observation_count: u64,
}

/// Graph memory for dependency tracking
pub struct GraphMemory {
    /// The dependency graph
    graph: Arc<RwLock<DiGraph<GraphNode, GraphEdge>>>,
    
    /// Command ID to node index mapping
    id_to_node: Arc<RwLock<HashMap<String, NodeIndex>>>,
    
    /// Resource to node mapping for conflict detection
    resource_to_nodes: Arc<RwLock<HashMap<String, HashSet<NodeIndex>>>>,
    
    /// Memory usage tracking
    memory_used: Arc<RwLock<usize>>,
    
    /// Pruning configuration
    pruning_threshold: Duration,
}

impl GraphMemory {
    /// Create a new graph memory instance
    pub fn new(pruning_threshold_secs: u64) -> Self {
        Self {
            graph: Arc::new(RwLock::new(DiGraph::new())),
            id_to_node: Arc::new(RwLock::new(HashMap::new())),
            resource_to_nodes: Arc::new(RwLock::new(HashMap::new())),
            memory_used: Arc::new(RwLock::new(0)),
            pruning_threshold: Duration::seconds(pruning_threshold_secs as i64),
        }
    }
    
    /// Add a command node to the graph
    pub fn add_node(&self, command: CommandPattern, resources: HashSet<String>) -> MemoryResult<NodeIndex> {
        let mut graph = self.graph.write();
        let mut id_to_node = self.id_to_node.write();
        let mut resource_to_nodes = self.resource_to_nodes.write();
        
        // Check if node already exists
        if let Some(&node_idx) = id_to_node.get(&command.id) {
            // Update access time
            if let Some(node) = graph.node_weight_mut(node_idx) {
                node.last_accessed = Utc::now();
                node.access_count += 1;
            }
            return Ok(node_idx);
        }
        
        // Create new node
        let node = GraphNode {
            command_id: command.id.clone(),
            command: command.command.clone(),
            created_at: command.timestamp,
            last_accessed: Utc::now(),
            access_count: 1,
            resources: resources.clone(),
        };
        
        // Update memory usage
        let node_size = std::mem::size_of::<GraphNode>() +
            node.command_id.len() +
            node.command.len() +
            resources.iter().map(|r| r.len()).sum::<usize>();
        *self.memory_used.write() += node_size;
        
        // Add to graph
        let node_idx = graph.add_node(node);
        id_to_node.insert(command.id, node_idx);
        
        // Update resource mappings
        for resource in resources {
            resource_to_nodes
                .entry(resource)
                .or_insert_with(HashSet::new)
                .insert(node_idx);
        }
        
        Ok(node_idx)
    }
    
    /// Add a dependency edge between commands
    pub fn add_dependency(
        &self,
        from_id: &str,
        to_id: &str,
        dependency_type: DependencyType,
        strength: f32,
    ) -> MemoryResult<()> {
        let mut graph = self.graph.write();
        let id_to_node = self.id_to_node.read();
        
        let from_idx = id_to_node.get(from_id)
            .ok_or_else(|| MemoryError::PatternNotFound(from_id.to_string()))?;
        let to_idx = id_to_node.get(to_id)
            .ok_or_else(|| MemoryError::PatternNotFound(to_id.to_string()))?;
        
        // Check if edge already exists
        if let Some(edge_idx) = graph.find_edge(*from_idx, *to_idx) {
            // Update existing edge
            if let Some(edge) = graph.edge_weight_mut(edge_idx) {
                edge.last_observed = Utc::now();
                edge.observation_count += 1;
                edge.strength = edge.strength.max(strength);
            }
        } else {
            // Create new edge
            let edge = GraphEdge {
                dependency_type,
                strength,
                created_at: Utc::now(),
                last_observed: Utc::now(),
                observation_count: 1,
            };
            
            // Update memory usage
            let edge_size = std::mem::size_of::<GraphEdge>();
            *self.memory_used.write() += edge_size;
            
            graph.add_edge(*from_idx, *to_idx, edge);
        }
        
        Ok(())
    }
    
    /// Find commands that depend on a given command
    pub fn find_dependents(&self, command_id: &str) -> MemoryResult<Vec<(String, Dependency)>> {
        let graph = self.graph.read();
        let id_to_node = self.id_to_node.read();
        
        let node_idx = id_to_node.get(command_id)
            .ok_or_else(|| MemoryError::PatternNotFound(command_id.to_string()))?;
        
        let mut dependents = Vec::new();
        
        for edge in graph.edges(*node_idx) {
            if let (Some(from_node), Some(to_node), Some(edge_data)) = (
                graph.node_weight(edge.source()),
                graph.node_weight(edge.target()),
                graph.edge_weight(edge.id())
            ) {
                dependents.push((
                    to_node.command_id.clone(),
                    Dependency {
                        from_command: from_node.command_id.clone(),
                        to_command: to_node.command_id.clone(),
                        dependency_type: edge_data.dependency_type.clone(),
                        strength: edge_data.strength,
                    }
                ));
            }
        }
        
        Ok(dependents)
    }
    
    /// Find commands that a given command depends on
    pub fn find_dependencies(&self, command_id: &str) -> MemoryResult<Vec<(String, Dependency)>> {
        let graph = self.graph.read();
        let id_to_node = self.id_to_node.read();
        
        let node_idx = id_to_node.get(command_id)
            .ok_or_else(|| MemoryError::PatternNotFound(command_id.to_string()))?;
        
        let mut dependencies = Vec::new();
        
        // Find incoming edges
        for edge in graph.edges_directed(*node_idx, petgraph::Direction::Incoming) {
            if let (Some(from_node), Some(to_node), Some(edge_data)) = (
                graph.node_weight(edge.source()),
                graph.node_weight(edge.target()),
                graph.edge_weight(edge.id())
            ) {
                dependencies.push((
                    from_node.command_id.clone(),
                    Dependency {
                        from_command: from_node.command_id.clone(),
                        to_command: to_node.command_id.clone(),
                        dependency_type: edge_data.dependency_type.clone(),
                        strength: edge_data.strength,
                    }
                ));
            }
        }
        
        Ok(dependencies)
    }
    
    /// Find the optimal execution order for a set of commands
    pub fn find_execution_order(&self, command_ids: &[String]) -> MemoryResult<Vec<String>> {
        let graph = self.graph.read();
        let id_to_node = self.id_to_node.read();
        
        // Create subgraph with only specified nodes
        let mut subgraph = DiGraph::new();
        let mut old_to_new = HashMap::new();
        let mut new_to_old = HashMap::new();
        
        // Add nodes to subgraph
        for command_id in command_ids {
            if let Some(&old_idx) = id_to_node.get(command_id) {
                if let Some(node) = graph.node_weight(old_idx) {
                    let new_idx = subgraph.add_node(node.clone());
                    old_to_new.insert(old_idx, new_idx);
                    new_to_old.insert(new_idx, old_idx);
                }
            }
        }
        
        // Add edges to subgraph
        for (&old_idx, &new_idx) in &old_to_new {
            for edge in graph.edges(old_idx) {
                if let Some(&new_target) = old_to_new.get(&edge.target()) {
                    if let Some(edge_data) = graph.edge_weight(edge.id()) {
                        subgraph.add_edge(new_idx, new_target, edge_data.clone());
                    }
                }
            }
        }
        
        // Check for cycles
        if is_cyclic_directed(&subgraph) {
            return Err(MemoryError::GraphError("Cyclic dependency detected".to_string()));
        }
        
        // Perform topological sort
        match toposort(&subgraph, None) {
            Ok(sorted) => {
                Ok(sorted.into_iter()
                    .filter_map(|new_idx| {
                        new_to_old.get(&new_idx)
                            .and_then(|&old_idx| graph.node_weight(old_idx))
                            .map(|node| node.command_id.clone())
                    })
                    .collect())
            }
            Err(_) => Err(MemoryError::GraphError("Failed to sort dependencies".to_string())),
        }
    }
    
    /// Detect resource conflicts between commands
    pub fn detect_conflicts(&self, command_ids: &[String]) -> MemoryResult<Vec<(String, String, Vec<String>)>> {
        let graph = self.graph.read();
        let id_to_node = self.id_to_node.read();
        
        let mut conflicts = Vec::new();
        
        for i in 0..command_ids.len() {
            for j in (i + 1)..command_ids.len() {
                let cmd1 = &command_ids[i];
                let cmd2 = &command_ids[j];
                
                if let (Some(&idx1), Some(&idx2)) = (id_to_node.get(cmd1), id_to_node.get(cmd2)) {
                    if let (Some(node1), Some(node2)) = (graph.node_weight(idx1), graph.node_weight(idx2)) {
                        let shared_resources: Vec<String> = node1.resources
                            .intersection(&node2.resources)
                            .cloned()
                            .collect();
                        
                        if !shared_resources.is_empty() {
                            conflicts.push((cmd1.clone(), cmd2.clone(), shared_resources));
                        }
                    }
                }
            }
        }
        
        Ok(conflicts)
    }
    
    /// Prune old nodes and edges based on access time
    pub fn prune_old_entries(&self) -> MemoryResult<u64> {
        let mut graph = self.graph.write();
        let mut id_to_node = self.id_to_node.write();
        let mut resource_to_nodes = self.resource_to_nodes.write();
        
        let cutoff_time = Utc::now() - self.pruning_threshold;
        let mut nodes_to_remove = Vec::new();
        let mut pruned_count = 0u64;
        
        // Find nodes to remove
        for node_idx in graph.node_indices() {
            if let Some(node) = graph.node_weight(node_idx) {
                if node.last_accessed < cutoff_time && node.access_count < 10 {
                    nodes_to_remove.push((node_idx, node.command_id.clone()));
                }
            }
        }
        
        // Remove nodes and their edges
        for (node_idx, command_id) in nodes_to_remove {
            if let Some(node) = graph.node_weight(node_idx) {
                // Update resource mappings
                for resource in &node.resources {
                    if let Some(nodes) = resource_to_nodes.get_mut(resource) {
                        nodes.remove(&node_idx);
                        if nodes.is_empty() {
                            resource_to_nodes.remove(resource);
                        }
                    }
                }
                
                // Update memory usage
                let node_size = std::mem::size_of::<GraphNode>() +
                    node.command_id.len() +
                    node.command.len() +
                    node.resources.iter().map(|r| r.len()).sum::<usize>();
                *self.memory_used.write() -= node_size;
            }
            
            graph.remove_node(node_idx);
            id_to_node.remove(&command_id);
            pruned_count += 1;
        }
        
        Ok(pruned_count)
    }
    
    /// Get graph statistics
    pub fn get_stats(&self) -> (usize, usize, usize) {
        let graph = self.graph.read();
        let node_count = graph.node_count();
        let edge_count = graph.edge_count();
        let memory_used = *self.memory_used.read();
        (node_count, edge_count, memory_used)
    }
    
    /// Clear the entire graph
    pub fn clear(&self) {
        self.graph.write().clear();
        self.id_to_node.write().clear();
        self.resource_to_nodes.write().clear();
        *self.memory_used.write() = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    
    fn create_test_pattern(id: &str, command: &str) -> CommandPattern {
        CommandPattern {
            id: id.to_string(),
            command: command.to_string(),
            arguments: vec![],
            environment: HashMap::new(),
            timestamp: Utc::now(),
            execution_time_ms: 100,
            exit_code: 0,
            resource_usage: ResourceUsage {
                cpu_percent: 10.0,
                memory_bytes: 1024,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                network_recv_bytes: 0,
                network_sent_bytes: 0,
            },
        }
    }
    
    #[test]
    fn test_node_addition() {
        let graph = GraphMemory::new(86400);
        let pattern = create_test_pattern("test-1", "docker");
        let resources = HashSet::from(["docker.sock".to_string()]);
        
        let node_idx = graph.add_node(pattern, resources).unwrap();
        assert!(node_idx.index() >= 0);
        
        let (nodes, edges, _) = graph.get_stats();
        assert_eq!(nodes, 1);
        assert_eq!(edges, 0);
    }
    
    #[test]
    fn test_dependency_tracking() {
        let graph = GraphMemory::new(86400);
        
        // Add nodes
        let pattern1 = create_test_pattern("build", "docker build");
        let pattern2 = create_test_pattern("push", "docker push");
        
        graph.add_node(pattern1, HashSet::new()).unwrap();
        graph.add_node(pattern2, HashSet::new()).unwrap();
        
        // Add dependency
        graph.add_dependency("build", "push", DependencyType::Sequential, 0.9).unwrap();
        
        // Check dependencies
        let deps = graph.find_dependencies("push").unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "build");
        
        let dependents = graph.find_dependents("build").unwrap();
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].0, "push");
    }
    
    #[test]
    fn test_execution_order() {
        let graph = GraphMemory::new(86400);
        
        // Create a dependency chain: build -> test -> deploy
        let commands = vec!["build", "test", "deploy"];
        for cmd in &commands {
            let pattern = create_test_pattern(cmd, cmd);
            graph.add_node(pattern, HashSet::new()).unwrap();
        }
        
        graph.add_dependency("build", "test", DependencyType::Sequential, 1.0).unwrap();
        graph.add_dependency("test", "deploy", DependencyType::Sequential, 1.0).unwrap();
        
        let order = graph.find_execution_order(&commands.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(order, vec!["build", "test", "deploy"]);
    }
    
    #[test]
    fn test_resource_conflict_detection() {
        let graph = GraphMemory::new(86400);
        
        // Add nodes with shared resources
        let pattern1 = create_test_pattern("app1", "docker run app1");
        let pattern2 = create_test_pattern("app2", "docker run app2");
        
        let resources1 = HashSet::from(["port:8080".to_string(), "db:postgres".to_string()]);
        let resources2 = HashSet::from(["port:8080".to_string(), "cache:redis".to_string()]);
        
        graph.add_node(pattern1, resources1).unwrap();
        graph.add_node(pattern2, resources2).unwrap();
        
        let conflicts = graph.detect_conflicts(&vec!["app1".to_string(), "app2".to_string()]).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].2, vec!["port:8080"]);
    }
}