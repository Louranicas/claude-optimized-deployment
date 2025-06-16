// ============================================================================
// Memory Index - Fast Lookup Support
// ============================================================================
// Provides O(log n) lookup performance using multiple index structures
// including B-trees, hash maps, and inverted indices.
// ============================================================================

use super::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use parking_lot::RwLock;
use petgraph::graph::NodeIndex;
use chrono::{DateTime, Utc};

/// Index entry metadata
#[derive(Debug, Clone)]
struct IndexEntry {
    node_index: NodeIndex,
    timestamp: DateTime<Utc>,
    access_count: u64,
    last_accessed: DateTime<Utc>,
}

/// Memory index for fast lookups
pub struct MemoryIndex {
    /// Primary key index (command_id -> metadata)
    primary_index: Arc<RwLock<HashMap<String, IndexEntry>>>,
    
    /// Command type index (command -> set of command_ids)
    command_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    
    /// Time-based index (timestamp -> command_ids)
    time_index: Arc<RwLock<BTreeMap<DateTime<Utc>, Vec<String>>>>,
    
    /// Resource index (resource -> command_ids)
    resource_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    
    /// Prefix index for autocomplete (prefix -> command_ids)
    prefix_index: Arc<RwLock<BTreeMap<String, HashSet<String>>>>,
    
    /// Index statistics
    stats: Arc<RwLock<IndexStats>>,
}

#[derive(Debug, Default)]
struct IndexStats {
    total_entries: usize,
    index_hits: u64,
    index_misses: u64,
    rebuild_count: u64,
}

impl MemoryIndex {
    /// Create a new memory index
    pub fn new() -> Self {
        Self {
            primary_index: Arc::new(RwLock::new(HashMap::new())),
            command_index: Arc::new(RwLock::new(HashMap::new())),
            time_index: Arc::new(RwLock::new(BTreeMap::new())),
            resource_index: Arc::new(RwLock::new(HashMap::new())),
            prefix_index: Arc::new(RwLock::new(BTreeMap::new())),
            stats: Arc::new(RwLock::new(IndexStats::default())),
        }
    }
    
    /// Add an entry to the index
    pub fn add_entry(&self, command_id: &str, node_index: NodeIndex) -> MemoryResult<()> {
        let entry = IndexEntry {
            node_index,
            timestamp: Utc::now(),
            access_count: 0,
            last_accessed: Utc::now(),
        };
        
        // Update primary index
        {
            let mut primary = self.primary_index.write();
            primary.insert(command_id.to_string(), entry.clone());
        }
        
        // Update command index
        if let Some(command) = self.extract_command(command_id) {
            let mut cmd_index = self.command_index.write();
            cmd_index
                .entry(command)
                .or_insert_with(HashSet::new)
                .insert(command_id.to_string());
        }
        
        // Update time index
        {
            let mut time_idx = self.time_index.write();
            time_idx
                .entry(entry.timestamp)
                .or_insert_with(Vec::new)
                .push(command_id.to_string());
        }
        
        // Update prefix indices
        self.update_prefix_index(command_id)?;
        
        // Update stats
        self.stats.write().total_entries += 1;
        
        Ok(())
    }
    
    /// Lookup by primary key
    pub fn lookup(&self, command_id: &str) -> Option<NodeIndex> {
        let mut primary = self.primary_index.write();
        
        if let Some(entry) = primary.get_mut(command_id) {
            entry.access_count += 1;
            entry.last_accessed = Utc::now();
            self.stats.write().index_hits += 1;
            Some(entry.node_index)
        } else {
            self.stats.write().index_misses += 1;
            None
        }
    }
    
    /// Find commands by type
    pub fn find_by_command(&self, command: &str) -> Vec<String> {
        let cmd_index = self.command_index.read();
        
        if let Some(command_ids) = cmd_index.get(command) {
            self.stats.write().index_hits += 1;
            command_ids.iter().cloned().collect()
        } else {
            self.stats.write().index_misses += 1;
            Vec::new()
        }
    }
    
    /// Find commands by time range
    pub fn find_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<String> {
        let time_idx = self.time_index.read();
        let mut results = Vec::new();
        
        for (timestamp, command_ids) in time_idx.range(start..=end) {
            results.extend(command_ids.iter().cloned());
        }
        
        if !results.is_empty() {
            self.stats.write().index_hits += 1;
        } else {
            self.stats.write().index_misses += 1;
        }
        
        results
    }
    
    /// Find commands by resource
    pub fn find_by_resource(&self, resource: &str) -> Vec<String> {
        let resource_idx = self.resource_index.read();
        
        if let Some(command_ids) = resource_idx.get(resource) {
            self.stats.write().index_hits += 1;
            command_ids.iter().cloned().collect()
        } else {
            self.stats.write().index_misses += 1;
            Vec::new()
        }
    }
    
    /// Find commands by prefix (for autocomplete)
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<String> {
        let prefix_idx = self.prefix_index.read();
        let mut results = HashSet::new();
        
        for (key, command_ids) in prefix_idx.range(prefix.to_string()..) {
            if !key.starts_with(prefix) {
                break;
            }
            results.extend(command_ids.iter().cloned());
        }
        
        if !results.is_empty() {
            self.stats.write().index_hits += 1;
        } else {
            self.stats.write().index_misses += 1;
        }
        
        results.into_iter().collect()
    }
    
    /// Update resource associations
    pub fn update_resources(&self, command_id: &str, resources: &HashSet<String>) -> MemoryResult<()> {
        let mut resource_idx = self.resource_index.write();
        
        for resource in resources {
            resource_idx
                .entry(resource.clone())
                .or_insert_with(HashSet::new)
                .insert(command_id.to_string());
        }
        
        Ok(())
    }
    
    /// Remove an entry from all indices
    pub fn remove_entry(&self, command_id: &str) -> MemoryResult<()> {
        // Remove from primary index
        let entry = {
            let mut primary = self.primary_index.write();
            primary.remove(command_id)
        };
        
        if let Some(entry) = entry {
            // Remove from command index
            if let Some(command) = self.extract_command(command_id) {
                let mut cmd_index = self.command_index.write();
                if let Some(commands) = cmd_index.get_mut(&command) {
                    commands.remove(command_id);
                    if commands.is_empty() {
                        cmd_index.remove(&command);
                    }
                }
            }
            
            // Remove from time index
            {
                let mut time_idx = self.time_index.write();
                if let Some(commands) = time_idx.get_mut(&entry.timestamp) {
                    commands.retain(|id| id != command_id);
                    if commands.is_empty() {
                        time_idx.remove(&entry.timestamp);
                    }
                }
            }
            
            // Remove from prefix index
            self.remove_from_prefix_index(command_id)?;
            
            // Update stats
            self.stats.write().total_entries -= 1;
        }
        
        Ok(())
    }
    
    /// Extract command from command_id
    fn extract_command(&self, command_id: &str) -> Option<String> {
        // Simple extraction - assumes command is first part before dash or underscore
        command_id
            .split(|c| c == '-' || c == '_')
            .next()
            .map(|s| s.to_string())
    }
    
    /// Update prefix index
    fn update_prefix_index(&self, command_id: &str) -> MemoryResult<()> {
        let mut prefix_idx = self.prefix_index.write();
        
        // Generate prefixes of various lengths
        for len in 1..=command_id.len().min(10) {
            let prefix = &command_id[..len];
            prefix_idx
                .entry(prefix.to_string())
                .or_insert_with(HashSet::new)
                .insert(command_id.to_string());
        }
        
        Ok(())
    }
    
    /// Remove from prefix index
    fn remove_from_prefix_index(&self, command_id: &str) -> MemoryResult<()> {
        let mut prefix_idx = self.prefix_index.write();
        
        // Remove from all prefix entries
        let prefixes_to_remove: Vec<String> = prefix_idx
            .iter()
            .filter_map(|(prefix, commands)| {
                if commands.contains(command_id) {
                    Some(prefix.clone())
                } else {
                    None
                }
            })
            .collect();
        
        for prefix in prefixes_to_remove {
            if let Some(commands) = prefix_idx.get_mut(&prefix) {
                commands.remove(command_id);
                if commands.is_empty() {
                    prefix_idx.remove(&prefix);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get index statistics
    pub fn get_stats(&self) -> (usize, u64, u64) {
        let stats = self.stats.read();
        (stats.total_entries, stats.index_hits, stats.index_misses)
    }
    
    /// Clear all indices
    pub fn clear(&self) {
        self.primary_index.write().clear();
        self.command_index.write().clear();
        self.time_index.write().clear();
        self.resource_index.write().clear();
        self.prefix_index.write().clear();
        *self.stats.write() = IndexStats::default();
    }
    
    /// Rebuild indices for optimization
    pub fn rebuild(&self) -> MemoryResult<()> {
        // This would be called periodically to optimize index structures
        // For now, just update stats
        self.stats.write().rebuild_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::NodeIndex;
    
    #[test]
    fn test_basic_index_operations() {
        let index = MemoryIndex::new();
        let node_idx = NodeIndex::new(0);
        
        // Add entry
        index.add_entry("docker-build-123", node_idx).unwrap();
        
        // Lookup
        assert_eq!(index.lookup("docker-build-123"), Some(node_idx));
        assert_eq!(index.lookup("nonexistent"), None);
        
        // Find by command
        let results = index.find_by_command("docker");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "docker-build-123");
    }
    
    #[test]
    fn test_prefix_search() {
        let index = MemoryIndex::new();
        
        // Add multiple entries
        index.add_entry("docker-build", NodeIndex::new(0)).unwrap();
        index.add_entry("docker-run", NodeIndex::new(1)).unwrap();
        index.add_entry("kubectl-apply", NodeIndex::new(2)).unwrap();
        
        // Search by prefix
        let docker_results = index.find_by_prefix("docker");
        assert_eq!(docker_results.len(), 2);
        
        let d_results = index.find_by_prefix("d");
        assert_eq!(d_results.len(), 2);
        
        let k_results = index.find_by_prefix("k");
        assert_eq!(k_results.len(), 1);
    }
    
    #[test]
    fn test_resource_index() {
        let index = MemoryIndex::new();
        
        // Add entries with resources
        index.add_entry("app1", NodeIndex::new(0)).unwrap();
        index.update_resources("app1", &HashSet::from(["port:8080".to_string()])).unwrap();
        
        index.add_entry("app2", NodeIndex::new(1)).unwrap();
        index.update_resources("app2", &HashSet::from(["port:8080".to_string(), "db:postgres".to_string()])).unwrap();
        
        // Find by resource
        let port_results = index.find_by_resource("port:8080");
        assert_eq!(port_results.len(), 2);
        
        let db_results = index.find_by_resource("db:postgres");
        assert_eq!(db_results.len(), 1);
        assert_eq!(db_results[0], "app2");
    }
    
    #[test]
    fn test_time_range_search() {
        let index = MemoryIndex::new();
        let now = Utc::now();
        
        // Add entries
        index.add_entry("cmd1", NodeIndex::new(0)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        index.add_entry("cmd2", NodeIndex::new(1)).unwrap();
        
        // Search by time range
        let results = index.find_by_time_range(now - chrono::Duration::seconds(1), now + chrono::Duration::seconds(1));
        assert_eq!(results.len(), 2);
    }
}