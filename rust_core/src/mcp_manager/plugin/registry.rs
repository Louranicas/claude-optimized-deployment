//! Plugin Registry - The Heart of Dynamic Extensibility
//!
//! This registry is not just a container. It's a living, breathing
//! system that manages the lifecycle of every plugin with surgical precision.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::toposort;
use tracing::{ info};

use super::{
    Capability, Plugin, PluginError, PluginHandle, PluginMetadata, 
    PluginState, Result, traits::*
};

/// The Plugin Registry - where all plugins live
pub struct PluginRegistry {
    /// All registered plugins by ID
    plugins: DashMap<String, Arc<PluginHandle>>,
    
    /// Capability index for fast lookup
    capability_index: Arc<RwLock<CapabilityIndex>>,
    
    /// Dependency graph
    dependency_graph: Arc<RwLock<DependencyGraph>>,
    
    /// Plugin state tracking
    state_tracker: Arc<RwLock<StateTracker>>,
    
    /// Registry configuration
    config: RegistryConfig,
}

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Maximum number of plugins
    pub max_plugins: usize,
    
    /// Enable hot reload
    pub enable_hot_reload: bool,
    
    /// Enable dependency resolution
    pub enable_dependencies: bool,
    
    /// Plugin timeout in seconds
    pub plugin_timeout: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_plugins: 1000,
            enable_hot_reload: true,
            enable_dependencies: true,
            plugin_timeout: 30,
        }
    }
}

/// Capability index for fast lookup
struct CapabilityIndex {
    /// Map from capability to plugin IDs that provide it
    providers: HashMap<Capability, HashSet<String>>,
    
    /// Map from namespace to capabilities
    namespaces: HashMap<String, HashSet<Capability>>,
}

/// Dependency graph for plugins
struct DependencyGraph {
    /// The actual graph
    graph: DiGraph<String, DependencyEdge>,
    
    /// Node index mapping
    nodes: HashMap<String, NodeIndex>,
}

/// Edge in dependency graph
#[derive(Debug, Clone)]
struct DependencyEdge {
    /// Is this a required dependency?
    required: bool,
    
    /// Version constraint
    version: String,
}

/// State tracker for all plugins
struct StateTracker {
    /// Plugin states
    states: HashMap<String, PluginState>,
    
    /// State change history
    history: Vec<StateChange>,
    
    /// Maximum history size
    max_history: usize,
}

/// State change record
#[derive(Debug, Clone)]
struct StateChange {
    /// Plugin ID
    plugin_id: String,
    
    /// Previous state
    from: PluginState,
    
    /// New state
    to: PluginState,
    
    /// Timestamp
    timestamp: std::time::SystemTime,
}

impl PluginRegistry {
    /// Create a new registry
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            plugins: DashMap::new(),
            capability_index: Arc::new(RwLock::new(CapabilityIndex {
                providers: HashMap::new(),
                namespaces: HashMap::new(),
            })),
            dependency_graph: Arc::new(RwLock::new(DependencyGraph {
                graph: DiGraph::new(),
                nodes: HashMap::new(),
            })),
            state_tracker: Arc::new(RwLock::new(StateTracker {
                states: HashMap::new(),
                history: Vec::new(),
                max_history: 1000,
            })),
            config,
        }
    }
    
    /// Register a plugin
    pub async fn register(&self, plugin: Box<dyn Plugin>) -> Result<String> {
        // Check capacity
        if self.plugins.len() >= self.config.max_plugins {
            return Err(PluginError::InvalidManifest(
                format!("Registry full: maximum {} plugins", self.config.max_plugins)
            ));
        }
        
        let metadata = plugin.metadata().clone();
        let plugin_id = metadata.id.clone();
        
        // Check if already registered
        if self.plugins.contains_key(&plugin_id) {
            return Err(PluginError::AlreadyLoaded(plugin_id));
        }
        
        info!("Registering plugin: {}", plugin_id);
        
        // Create plugin handle
        let handle = Arc::new(PluginHandle::new(plugin));
        
        // Add to dependency graph if enabled
        if self.config.enable_dependencies {
            self.add_to_dependency_graph(&metadata).await?;
        }
        
        // Index capabilities
        self.index_capabilities(&plugin_id, &metadata.provides).await?;
        
        // Track initial state
        self.track_state_change(&plugin_id, PluginState::Loaded).await;
        
        // Store plugin
        self.plugins.insert(plugin_id.clone(), handle);
        
        info!("Plugin registered successfully: {}", plugin_id);
        Ok(plugin_id)
    }
    
    /// Unregister a plugin
    pub async fn unregister(&self, plugin_id: &str) -> Result<()> {
        // Get plugin
        let handle = self.plugins.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;
        
        // Check state
        let state = handle.state().await;
        if state != PluginState::Shutdown && state != PluginState::Error {
            // Shutdown first
            handle.shutdown().await?;
        }
        
        // Remove from indices
        let metadata = handle.metadata().await;
        self.unindex_capabilities(&plugin_id, &metadata.provides).await?;
        
        // Remove from dependency graph
        if self.config.enable_dependencies {
            self.remove_from_dependency_graph(&plugin_id).await?;
        }
        
        // Remove plugin
        self.plugins.remove(plugin_id);
        
        info!("Plugin unregistered: {}", plugin_id);
        Ok(())
    }
    
    /// Get a plugin by ID
    pub fn get(&self, plugin_id: &str) -> Option<Arc<PluginHandle>> {
        self.plugins.get(plugin_id).map(|entry| entry.clone())
    }
    
    /// Get all plugins
    pub fn list(&self) -> Vec<(String, Arc<PluginHandle>)> {
        self.plugins
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
    
    /// Find plugins by capability
    pub async fn find_by_capability(&self, capability: &Capability) -> Vec<String> {
        let index = self.capability_index.read().await;
        index.providers
            .get(capability)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }
    
    /// Find plugins by namespace
    pub async fn find_by_namespace(&self, namespace: &str) -> Vec<String> {
        let index = self.capability_index.read().await;
        let mut plugin_ids = HashSet::new();
        
        for (cap, providers) in &index.providers {
            if cap.namespace == namespace {
                plugin_ids.extend(providers.iter().cloned());
            }
        }
        
        plugin_ids.into_iter().collect()
    }
    
    /// Get plugin load order based on dependencies
    pub async fn get_load_order(&self) -> Result<Vec<String>> {
        if !self.config.enable_dependencies {
            // No dependency resolution, return arbitrary order
            return Ok(self.plugins.iter().map(|e| e.key().clone()).collect());
        }
        
        let graph = self.dependency_graph.read().await;
        
        // Topological sort
        match toposort(&graph.graph, None) {
            Ok(sorted) => {
                Ok(sorted.into_iter()
                    .map(|idx| graph.graph[idx].clone())
                    .collect())
            }
            Err(_) => {
                Err(PluginError::DependencyNotSatisfied(
                    "Circular dependency detected".to_string()
                ))
            }
        }
    }
    
    /// Check if dependencies are satisfied
    pub async fn check_dependencies(&self, plugin_id: &str) -> Result<bool> {
        if !self.config.enable_dependencies {
            return Ok(true);
        }
        
        let plugin = self.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;
        
        let metadata = plugin.metadata().await;
        
        for dep in &metadata.dependencies {
            // Check if dependency exists
            if !self.plugins.contains_key(&dep.id) {
                if !dep.optional {
                    return Ok(false);
                }
                continue;
            }
            
            // TODO: Check version compatibility
            // This would require semver parsing
        }
        
        Ok(true)
    }
    
    /// Get plugin states
    pub async fn get_states(&self) -> HashMap<String, PluginState> {
        let tracker = self.state_tracker.read().await;
        tracker.states.clone()
    }
    
    /// Get state history
    pub async fn get_state_history(&self) -> Vec<StateChange> {
        let tracker = self.state_tracker.read().await;
        tracker.history.clone()
    }
    
    // Private helper methods
    
    async fn add_to_dependency_graph(&self, metadata: &PluginMetadata) -> Result<()> {
        let mut graph = self.dependency_graph.write().await;
        
        // Add node for this plugin
        let node = graph.graph.add_node(metadata.id.clone());
        graph.nodes.insert(metadata.id.clone(), node);
        
        // Add edges for dependencies
        for dep in &metadata.dependencies {
            if let Some(&dep_node) = graph.nodes.get(&dep.id) {
                graph.graph.add_edge(
                    dep_node,
                    node,
                    DependencyEdge {
                        required: !dep.optional,
                        version: dep.version.clone(),
                    },
                );
            }
        }
        
        Ok(())
    }
    
    async fn remove_from_dependency_graph(&self, plugin_id: &str) -> Result<()> {
        let mut graph = self.dependency_graph.write().await;
        
        if let Some(&node) = graph.nodes.get(plugin_id) {
            graph.graph.remove_node(node);
            graph.nodes.remove(plugin_id);
        }
        
        Ok(())
    }
    
    async fn index_capabilities(&self, plugin_id: &str, capabilities: &[Capability]) -> Result<()> {
        let mut index = self.capability_index.write().await;
        
        for cap in capabilities {
            // Add to providers index
            index.providers
                .entry(cap.clone())
                .or_insert_with(HashSet::new)
                .insert(plugin_id.to_string());
            
            // Add to namespace index
            index.namespaces
                .entry(cap.namespace.clone())
                .or_insert_with(HashSet::new)
                .insert(cap.clone());
        }
        
        Ok(())
    }
    
    async fn unindex_capabilities(&self, plugin_id: &str, capabilities: &[Capability]) -> Result<()> {
        let mut index = self.capability_index.write().await;
        
        for cap in capabilities {
            // Remove from providers index
            if let Some(providers) = index.providers.get_mut(cap) {
                providers.remove(plugin_id);
                if providers.is_empty() {
                    index.providers.remove(cap);
                }
            }
            
            // Remove from namespace index
            if let Some(caps) = index.namespaces.get_mut(&cap.namespace) {
                caps.remove(cap);
                if caps.is_empty() {
                    index.namespaces.remove(&cap.namespace);
                }
            }
        }
        
        Ok(())
    }
    
    async fn track_state_change(&self, plugin_id: &str, to: PluginState) {
        let mut tracker = self.state_tracker.write().await;
        
        // Get the previous state
        let from = tracker.states.get(plugin_id).copied().unwrap_or(PluginState::Unloaded);
        
        // Update current state
        tracker.states.insert(plugin_id.to_string(), to);
        
        // Add to history
        tracker.history.push(StateChange {
            plugin_id: plugin_id.to_string(),
            from,
            to,
            timestamp: std::time::SystemTime::now(),
        });
        
        // Trim history if needed
        if tracker.history.len() > tracker.max_history {
            let trim = tracker.history.len() - tracker.max_history;
            tracker.history.drain(0..trim);
        }
    }
}

/// Registry builder for convenient construction
pub struct RegistryBuilder {
    config: RegistryConfig,
}

impl RegistryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: RegistryConfig::default(),
        }
    }
    
    /// Set maximum plugins
    pub fn max_plugins(mut self, max: usize) -> Self {
        self.config.max_plugins = max;
        self
    }
    
    /// Enable/disable hot reload
    pub fn hot_reload(mut self, enable: bool) -> Self {
        self.config.enable_hot_reload = enable;
        self
    }
    
    /// Enable/disable dependency resolution
    pub fn dependencies(mut self, enable: bool) -> Self {
        self.config.enable_dependencies = enable;
        self
    }
    
    /// Set plugin timeout
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.config.plugin_timeout = seconds;
        self
    }
    
    /// Build the registry
    pub fn build(self) -> PluginRegistry {
        PluginRegistry::new(self.config)
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::Value;
    use std::any::Any;
    
    struct TestPlugin {
        metadata: PluginMetadata,
    }
    
    #[async_trait]
    impl Plugin for TestPlugin {
        fn metadata(&self) -> &PluginMetadata {
            &self.metadata
        }
        
        async fn initialize(&mut self, _config: Value) -> Result<()> {
            Ok(())
        }
        
        async fn handle(&self, _request: super::PluginRequest) -> Result<super::PluginResponse> {
            unimplemented!()
        }
        
        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
        
        fn as_any(&self) -> &dyn Any {
            self
        }
    }
    
    #[tokio::test]
    async fn test_registry_basic() {
        let registry = RegistryBuilder::new()
            .max_plugins(10)
            .build();
        
        let plugin = TestPlugin {
            metadata: PluginMetadata {
                id: "test".to_string(),
                name: "Test Plugin".to_string(),
                version: "1.0.0".to_string(),
                author: "Test".to_string(),
                description: "Test plugin".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![Capability::new("test", "feature", 1)],
                requires: vec![],
            },
        };
        
        let id = registry.register(Box::new(plugin)).await.unwrap();
        assert_eq!(id, "test");
        
        assert!(registry.get("test").is_some());
        
        let providers = registry.find_by_capability(&Capability::new("test", "feature", 1)).await;
        assert_eq!(providers, vec!["test"]);
    }
}