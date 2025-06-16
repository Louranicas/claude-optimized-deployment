/*!
 * Resource Registry and Management for Rust MCP Server
 */

use std::collections::HashMap;

/// Resource definition
#[derive(Debug, Clone)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// Resource registry for managing available resources
#[derive(Debug)]
pub struct ResourceRegistry {
    resources: HashMap<String, Resource>,
}

impl ResourceRegistry {
    /// Create a new resource registry
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
        }
    }
    
    /// Register a new resource
    pub fn register(&mut self, resource: Resource) {
        self.resources.insert(resource.uri.clone(), resource);
    }
    
    /// Get a resource by URI
    pub fn get(&self, uri: &str) -> Option<&Resource> {
        self.resources.get(uri)
    }
    
    /// List all resources
    pub fn list(&self) -> Vec<&Resource> {
        self.resources.values().collect()
    }
    
    /// Check if a resource exists
    pub fn exists(&self, uri: &str) -> bool {
        self.resources.contains_key(uri)
    }
    
    /// Get the number of registered resources
    pub fn count(&self) -> usize {
        self.resources.len()
    }
    
    /// Remove a resource
    pub fn unregister(&mut self, uri: &str) -> Option<Resource> {
        self.resources.remove(uri)
    }
    
    /// Clear all resources
    pub fn clear(&mut self) {
        self.resources.clear();
    }
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}