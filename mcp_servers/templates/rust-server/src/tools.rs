/*!
 * Tool Registry and Management for Rust MCP Server
 */

use serde_json::Value;
use std::collections::HashMap;

/// Tool definition
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Tool registry for managing available tools
#[derive(Debug)]
pub struct ToolRegistry {
    tools: HashMap<String, Tool>,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }
    
    /// Register a new tool
    pub fn register(&mut self, tool: Tool) {
        self.tools.insert(tool.name.clone(), tool);
    }
    
    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<&Tool> {
        self.tools.get(name)
    }
    
    /// List all tools
    pub fn list(&self) -> Vec<&Tool> {
        self.tools.values().collect()
    }
    
    /// Check if a tool exists
    pub fn exists(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }
    
    /// Get the number of registered tools
    pub fn count(&self) -> usize {
        self.tools.len()
    }
    
    /// Remove a tool
    pub fn unregister(&mut self, name: &str) -> Option<Tool> {
        self.tools.remove(name)
    }
    
    /// Clear all tools
    pub fn clear(&mut self) {
        self.tools.clear();
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}