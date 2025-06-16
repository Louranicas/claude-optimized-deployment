//! SYNTHEX Query Module
//! 
//! Query structures and options for search operations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Search query with all options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The search query string
    pub query: String,
    /// Query options
    pub options: QueryOptions,
    /// Security context
    pub security_context: Option<SecurityContext>,
}

impl SearchQuery {
    /// Create a new search query
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            options: QueryOptions::default(),
            security_context: None,
        }
    }
    
    /// Set query options
    pub fn with_options(mut self, options: QueryOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Set security context
    pub fn with_security(mut self, context: SecurityContext) -> Self {
        self.security_context = Some(context);
        self
    }
}

/// Options for search queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptions {
    /// Maximum number of results to return
    pub max_results: usize,
    /// Query timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable result caching
    pub enable_cache: bool,
    /// Sources to search
    pub sources: Vec<String>,
    /// Additional filters
    pub filters: HashMap<String, String>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            max_results: 100,
            timeout_ms: 5000,
            enable_cache: true,
            sources: vec!["all".to_string()],
            filters: HashMap::new(),
        }
    }
}

impl QueryOptions {
    /// Create options with a specific max results
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
    
    /// Disable caching
    pub fn without_cache(mut self) -> Self {
        self.enable_cache = false;
        self
    }
    
    /// Set specific sources
    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.sources = sources;
        self
    }
    
    /// Add a filter
    pub fn with_filter(mut self, key: String, value: String) -> Self {
        self.filters.insert(key, value);
        self
    }
}

/// Security context for query execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// User ID making the request
    pub user_id: Option<String>,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Remaining rate limit
    pub rate_limit_remaining: Option<u32>,
    /// User permissions
    pub permissions: Vec<String>,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            user_id: None,
            api_key: None,
            rate_limit_remaining: None,
            permissions: Vec::new(),
        }
    }
}

/// Query execution plan after parsing and optimization
#[derive(Debug, Clone)]
pub struct QueryExecutionPlan {
    /// Original query
    pub original_query: String,
    /// Optimized query parts
    pub query_parts: Vec<QueryPart>,
    /// Parallel execution groups
    pub execution_groups: Vec<ExecutionGroup>,
    /// Estimated execution time
    pub estimated_time_ms: u64,
}

/// Individual part of a parsed query
#[derive(Debug, Clone)]
pub struct QueryPart {
    /// Part type (keyword, phrase, filter, etc.)
    pub part_type: QueryPartType,
    /// The actual content
    pub content: String,
    /// Weight for ranking
    pub weight: f32,
}

/// Type of query part
#[derive(Debug, Clone, PartialEq)]
pub enum QueryPartType {
    Keyword,
    Phrase,
    WildCard,
    Filter,
    Negation,
    Boost,
}

/// Group of queries that can be executed in parallel
#[derive(Debug, Clone)]
pub struct ExecutionGroup {
    /// Group ID
    pub id: String,
    /// Queries in this group
    pub queries: Vec<SubQuery>,
    /// Can be executed in parallel
    pub parallel: bool,
}

/// Sub-query for a specific source
#[derive(Debug, Clone)]
pub struct SubQuery {
    /// Unique ID for this sub-query
    pub id: String,
    /// Target source
    pub source: String,
    /// Transformed query for this source
    pub query: String,
    /// Source-specific parameters
    pub params: HashMap<String, serde_json::Value>,
    /// Priority (0-100, higher is more important)
    pub priority: u8,
    /// Sources to search
    pub sources: Vec<String>,
    /// Dependencies on other sub-queries
    pub dependencies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::synthex::query::SubQuery;
    
    #[test]
    fn test_query_builder() {
        let query = SearchQuery::new("rust performance")
            .with_options(
                QueryOptions::default()
                    .with_max_results(50)
                    .with_timeout(3000)
                    .with_sources(vec!["web".to_string(), "docs".to_string()])
            );
        
        assert_eq!(query.query, "rust performance");
        assert_eq!(query.options.max_results, 50);
        assert_eq!(query.options.timeout_ms, 3000);
        assert_eq!(query.options.sources.len(), 2);
    }
    
    #[test]
    fn test_query_options_builder() {
        let options = QueryOptions::default()
            .with_max_results(200)
            .without_cache()
            .with_filter("language".to_string(), "rust".to_string());
        
        assert_eq!(options.max_results, 200);
        assert!(!options.enable_cache);
        assert_eq!(options.filters.get("language"), Some(&"rust".to_string()));
    }
}