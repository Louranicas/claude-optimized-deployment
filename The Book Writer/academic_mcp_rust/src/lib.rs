use pyo3::prelude::*;
use pyo3_asyncio::tokio::future_into_py;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paper {
    pub id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub year: Option<i32>,
    pub doi: Option<String>,
    pub abstract_text: Option<String>,
    pub citations: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct MCPClient {
    cache: Arc<RwLock<LruCache<String, Paper>>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl MCPClient {
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap()
            ))),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
        }
    }
    
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<Paper>, MCPError> {
        // Check rate limits
        self.rate_limiter.write().await.check_limit()?;
        
        // Check cache first
        let cache_key = format!("search:{}:{}", query, limit);
        if let Some(cached) = self.cache.read().await.peek(&cache_key) {
            return Ok(vec![cached.clone()]);
        }
        
        // Perform actual search
        let papers = self.perform_search(query, limit).await?;
        
        // Update cache
        for paper in &papers {
            self.cache.write().await.put(paper.id.clone(), paper.clone());
        }
        
        Ok(papers)
    }
    
    async fn perform_search(&self, query: &str, limit: usize) -> Result<Vec<Paper>, MCPError> {
        // Implementation for actual MCP search
        todo!("Implement MCP search")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MCPError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

pub struct RateLimiter {
    last_request: std::time::Instant,
    request_count: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            last_request: std::time::Instant::now(),
            request_count: 0,
        }
    }
    
    pub fn check_limit(&mut self) -> Result<(), MCPError> {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_request).as_secs() > 1 {
            self.request_count = 0;
            self.last_request = now;
        }
        
        if self.request_count >= 10 {
            return Err(MCPError::RateLimitExceeded);
        }
        
        self.request_count += 1;
        Ok(())
    }
}

/// Python module definition
#[pymodule]
fn academic_mcp(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMCPClient>()?;
    Ok(())
}

#[pyclass]
struct PyMCPClient {
    inner: Arc<MCPClient>,
}

#[pymethods]
impl PyMCPClient {
    #[new]
    fn new(cache_size: Option<usize>) -> Self {
        Self {
            inner: Arc::new(MCPClient::new(cache_size.unwrap_or(1000))),
        }
    }
    
    fn search<'py>(&self, py: Python<'py>, query: String, limit: Option<usize>) -> PyResult<&'py PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            let papers = client.search(&query, limit.unwrap_or(10)).await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            
            Ok(papers)
        })
    }
}
