// Web Search Agent - High-speed web search optimized for AI
use super::*;
use reqwest::{Client, ClientBuilder};
use scraper::{Html, Selector};
use tokio::sync::{Semaphore, RwLock};
use url::Url;
use std::time::Duration;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

/// Web search agent for internet searches
pub struct WebSearchAgent {
    client: Client,
    config: Arc<WebSearchConfig>,
    semaphore: Arc<Semaphore>,
    cache: Arc<RwLock<LruCache<String, CachedResult>>>,
    metrics: Arc<RwLock<AgentMetrics>>,
}

/// Web search configuration
#[derive(Clone)]
pub struct WebSearchConfig {
    pub user_agent: String,
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
    pub max_redirects: usize,
    pub cache_size: usize,
    pub cache_ttl_ms: u64,
    pub brave_api_key: Option<String>,
    pub searxng_url: Option<String>,
}

impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            user_agent: "SYNTHEX/1.0 (AI Search Engine)".to_string(),
            max_concurrent_requests: 100,
            request_timeout_ms: 5000,
            max_redirects: 5,
            cache_size: 10000,
            cache_ttl_ms: 3600000, // 1 hour
            brave_api_key: None,
            searxng_url: None,
        }
    }
}

/// Cached search result
#[derive(Clone)]
struct CachedResult {
    results: Vec<RawResult>,
    cached_at: u64,
}

impl WebSearchAgent {
    pub fn new(config: WebSearchConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client = ClientBuilder::new()
            .user_agent(&config.user_agent)
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .pool_max_idle_per_host(config.max_concurrent_requests)
            .build()?;
        
        Ok(Self {
            client,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            cache: Arc::new(RwLock::new(LruCache::new(config.cache_size))),
            config: Arc::new(config),
            metrics: Arc::new(RwLock::new(AgentMetrics::default())),
        })
    }
    
    /// Search using Brave Search API
    async fn search_brave(&self, query: &str) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let api_key = self.config.brave_api_key.as_ref()
            .ok_or("Brave API key not configured")?;
        
        let url = format!("https://api.search.brave.com/res/v1/web/search?q={}", 
            urlencoding::encode(query));
        
        let response = self.client
            .get(&url)
            .header("X-Subscription-Token", api_key)
            .send()
            .await?;
        
        let data: serde_json::Value = response.json().await?;
        let mut results = Vec::new();
        
        if let Some(web_results) = data["web"]["results"].as_array() {
            for result in web_results {
                let raw_result = RawResult {
                    content: format!("{}\n\n{}", 
                        result["title"].as_str().unwrap_or(""),
                        result["description"].as_str().unwrap_or("")
                    ),
                    metadata: hashmap!{
                        "url".to_string() => serde_json::Value::String(
                            result["url"].as_str().unwrap_or("").to_string()
                        ),
                        "source".to_string() => serde_json::Value::String("brave".to_string()),
                    },
                    score: 0.9,
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                };
                results.push(raw_result);
            }
        }
        
        Ok(results)
    }
    
    /// Search using SearXNG instance
    async fn search_searxng(&self, query: &str) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let searxng_url = self.config.searxng_url.as_ref()
            .ok_or("SearXNG URL not configured")?;
        
        let url = format!("{}/search?q={}&format=json", 
            searxng_url, urlencoding::encode(query));
        
        let response = self.client.get(&url).send().await?;
        let data: serde_json::Value = response.json().await?;
        let mut results = Vec::new();
        
        if let Some(search_results) = data["results"].as_array() {
            for result in search_results {
                let raw_result = RawResult {
                    content: format!("{}\n\n{}", 
                        result["title"].as_str().unwrap_or(""),
                        result["content"].as_str().unwrap_or("")
                    ),
                    metadata: hashmap!{
                        "url".to_string() => serde_json::Value::String(
                            result["url"].as_str().unwrap_or("").to_string()
                        ),
                        "engine".to_string() => serde_json::Value::String(
                            result["engine"].as_str().unwrap_or("").to_string()
                        ),
                        "source".to_string() => serde_json::Value::String("searxng".to_string()),
                    },
                    score: result["score"].as_f64().unwrap_or(0.8),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                };
                results.push(raw_result);
            }
        }
        
        Ok(results)
    }
    
    /// Scrape a specific URL
    async fn scrape_url(&self, url: &str) -> Result<RawResult, Box<dyn std::error::Error>> {
        let _permit = self.semaphore.acquire().await?;
        
        let response = self.client.get(url).send().await?;
        let html = response.text().await?;
        let document = Html::parse_document(&html);
        
        // Extract main content
        let content = self.extract_main_content(&document);
        
        // Extract metadata
        let title = self.extract_title(&document);
        let description = self.extract_description(&document);
        
        Ok(RawResult {
            content: format!("{}\n\n{}\n\n{}", title, description, content),
            metadata: hashmap!{
                "url".to_string() => serde_json::Value::String(url.to_string()),
                "source".to_string() => serde_json::Value::String("direct_scrape".to_string()),
                "scraped_at".to_string() => serde_json::Value::Number(
                    serde_json::Number::from(chrono::Utc::now().timestamp())
                ),
            },
            score: 0.85,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    /// Extract main content from HTML
    fn extract_main_content(&self, document: &Html) -> String {
        // Try common content selectors
        let selectors = vec![
            "main", "article", "[role='main']", 
            ".content", "#content", ".post", ".entry-content"
        ];
        
        for selector_str in selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    return element.text().collect::<Vec<_>>().join(" ");
                }
            }
        }
        
        // Fallback to body
        if let Ok(body_selector) = Selector::parse("body") {
            if let Some(body) = document.select(&body_selector).next() {
                return body.text().collect::<Vec<_>>().join(" ");
            }
        }
        
        String::new()
    }
    
    /// Extract title from HTML
    fn extract_title(&self, document: &Html) -> String {
        if let Ok(selector) = Selector::parse("title") {
            if let Some(title) = document.select(&selector).next() {
                return title.text().collect::<Vec<_>>().join("");
            }
        }
        String::new()
    }
    
    /// Extract description from HTML
    fn extract_description(&self, document: &Html) -> String {
        if let Ok(selector) = Selector::parse("meta[name='description']") {
            if let Some(meta) = document.select(&selector).next() {
                if let Some(content) = meta.value().attr("content") {
                    return content.to_string();
                }
            }
        }
        String::new()
    }
}

#[async_trait]
impl SearchAgent for WebSearchAgent {
    fn name(&self) -> &str {
        "web"
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![QueryType::FullText, QueryType::Semantic]
    }
    
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_searches += 1;
        }
        
        // Check cache
        let cache_key = format!("{}:{:?}", query, options.filters);
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(&cache_key) {
                let age = chrono::Utc::now().timestamp_millis() as u64 - cached.cached_at;
                if age < self.config.cache_ttl_ms {
                    let mut metrics = self.metrics.write().await;
                    metrics.cache_hits += 1;
                    metrics.successful_searches += 1;
                    return Ok(cached.results.clone());
                }
            }
        }
        
        // Update cache miss metric
        {
            let mut metrics = self.metrics.write().await;
            metrics.cache_misses += 1;
        }
        
        // Perform search
        let start_time = std::time::Instant::now();
        let mut all_results = Vec::new();
        
        // Check if URL
        if let Ok(url) = Url::parse(query) {
            match self.scrape_url(query).await {
                Ok(result) => all_results.push(result),
                Err(e) => eprintln!("Failed to scrape {}: {}", query, e),
            }
        } else {
            // Use search engines
            if self.config.brave_api_key.is_some() {
                match self.search_brave(query).await {
                    Ok(mut results) => all_results.append(&mut results),
                    Err(e) => eprintln!("Brave search failed: {}", e),
                }
            }
            
            if self.config.searxng_url.is_some() {
                match self.search_searxng(query).await {
                    Ok(mut results) => all_results.append(&mut results),
                    Err(e) => eprintln!("SearXNG search failed: {}", e),
                }
            }
        }
        
        // Limit results
        all_results.truncate(options.max_results);
        
        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.put(cache_key, CachedResult {
                results: all_results.clone(),
                cached_at: chrono::Utc::now().timestamp_millis() as u64,
            });
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.successful_searches += 1;
            let elapsed = start_time.elapsed().as_millis() as u64;
            metrics.avg_latency_ms = (metrics.avg_latency_ms * (metrics.successful_searches - 1) 
                + elapsed) / metrics.successful_searches;
        }
        
        Ok(all_results)
    }
    
    async fn health_check(&self) -> Result<HealthStatus, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        
        // Try a simple request
        let response = self.client
            .get("https://www.google.com/robots.txt")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        
        let latency_ms = start.elapsed().as_millis() as u64;
        let healthy = response.status().is_success();
        
        let metrics = self.metrics.read().await;
        let error_rate = if metrics.total_searches > 0 {
            metrics.failed_searches as f64 / metrics.total_searches as f64
        } else {
            0.0
        };
        
        Ok(HealthStatus {
            healthy,
            latency_ms,
            error_rate,
            last_check: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    fn get_metrics(&self) -> AgentMetrics {
        // Note: This is a sync function so we'll need to handle this differently
        // For now, return a default. In a real implementation, you'd want to 
        // make this async or use a different approach
        AgentMetrics::default()
    }
}

// LRU Cache implementation
struct LruCache<K, V> {
    capacity: usize,
    map: HashMap<K, V>,
    order: Vec<K>,
}

impl<K: Clone + Eq + std::hash::Hash, V> LruCache<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: Vec::new(),
        }
    }
    
    fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            // Move to front
            self.order.retain(|k| k != key);
            self.order.push(key.clone());
            self.map.get(key)
        } else {
            None
        }
    }
    
    fn put(&mut self, key: K, value: V) {
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            // Remove oldest
            if let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                self.map.remove(&oldest);
            }
        }
        
        self.map.insert(key.clone(), value);
        self.order.retain(|k| k != &key);
        self.order.push(key);
    }
}

// Helper macro for hashmaps
macro_rules! hashmap {
    ($($key:expr => $value:expr),*) => {
        {
            let mut map = HashMap::new();
            $(map.insert($key, $value);)*
            map
        }
    };
}