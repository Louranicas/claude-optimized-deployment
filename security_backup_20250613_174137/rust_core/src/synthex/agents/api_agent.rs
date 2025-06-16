// API Search Agent - High-speed API integration
use super::*;
use reqwest::{Client, ClientBuilder, Method};
use std::time::Duration;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

/// API search agent for external service integration
pub struct ApiSearchAgent {
    client: Client,
    config: Arc<ApiConfig>,
    endpoints: Arc<RwLock<HashMap<String, ApiEndpoint>>>,
    semaphore: Arc<Semaphore>,
    metrics: Arc<RwLock<AgentMetrics>>,
}

/// API configuration
#[derive(Clone)]
pub struct ApiConfig {
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub rate_limit_per_second: Option<u32>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 50,
            request_timeout_ms: 10000,
            retry_attempts: 3,
            retry_delay_ms: 1000,
            rate_limit_per_second: Some(100),
        }
    }
}

/// API endpoint configuration
#[derive(Clone)]
pub struct ApiEndpoint {
    pub name: String,
    pub base_url: String,
    pub method: Method,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub auth: Option<ApiAuth>,
    pub query_param: String,
    pub response_path: Option<String>,
    pub transform: Option<ResponseTransform>,
}

/// API authentication methods
#[derive(Clone)]
pub enum ApiAuth {
    Bearer(String),
    Basic { username: String, password: String },
    ApiKey { header: String, value: String },
    OAuth2 { token_url: String, client_id: String, client_secret: String },
}

/// Response transformation configuration
#[derive(Clone)]
pub struct ResponseTransform {
    pub results_path: String,
    pub id_field: String,
    pub content_field: String,
    pub score_field: Option<String>,
    pub metadata_fields: Vec<String>,
}

impl ApiSearchAgent {
    pub fn new(config: ApiConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .pool_max_idle_per_host(config.max_concurrent_requests)
            .build()?;
        
        Ok(Self {
            client,
            config: Arc::new(config),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            metrics: Arc::new(RwLock::new(AgentMetrics::default())),
        })
    }
    
    /// Register an API endpoint
    pub async fn register_endpoint(&self, endpoint: ApiEndpoint) {
        let mut endpoints = self.endpoints.write();
        endpoints.insert(endpoint.name.clone(), endpoint);
    }
    
    /// Search a specific API endpoint
    async fn search_endpoint(
        &self,
        endpoint: &ApiEndpoint,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let _permit = self.semaphore.acquire().await?;
        
        // Build request
        let url = format!("{}{}", endpoint.base_url, endpoint.path);
        let mut request = self.client.request(endpoint.method.clone(), &url);
        
        // Add headers
        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }
        
        // Add authentication
        if let Some(auth) = &endpoint.auth {
            request = self.apply_auth(request, auth)?;
        }
        
        // Add query parameters
        request = request.query(&[(endpoint.query_param.as_str(), query)]);
        
        // Add additional filters from options
        for (key, value) in &options.filters {
            request = request.query(&[(key.as_str(), value.as_str())]);
        }
        
        // Execute request with retries
        let response = self.execute_with_retry(request).await?;
        let json: Value = response.json().await?;
        
        // Transform response to RawResults
        self.transform_response(json, endpoint, query)
    }
    
    /// Apply authentication to request
    fn apply_auth(
        &self,
        mut request: reqwest::RequestBuilder,
        auth: &ApiAuth,
    ) -> Result<reqwest::RequestBuilder, Box<dyn std::error::Error>> {
        match auth {
            ApiAuth::Bearer(token) => {
                request = request.bearer_auth(token);
            }
            ApiAuth::Basic { username, password } => {
                request = request.basic_auth(username, Some(password));
            }
            ApiAuth::ApiKey { header, value } => {
                request = request.header(header, value);
            }
            ApiAuth::OAuth2 { .. } => {
                // TODO: Implement OAuth2 flow
                return Err("OAuth2 not yet implemented".into());
            }
        }
        Ok(request)
    }
    
    /// Execute request with retry logic
    async fn execute_with_retry(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            
            match request.try_clone().unwrap().send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    
                    if attempts >= self.config.retry_attempts {
                        return Err(format!("API error {}: {}", status, body).into());
                    }
                    
                    // Check if retryable
                    if status.is_server_error() || status == 429 {
                        tokio::time::sleep(Duration::from_millis(
                            self.config.retry_delay_ms * attempts as u64
                        )).await;
                        continue;
                    }
                    
                    return Err(format!("API error {}: {}", status, body).into());
                }
                Err(e) => {
                    if attempts >= self.config.retry_attempts {
                        return Err(e.into());
                    }
                    tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                }
            }
        }
    }
    
    /// Transform API response to RawResults
    fn transform_response(
        &self,
        json: Value,
        endpoint: &ApiEndpoint,
        query: &str,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        
        // Navigate to results array
        let items = if let Some(transform) = &endpoint.transform {
            self.extract_path(&json, &transform.results_path)?
        } else {
            &json
        };
        
        // Process each item
        if let Some(array) = items.as_array() {
            for item in array {
                let result = self.transform_item(item, endpoint, query)?;
                results.push(result);
            }
        } else if items.is_object() {
            // Single result
            let result = self.transform_item(items, endpoint, query)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Transform single item to RawResult
    fn transform_item(
        &self,
        item: &Value,
        endpoint: &ApiEndpoint,
        query: &str,
    ) -> Result<RawResult, Box<dyn std::error::Error>> {
        let transform = endpoint.transform.as_ref();
        
        // Extract fields
        let id = transform
            .and_then(|t| item.get(&t.id_field))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        
        let content = transform
            .and_then(|t| item.get(&t.content_field))
            .map(|v| v.to_string())
            .unwrap_or_else(|| item.to_string());
        
        let score = transform
            .and_then(|t| t.score_field.as_ref())
            .and_then(|field| item.get(field))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.8);
        
        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), json!("api"));
        metadata.insert("endpoint".to_string(), json!(endpoint.name));
        metadata.insert("query".to_string(), json!(query));
        metadata.insert("id".to_string(), json!(id));
        
        // Add custom metadata fields
        if let Some(transform) = &endpoint.transform {
            for field in &transform.metadata_fields {
                if let Some(value) = item.get(field) {
                    metadata.insert(field.clone(), value.clone());
                }
            }
        }
        
        Ok(RawResult {
            content,
            metadata,
            score,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    /// Extract value from JSON path
    fn extract_path<'a>(&self, json: &'a Value, path: &str) -> Result<&'a Value, Box<dyn std::error::Error>> {
        let mut current = json;
        
        for part in path.split('.') {
            if part.is_empty() {
                continue;
            }
            
            // Handle array index
            if let Some(index_str) = part.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let index: usize = index_str.parse()?;
                current = current.get(index)
                    .ok_or_else(|| format!("Array index {} not found", index))?;
            } else {
                current = current.get(part)
                    .ok_or_else(|| format!("Field {} not found", part))?;
            }
        }
        
        Ok(current)
    }
}

#[async_trait]
impl SearchAgent for ApiSearchAgent {
    fn name(&self) -> &str {
        "api"
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![QueryType::FullText, QueryType::Structured]
    }
    
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_searches += 1;
        }
        
        let mut all_results = Vec::new();
        let endpoints = self.endpoints.read();
        
        // Search all registered endpoints
        for (name, endpoint) in endpoints.iter() {
            match self.search_endpoint(endpoint, query, &options).await {
                Ok(mut results) => {
                    all_results.append(&mut results);
                }
                Err(e) => {
                    eprintln!("Failed to search endpoint {}: {}", name, e);
                }
            }
        }
        
        // Sort by score and limit
        all_results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        all_results.truncate(options.max_results);
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.successful_searches += 1;
            let elapsed = start.elapsed().as_millis() as u64;
            metrics.avg_latency_ms = (metrics.avg_latency_ms * (metrics.successful_searches - 1) 
                + elapsed) / metrics.successful_searches;
        }
        
        Ok(all_results)
    }
    
    async fn health_check(&self) -> Result<HealthStatus, Box<dyn std::error::Error>> {
        let endpoints = self.endpoints.read();
        
        if endpoints.is_empty() {
            return Ok(HealthStatus {
                healthy: true,
                latency_ms: 0,
                error_rate: 0.0,
                last_check: chrono::Utc::now().timestamp_millis() as u64,
            });
        }
        
        // Check first endpoint
        let (_, endpoint) = endpoints.iter().next().unwrap();
        let start = std::time::Instant::now();
        
        let url = format!("{}/health", endpoint.base_url);
        let response = self.client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        
        let latency_ms = start.elapsed().as_millis() as u64;
        let healthy = response.map(|r| r.status().is_success()).unwrap_or(false);
        
        let metrics = self.metrics.read();
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
        self.metrics.read().clone()
    }
}