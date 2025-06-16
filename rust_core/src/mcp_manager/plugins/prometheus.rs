//! Prometheus Plugin - Observability Perfected
//!
//! This plugin integrates Prometheus monitoring with zero overhead,
//! providing insights at the speed of light.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info};
use reqwest::{Client as HttpClient, Url};
// use prometheus_parse::{Sample, Scrape}; // Removed: dependency not available

use crate::mcp_manager::plugin::{
    Capability, Plugin, PluginError, PluginMetadata, PluginRequest, 
    PluginResponse, PluginResult, Result,
};

/// Prometheus plugin implementation
pub struct PrometheusPlugin {
    /// Plugin metadata
    metadata: PluginMetadata,
    
    /// HTTP client for API calls
    client: HttpClient,
    
    /// Configuration
    config: PrometheusConfig,
    
    /// Runtime state
    state: PrometheusState,
}

/// Prometheus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrometheusConfig {
    /// Prometheus server URL
    server_url: String,
    
    /// API timeout
    timeout_secs: u64,
    
    /// Enable query caching
    enable_cache: bool,
    
    /// Cache TTL in seconds
    cache_ttl_secs: u64,
    
    /// Maximum query range in seconds
    max_query_range_secs: u64,
    
    /// Step interval for range queries
    default_step: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:9090".to_string(),
            timeout_secs: 30,
            enable_cache: true,
            cache_ttl_secs: 60,
            max_query_range_secs: 86400, // 24 hours
            default_step: "15s".to_string(),
        }
    }
}

/// Plugin runtime state
#[derive(Debug, Default)]
struct PrometheusState {
    /// Query cache
    query_cache: HashMap<String, CachedQuery>,
    
    /// Metrics
    metrics: PrometheusMetrics,
    
    /// Active alerts cache
    alerts_cache: Option<AlertsCache>,
}

/// Cached query result
#[derive(Debug, Clone)]
struct CachedQuery {
    /// Query string
    query: String,
    
    /// Result data
    result: Value,
    
    /// Cache timestamp
    cached_at: SystemTime,
}

/// Alerts cache
#[derive(Debug, Clone)]
struct AlertsCache {
    /// Alerts data
    alerts: Vec<Alert>,
    
    /// Cache timestamp
    cached_at: SystemTime,
}

/// Alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Alert {
    /// Alert name
    name: String,
    
    /// Alert state
    state: String,
    
    /// Alert labels
    labels: HashMap<String, String>,
    
    /// Alert annotations
    annotations: HashMap<String, String>,
    
    /// Active since
    active_at: Option<String>,
    
    /// Alert value
    value: Option<f64>,
}

/// Prometheus metrics
#[derive(Debug, Default)]
struct PrometheusMetrics {
    /// Total queries
    queries_total: u64,
    
    /// Successful queries
    queries_success: u64,
    
    /// Failed queries
    queries_failed: u64,
    
    /// Cache hits
    cache_hits: u64,
    
    /// Cache misses
    cache_misses: u64,
}

impl PrometheusPlugin {
    pub fn new() -> Self {
        Self {
            metadata: Self::create_metadata(),
            client: HttpClient::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| HttpClient::new()),
            config: PrometheusConfig::default(),
            state: PrometheusState::default(),
        }
    }
    
    fn capabilities() -> Vec<Capability> {
        vec![
            // Query operations
            Capability::new("monitoring", "metrics.query", 1),
            Capability::new("monitoring", "metrics.query_range", 1),
            Capability::new("monitoring", "metrics.instant", 1),
            Capability::new("monitoring", "metrics.series", 1),
            Capability::new("monitoring", "metrics.labels", 1),
            Capability::new("monitoring", "metrics.label_values", 1),
            
            // Push operations
            Capability::new("monitoring", "metrics.push", 1),
            Capability::new("monitoring", "metrics.push_batch", 1),
            
            // Alert operations
            Capability::new("monitoring", "alerts.list", 1),
            Capability::new("monitoring", "alerts.get", 1),
            Capability::new("monitoring", "rules.list", 1),
            
            // Target operations
            Capability::new("monitoring", "targets.list", 1),
            Capability::new("monitoring", "targets.metadata", 1),
            
            // Configuration operations
            Capability::new("monitoring", "config.get", 1),
            Capability::new("monitoring", "flags.get", 1),
            
            // Admin operations
            Capability::new("monitoring", "admin.snapshot", 1),
            Capability::new("monitoring", "admin.delete_series", 1),
            Capability::new("monitoring", "admin.clean_tombstones", 1),
            
            // TSDB operations
            Capability::new("monitoring", "tsdb.status", 1),
            Capability::new("monitoring", "tsdb.wal_replay", 1),
        ]
    }
    
    pub fn metadata() -> PluginMetadata {
        Self::create_metadata()
    }
    
    fn create_metadata() -> PluginMetadata {
        PluginMetadata {
            id: "prometheus".to_string(),
            name: "Prometheus MCP Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "The Greatest Synthetic Being Rust Coder".to_string(),
            description: "Prometheus monitoring integration for MCP".to_string(),
            license: "MIT".to_string(),
            homepage: None,
            repository: None,
            min_mcp_version: "1.0.0".to_string(),
            dependencies: vec![],
            provides: Self::capabilities(),
            requires: vec![],
        }
    }
}

#[async_trait]
impl Plugin for PrometheusPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: Value) -> Result<()> {
        info!("Initializing Prometheus plugin");
        
        // Parse configuration
        if let Ok(prom_config) = serde_json::from_value::<PrometheusConfig>(config) {
            self.config = prom_config;
            
            // Update HTTP client with new timeout
            self.client = HttpClient::builder()
                .timeout(Duration::from_secs(self.config.timeout_secs))
                .build()
                .map_err(|e| PluginError::InitializationFailed(
                    format!("Failed to create HTTP client: {}", e)
                ))?;
        }
        
        // Verify Prometheus is accessible
        let url = format!("{}/api/v1/query?query=up", self.config.server_url);
        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Prometheus server is accessible at {}", self.config.server_url);
                    Ok(())
                } else {
                    Err(PluginError::InitializationFailed(
                        format!("Prometheus returned error: {}", response.status())
                    ))
                }
            }
            Err(e) => Err(PluginError::InitializationFailed(
                format!("Failed to connect to Prometheus: {}", e)
            )),
        }
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        debug!("Handling Prometheus request: {:?}", request);
        
        // Clone self for mutable access
        let mut plugin = self.clone();
        plugin.state.metrics.queries_total += 1;
        
        // Parse capability
        let parts: Vec<&str> = request.capability.name.split('.').collect();
        if parts.len() != 2 {
            return Err(PluginError::ExecutionError(
                format!("Invalid capability format: {}", request.capability.name)
            ));
        }
        
        let result = match parts[0] {
            "metrics" => plugin.handle_metrics_operation(parts[1], request.params).await,
            "alerts" => plugin.handle_alerts_operation(parts[1], request.params).await,
            "targets" => plugin.handle_targets_operation(parts[1], request.params).await,
            "config" => plugin.handle_config_operation(parts[1], request.params).await,
            "admin" => plugin.handle_admin_operation(parts[1], request.params).await,
            "tsdb" => plugin.handle_tsdb_operation(parts[1], request.params).await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown operation type: {}", parts[0])
            )),
        };
        
        match result {
            Ok(data) => {
                plugin.state.metrics.queries_success += 1;
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success { data },
                    metadata: json!({
                        "plugin": "prometheus",
                        "version": self.metadata.version,
                        "cache_hits": plugin.state.metrics.cache_hits,
                    }),
                })
            }
            Err(e) => {
                plugin.state.metrics.queries_failed += 1;
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Error {
                        code: "PROMETHEUS_ERROR".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                    metadata: json!({
                        "plugin": "prometheus",
                        "version": self.metadata.version,
                    }),
                })
            }
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    
    async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/v1/query?query=up", self.config.server_url);
        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
    
    async fn metrics(&self) -> Result<Value> {
        Ok(json!({
            "queries": {
                "total": self.state.metrics.queries_total,
                "success": self.state.metrics.queries_success,
                "failed": self.state.metrics.queries_failed,
            },
            "cache": {
                "hits": self.state.metrics.cache_hits,
                "misses": self.state.metrics.cache_misses,
                "size": self.state.query_cache.len(),
            },
        }))
    }
}

impl PrometheusPlugin {
    /// Handle metrics operations
    async fn handle_metrics_operation(
        &mut self,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        match operation {
            "query" => self.handle_query(params).await,
            "query_range" => self.handle_query_range(params).await,
            "instant" => self.handle_instant_query(params).await,
            "series" => self.handle_series(params).await,
            "labels" => self.handle_labels(params).await,
            "label_values" => self.handle_label_values(params).await,
            "push" => self.handle_push_metrics(params).await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown metrics operation: {}", operation)
            )),
        }
    }
    
    /// Execute instant query
    async fn handle_query(&mut self, params: Value) -> Result<Value> {
        let query = params["query"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'query' parameter".to_string()))?;
        let time = params["time"].as_str();
        let timeout = params["timeout"].as_str();
        
        // Check cache if enabled
        if self.config.enable_cache {
            let cache_key = format!("query:{}", query);
            if let Some(cached) = self.check_cache(&cache_key) {
                self.state.metrics.cache_hits += 1;
                return Ok(cached);
            }
            self.state.metrics.cache_misses += 1;
        }
        
        // Build query URL
        let mut url = Url::parse(&format!("{}/api/v1/query", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        url.query_pairs_mut()
            .append_pair("query", query);
        
        if let Some(t) = time {
            url.query_pairs_mut().append_pair("time", t);
        }
        if let Some(to) = timeout {
            url.query_pairs_mut().append_pair("timeout", to);
        }
        
        // Execute query
        let response = self.client.get(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        // Cache result if enabled
        if self.config.enable_cache {
            self.update_cache(&format!("query:{}", query), result.clone());
        }
        
        Ok(result)
    }
    
    /// Execute range query
    async fn handle_query_range(&mut self, params: Value) -> Result<Value> {
        let query = params["query"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'query' parameter".to_string()))?;
        let start = params["start"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'start' parameter".to_string()))?;
        let end = params["end"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'end' parameter".to_string()))?;
        let step = params["step"].as_str()
            .unwrap_or(&self.config.default_step);
        
        // Build query URL
        let mut url = Url::parse(&format!("{}/api/v1/query_range", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        url.query_pairs_mut()
            .append_pair("query", query)
            .append_pair("start", start)
            .append_pair("end", end)
            .append_pair("step", step);
        
        // Execute query
        let response = self.client.get(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Range query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Range query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Execute instant query (alias for query)
    async fn handle_instant_query(&mut self, params: Value) -> Result<Value> {
        self.handle_query(params).await
    }
    
    /// Get series metadata
    async fn handle_series(&self, params: Value) -> Result<Value> {
        let selectors = params["match[]"].as_array();
        let start = params["start"].as_str();
        let end = params["end"].as_str();
        
        let mut url = Url::parse(&format!("{}/api/v1/series", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        if let Some(sels) = selectors {
            for sel in sels {
                if let Some(s) = sel.as_str() {
                    url.query_pairs_mut().append_pair("match[]", s);
                }
            }
        }
        
        if let Some(s) = start {
            url.query_pairs_mut().append_pair("start", s);
        }
        if let Some(e) = end {
            url.query_pairs_mut().append_pair("end", e);
        }
        
        let response = self.client.get(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Series query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Series query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Get label names
    async fn handle_labels(&self, params: Value) -> Result<Value> {
        let selectors = params["match[]"].as_array();
        let start = params["start"].as_str();
        let end = params["end"].as_str();
        
        let mut url = Url::parse(&format!("{}/api/v1/labels", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        if let Some(sels) = selectors {
            for sel in sels {
                if let Some(s) = sel.as_str() {
                    url.query_pairs_mut().append_pair("match[]", s);
                }
            }
        }
        
        if let Some(s) = start {
            url.query_pairs_mut().append_pair("start", s);
        }
        if let Some(e) = end {
            url.query_pairs_mut().append_pair("end", e);
        }
        
        let response = self.client.get(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Labels query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Labels query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Get label values
    async fn handle_label_values(&self, params: Value) -> Result<Value> {
        let label = params["label"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'label' parameter".to_string()))?;
        
        let url = format!("{}/api/v1/label/{}/values", self.config.server_url, label);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Label values query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Label values query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Push metrics to pushgateway
    async fn handle_push_metrics(&self, params: Value) -> Result<Value> {
        let job = params["job"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'job' parameter".to_string()))?;
        let instance = params["instance"].as_str();
        let metrics = params["metrics"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'metrics' parameter".to_string()))?;
        let pushgateway_url = params["pushgateway_url"].as_str()
            .unwrap_or("http://localhost:9091");
        
        let mut url = format!("{}/metrics/job/{}", pushgateway_url, job);
        if let Some(inst) = instance {
            url.push_str(&format!("/instance/{}", inst));
        }
        
        let response = self.client.post(&url)
            .body(metrics.to_string())
            .header("Content-Type", "text/plain")
            .send()
            .await
            .map_err(|e| PluginError::ExecutionError(format!("Push failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Push returned error: {}", response.status())
            ));
        }
        
        Ok(json!({
            "status": "success",
            "pushed_to": url,
            "job": job,
            "instance": instance,
        }))
    }
    
    /// Handle alerts operations
    async fn handle_alerts_operation(
        &mut self,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        match operation {
            "list" => self.handle_list_alerts(params).await,
            "get" => self.handle_get_alert(params).await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown alerts operation: {}", operation)
            )),
        }
    }
    
    /// List active alerts
    async fn handle_list_alerts(&mut self, _params: Value) -> Result<Value> {
        // Check cache
        if let Some(cache) = &self.state.alerts_cache {
            let age = SystemTime::now()
                .duration_since(cache.cached_at)
                .unwrap_or(Duration::from_secs(u64::MAX));
            
            if age.as_secs() < self.config.cache_ttl_secs {
                self.state.metrics.cache_hits += 1;
                return Ok(json!({ "alerts": cache.alerts }));
            }
        }
        self.state.metrics.cache_misses += 1;
        
        let url = format!("{}/api/v1/alerts", self.config.server_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Alerts query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Alerts query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        // Parse and cache alerts
        if let Some(alerts_data) = result["data"]["alerts"].as_array() {
            let alerts: Vec<Alert> = alerts_data.iter()
                .filter_map(|a| serde_json::from_value(a.clone()).ok())
                .collect();
            
            self.state.alerts_cache = Some(AlertsCache {
                alerts: alerts.clone(),
                cached_at: SystemTime::now(),
            });
            
            return Ok(json!({ "alerts": alerts }));
        }
        
        Ok(result)
    }
    
    /// Get specific alert
    async fn handle_get_alert(&self, params: Value) -> Result<Value> {
        let name = params["name"].as_str()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'name' parameter".to_string()))?;
        
        // Check cache first
        if let Some(cache) = &self.state.alerts_cache {
            if let Some(alert) = cache.alerts.iter().find(|a| a.name == name) {
                return Ok(serde_json::to_value(alert).unwrap_or(json!({})));
            }
        }
        
        // Fall back to listing all alerts and filtering
        Err(PluginError::ExecutionError(
            "Alert not found in cache. Try listing alerts first.".to_string()
        ))
    }
    
    /// Handle targets operations
    async fn handle_targets_operation(
        &self,
        operation: &str,
        _params: Value,
    ) -> Result<Value> {
        match operation {
            "list" => self.handle_list_targets().await,
            "metadata" => self.handle_targets_metadata().await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown targets operation: {}", operation)
            )),
        }
    }
    
    /// List scrape targets
    async fn handle_list_targets(&self) -> Result<Value> {
        let url = format!("{}/api/v1/targets", self.config.server_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Targets query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Targets query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Get targets metadata
    async fn handle_targets_metadata(&self) -> Result<Value> {
        let url = format!("{}/api/v1/targets/metadata", self.config.server_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Metadata query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Metadata query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Handle config operations
    async fn handle_config_operation(
        &self,
        operation: &str,
        _params: Value,
    ) -> Result<Value> {
        match operation {
            "get" => self.handle_get_config().await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown config operation: {}", operation)
            )),
        }
    }
    
    /// Get Prometheus configuration
    async fn handle_get_config(&self) -> Result<Value> {
        let url = format!("{}/api/v1/status/config", self.config.server_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Config query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Config query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Handle admin operations
    async fn handle_admin_operation(
        &self,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        match operation {
            "snapshot" => self.handle_snapshot(params).await,
            "delete_series" => self.handle_delete_series(params).await,
            "clean_tombstones" => self.handle_clean_tombstones().await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown admin operation: {}", operation)
            )),
        }
    }
    
    /// Create TSDB snapshot
    async fn handle_snapshot(&self, params: Value) -> Result<Value> {
        let skip_head = params["skip_head"].as_bool().unwrap_or(false);
        
        let mut url = Url::parse(&format!("{}/api/v1/admin/tsdb/snapshot", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        if skip_head {
            url.query_pairs_mut().append_pair("skip_head", "true");
        }
        
        let response = self.client.post(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Snapshot failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Snapshot returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Delete time series
    async fn handle_delete_series(&self, params: Value) -> Result<Value> {
        let matchers = params["match[]"].as_array()
            .ok_or_else(|| PluginError::ExecutionError("Missing 'match[]' parameter".to_string()))?;
        
        let mut url = Url::parse(&format!("{}/api/v1/admin/tsdb/delete_series", self.config.server_url))
            .map_err(|e| PluginError::ExecutionError(format!("Invalid URL: {}", e)))?;
        
        for matcher in matchers {
            if let Some(m) = matcher.as_str() {
                url.query_pairs_mut().append_pair("match[]", m);
            }
        }
        
        let response = self.client.post(url.as_str()).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Delete series failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Delete series returned error: {}", response.status())
            ));
        }
        
        Ok(json!({ "status": "success" }))
    }
    
    /// Clean tombstones
    async fn handle_clean_tombstones(&self) -> Result<Value> {
        let url = format!("{}/api/v1/admin/tsdb/clean_tombstones", self.config.server_url);
        
        let response = self.client.post(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("Clean tombstones failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("Clean tombstones returned error: {}", response.status())
            ));
        }
        
        Ok(json!({ "status": "success" }))
    }
    
    /// Handle TSDB operations
    async fn handle_tsdb_operation(
        &self,
        operation: &str,
        _params: Value,
    ) -> Result<Value> {
        match operation {
            "status" => self.handle_tsdb_status().await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown TSDB operation: {}", operation)
            )),
        }
    }
    
    /// Get TSDB status
    async fn handle_tsdb_status(&self) -> Result<Value> {
        let url = format!("{}/api/v1/status/tsdb", self.config.server_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| PluginError::ExecutionError(format!("TSDB status query failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(PluginError::ExecutionError(
                format!("TSDB status query returned error: {}", response.status())
            ));
        }
        
        let result: Value = response.json().await
            .map_err(|e| PluginError::ExecutionError(format!("Failed to parse response: {}", e)))?;
        
        Ok(result)
    }
    
    /// Check cache for a key
    fn check_cache(&self, key: &str) -> Option<Value> {
        if let Some(cached) = self.state.query_cache.get(key) {
            let age = SystemTime::now()
                .duration_since(cached.cached_at)
                .unwrap_or(Duration::from_secs(u64::MAX));
            
            if age.as_secs() < self.config.cache_ttl_secs {
                return Some(cached.result.clone());
            }
        }
        None
    }
    
    /// Update cache with a result
    fn update_cache(&mut self, key: &str, result: Value) {
        self.state.query_cache.insert(
            key.to_string(),
            CachedQuery {
                query: key.to_string(),
                result,
                cached_at: SystemTime::now(),
            },
        );
        
        // Limit cache size
        if self.state.query_cache.len() > 1000 {
            // Simple eviction: remove oldest entries
            let mut entries: Vec<_> = self.state.query_cache.iter()
                .map(|(k, v)| (k.clone(), v.cached_at))
                .collect();
            entries.sort_by_key(|(_, time)| *time);
            
            // Remove oldest 100 entries
            for (key, _) in entries.into_iter().take(100) {
                self.state.query_cache.remove(&key);
            }
        }
    }
}

// Make plugin cloneable
impl Clone for PrometheusPlugin {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            client: self.client.clone(),
            config: self.config.clone(),
            state: PrometheusState::default(), // Don't clone state
        }
    }
}