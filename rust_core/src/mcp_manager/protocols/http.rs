use super::*;
use async_trait::async_trait;
use reqwest::{Client, ClientBuilder, header::{HeaderMap, HeaderValue}};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout};
use serde_json::Value;
use anyhow::{anyhow, Context};
use bytes::Bytes;
use backoff::{ExponentialBackoff, future::retry};

/// HTTP-based MCP protocol implementation
pub struct HttpProtocol {
    client: Client,
    config: HttpConfig,
    state: Arc<RwLock<ConnectionState>>,
    capabilities: ProtocolCapabilities,
    metrics: Arc<Mutex<ProtocolMetrics>>,
    pending_requests: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Result<Value>>>>>,
}

#[derive(Debug, Clone)]
struct HttpConfig {
    endpoint: String,
    headers: HashMap<String, String>,
    timeout: Duration,
    max_connections: usize,
    keep_alive: bool,
}

impl HttpProtocol {
    pub fn new(
        endpoint: String,
        headers: HashMap<String, String>,
        timeout: Duration,
        max_connections: usize,
        keep_alive: bool,
    ) -> Result<Self> {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", HeaderValue::from_static("application/json"));
        header_map.insert("Accept", HeaderValue::from_static("application/json"));
        header_map.insert("X-MCP-Version", HeaderValue::from_static(MCP_VERSION));
        
        for (key, value) in &headers {
            header_map.insert(
                key.parse().context("Invalid header name")?,
                HeaderValue::from_str(value).context("Invalid header value")?,
            );
        }
        
        let client = ClientBuilder::new()
            .default_headers(header_map)
            .timeout(timeout)
            .pool_max_idle_per_host(max_connections)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(if keep_alive { Some(Duration::from_secs(30)) } else { None })
            .build()
            .context("Failed to build HTTP client")?;
        
        let capabilities = ProtocolCapabilities {
            compression: true,
            streaming: false,
            multiplexing: true,
            max_message_size: 10 * 1024 * 1024, // 10MB
            timeout,
            keep_alive,
            retry_policy: RetryPolicy::default(),
        };
        
        Ok(Self {
            client,
            config: HttpConfig {
                endpoint,
                headers,
                timeout,
                max_connections,
                keep_alive,
            },
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            capabilities,
            metrics: Arc::new(Mutex::new(ProtocolMetrics::default())),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    async fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut ProtocolMetrics),
    {
        let mut metrics = self.metrics.lock().await;
        f(&mut metrics);
        metrics.last_activity = Some(std::time::Instant::now());
    }
    
    async fn send_http_request(&self, message: MessageType) -> Result<Value> {
        let start = std::time::Instant::now();
        let body = serde_json::to_vec(&message)?;
        let body_len = body.len() as u64;
        
        let backoff = ExponentialBackoff {
            max_elapsed_time: Some(self.config.timeout),
            initial_interval: self.capabilities.retry_policy.initial_delay,
            max_interval: self.capabilities.retry_policy.max_delay,
            multiplier: self.capabilities.retry_policy.exponential_base,
            ..Default::default()
        };
        
        let response = retry(backoff, || async {
            let response = self.client
                .post(&self.config.endpoint)
                .body(body.clone())
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        backoff::Error::transient(anyhow!("Request timeout: {}", e))
                    } else if e.is_connect() {
                        backoff::Error::transient(anyhow!("Connection error: {}", e))
                    } else {
                        backoff::Error::permanent(anyhow!("HTTP error: {}", e))
                    }
                })?;
            
            if response.status().is_server_error() {
                return Err(backoff::Error::transient(anyhow!(
                    "Server error: {}",
                    response.status()
                )));
            }
            
            if !response.status().is_success() {
                return Err(backoff::Error::permanent(anyhow!(
                    "HTTP error: {}",
                    response.status()
                )));
            }
            
            Ok(response)
        })
        .await?;
        
        let response_body = response.bytes().await?;
        let response_len = response_body.len() as u64;
        
        self.update_metrics(|m| {
            m.messages_sent += 1;
            m.bytes_sent += body_len;
            m.messages_received += 1;
            m.bytes_received += response_len;
            let latency = start.elapsed().as_millis() as f64;
            m.average_latency_ms = (m.average_latency_ms * (m.messages_sent - 1) as f64 + latency)
                / m.messages_sent as f64;
        }).await;
        
        let response_msg: MessageType = serde_json::from_slice(&response_body)
            .context("Failed to parse response")?;
        
        match response_msg {
            MessageType::Response { result, error, .. } => {
                if let Some(err) = error {
                    Err(anyhow!("RPC error: {} (code: {})", err.message, err.code))
                } else {
                    result.ok_or_else(|| anyhow!("Empty response"))
                }
            }
            MessageType::Error { code, message, data } => {
                Err(anyhow!("Protocol error: {} (code: {})", message, code))
            }
            _ => Err(anyhow!("Unexpected response type")),
        }
    }
}

#[async_trait]
impl McpProtocol for HttpProtocol {
    async fn connect(&mut self) -> Result<()> {
        *self.state.write().await = ConnectionState::Connecting;
        
        // Test connection with a simple request
        let test_msg = MessageType::Request {
            id: uuid::Uuid::new_v4().to_string(),
            method: "ping".to_string(),
            params: serde_json::json!({}),
        };
        
        match timeout(Duration::from_secs(5), self.send_http_request(test_msg)).await {
            Ok(Ok(_)) => {
                *self.state.write().await = ConnectionState::Connected;
                Ok(())
            }
            Ok(Err(e)) => {
                *self.state.write().await = ConnectionState::Failed(e.to_string());
                Err(e)
            }
            Err(_) => {
                let err = anyhow!("Connection timeout");
                *self.state.write().await = ConnectionState::Failed(err.to_string());
                Err(err)
            }
        }
    }
    
    async fn send(&mut self, message: MessageType) -> Result<()> {
        if !self.is_connected().await {
            return Err(anyhow!("Not connected"));
        }
        
        self.send_http_request(message).await?;
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<MessageType>> {
        // HTTP is request-response, so this doesn't apply
        Ok(None)
    }
    
    async fn request(&mut self, method: String, params: Value) -> Result<Value> {
        if !self.is_connected().await {
            self.connect().await?;
        }
        
        let id = uuid::Uuid::new_v4().to_string();
        let message = MessageType::Request { id, method, params };
        
        self.send_http_request(message).await
    }
    
    async fn notify(&mut self, method: String, params: Value) -> Result<()> {
        if !self.is_connected().await {
            self.connect().await?;
        }
        
        let message = MessageType::Notification { method, params };
        self.send_http_request(message).await?;
        Ok(())
    }
    
    async fn is_connected(&self) -> bool {
        matches!(*self.state.read().await, ConnectionState::Connected)
    }
    
    fn connection_state(&self) -> ConnectionState {
        // This is a blocking read, but should be very fast
        futures::executor::block_on(async {
            self.state.read().await.clone()
        })
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        *self.state.write().await = ConnectionState::Disconnected;
        Ok(())
    }
    
    fn capabilities(&self) -> &ProtocolCapabilities {
        &self.capabilities
    }
    
    async fn keep_alive(&mut self) -> Result<()> {
        if !self.config.keep_alive {
            return Ok(());
        }
        
        self.request("ping".to_string(), serde_json::json!({})).await?;
        Ok(())
    }
    
    fn metrics(&self) -> ProtocolMetrics {
        futures::executor::block_on(async {
            self.metrics.lock().await.clone()
        })
    }
}

/// HTTP connection pool implementation
pub struct HttpConnectionPool {
    endpoint: String,
    headers: HashMap<String, String>,
    timeout: Duration,
    max_connections: usize,
    keep_alive: bool,
    connections: Arc<Mutex<Vec<HttpProtocol>>>,
}

impl HttpConnectionPool {
    pub fn new(
        endpoint: String,
        headers: HashMap<String, String>,
        timeout: Duration,
        max_connections: usize,
        keep_alive: bool,
    ) -> Self {
        Self {
            endpoint,
            headers,
            timeout,
            max_connections,
            keep_alive,
            connections: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ConnectionPool for HttpConnectionPool {
    type Connection = HttpProtocol;
    
    async fn get(&self) -> Result<Self::Connection> {
        let mut pool = self.connections.lock().await;
        
        if let Some(mut conn) = pool.pop() {
            if conn.is_connected().await {
                return Ok(conn);
            }
        }
        
        // Create new connection
        let mut conn = HttpProtocol::new(
            self.endpoint.clone(),
            self.headers.clone(),
            self.timeout,
            self.max_connections,
            self.keep_alive,
        )?;
        
        conn.connect().await?;
        Ok(conn)
    }
    
    async fn put(&self, conn: Self::Connection) -> Result<()> {
        if conn.is_connected().await {
            let mut pool = self.connections.lock().await;
            if pool.len() < self.max_connections {
                pool.push(conn);
            }
        }
        Ok(())
    }
    
    async fn health_check(&self) -> Result<()> {
        let mut pool = self.connections.lock().await;
        pool.retain(|conn| {
            futures::executor::block_on(conn.is_connected())
        });
        Ok(())
    }
    
    fn stats(&self) -> PoolStats {
        let pool = futures::executor::block_on(self.connections.lock());
        PoolStats {
            total_connections: self.max_connections,
            active_connections: 0, // Would need tracking
            idle_connections: pool.len(),
            wait_time_ms: 0.0,
            timeouts: 0,
        }
    }
}

/// HTTP protocol factory
pub struct HttpProtocolFactory {
    default_timeout: Duration,
    default_headers: HashMap<String, String>,
}

impl HttpProtocolFactory {
    pub fn new() -> Self {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "MCP-Client/1.0".to_string());
        
        Self {
            default_timeout: Duration::from_secs(30),
            default_headers: headers,
        }
    }
}

#[async_trait]
impl ProtocolFactory for HttpProtocolFactory {
    type Protocol = HttpProtocol;
    
    async fn create(&self, config: ProtocolConfig) -> Result<Self::Protocol> {
        match config {
            ProtocolConfig::Http {
                endpoint,
                mut headers,
                timeout,
                max_connections,
                keep_alive,
            } => {
                // Merge with default headers
                for (k, v) in &self.default_headers {
                    headers.entry(k.clone()).or_insert(v.clone());
                }
                
                HttpProtocol::new(endpoint, headers, timeout, max_connections, keep_alive)
            }
            _ => Err(anyhow!("Invalid protocol config for HTTP")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_http_protocol_creation() {
        let protocol = HttpProtocol::new(
            "http://localhost:8080".to_string(),
            HashMap::new(),
            Duration::from_secs(30),
            10,
            true,
        );
        
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        assert_eq!(protocol.capabilities().timeout, Duration::from_secs(30));
    }
}