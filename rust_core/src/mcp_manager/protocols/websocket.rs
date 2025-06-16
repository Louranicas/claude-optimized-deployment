use super::*;
use async_trait::async_trait;
use tokio_tungstenite::{
    connect_async, tungstenite::{
        protocol::WebSocketConfig,
        Message as WsMessage,
        Error as WsError,
    },
    MaybeTlsStream, WebSocketStream,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use anyhow::{anyhow, Context};
use url::Url;

/// WebSocket-based MCP protocol implementation
pub struct WebSocketProtocol {
    config: WebSocketConfig,
    url: Url,
    subprotocols: Vec<String>,
    state: Arc<RwLock<ConnectionState>>,
    capabilities: ProtocolCapabilities,
    metrics: Arc<Mutex<ProtocolMetrics>>,
    ws_stream: Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
    message_tx: mpsc::Sender<MessageType>,
    message_rx: Arc<Mutex<mpsc::Receiver<MessageType>>>,
    ping_interval: Duration,
    pong_timeout: Duration,
}

impl WebSocketProtocol {
    pub fn new(
        url: String,
        subprotocols: Vec<String>,
        ping_interval: Duration,
        pong_timeout: Duration,
        max_frame_size: usize,
    ) -> Result<Self> {
        let url = Url::parse(&url).context("Invalid WebSocket URL")?;
        
        let config = WebSocketConfig {
            max_send_queue: Some(1000),
            max_message_size: Some(max_frame_size),
            max_frame_size: Some(max_frame_size),
            accept_unmasked_frames: false,
        };
        
        let capabilities = ProtocolCapabilities {
            compression: true,
            streaming: true,
            multiplexing: true,
            max_message_size: max_frame_size,
            timeout: Duration::from_secs(60),
            keep_alive: true,
            retry_policy: RetryPolicy::default(),
        };
        
        let (message_tx, message_rx) = mpsc::channel(1000);
        
        Ok(Self {
            config,
            url,
            subprotocols,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            capabilities,
            metrics: Arc::new(Mutex::new(ProtocolMetrics::default())),
            ws_stream: Arc::new(Mutex::new(None)),
            message_tx,
            message_rx: Arc::new(Mutex::new(message_rx)),
            ping_interval,
            pong_timeout,
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
    
    async fn handle_connection(&self) -> Result<()> {
        let ws_stream = self.ws_stream.clone();
        let message_tx = self.message_tx.clone();
        let metrics = self.metrics.clone();
        let state = self.state.clone();
        let ping_interval = self.ping_interval;
        let pong_timeout = self.pong_timeout;
        
        tokio::spawn(async move {
            let mut ping_timer = interval(ping_interval);
            let mut last_pong = std::time::Instant::now();
            
            loop {
                let mut stream_guard = ws_stream.lock().await;
                if let Some(stream) = stream_guard.as_mut() {
                    tokio::select! {
                        // Handle incoming messages
                        msg = stream.next() => {
                            match msg {
                                Some(Ok(WsMessage::Text(text))) => {
                                    if let Ok(message) = serde_json::from_str::<MessageType>(&text) {
                                        let _ = message_tx.send(message).await;
                                        
                                        let mut m = metrics.lock().await;
                                        m.messages_received += 1;
                                        m.bytes_received += text.len() as u64;
                                        m.last_activity = Some(std::time::Instant::now());
                                    }
                                }
                                Some(Ok(WsMessage::Binary(data))) => {
                                    if let Ok(message) = serde_json::from_slice::<MessageType>(&data) {
                                        let _ = message_tx.send(message).await;
                                        
                                        let mut m = metrics.lock().await;
                                        m.messages_received += 1;
                                        m.bytes_received += data.len() as u64;
                                        m.last_activity = Some(std::time::Instant::now());
                                    }
                                }
                                Some(Ok(WsMessage::Pong(_))) => {
                                    last_pong = std::time::Instant::now();
                                }
                                Some(Ok(WsMessage::Close(_))) => {
                                    *state.write().await = ConnectionState::Disconnected;
                                    break;
                                }
                                Some(Err(e)) => {
                                    let mut m = metrics.lock().await;
                                    m.errors += 1;
                                    
                                    *state.write().await = ConnectionState::Failed(e.to_string());
                                    break;
                                }
                                None => {
                                    *state.write().await = ConnectionState::Disconnected;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        
                        // Send periodic pings
                        _ = ping_timer.tick() => {
                            if last_pong.elapsed() > pong_timeout {
                                *state.write().await = ConnectionState::Failed("Pong timeout".to_string());
                                break;
                            }
                            
                            if let Err(e) = stream.send(WsMessage::Ping(vec![])).await {
                                let mut m = metrics.lock().await;
                                m.errors += 1;
                                
                                *state.write().await = ConnectionState::Failed(e.to_string());
                                break;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        });
        
        Ok(())
    }
}

#[async_trait]
impl McpProtocol for WebSocketProtocol {
    async fn connect(&mut self) -> Result<()> {
        *self.state.write().await = ConnectionState::Connecting;
        
        let mut request = self.url.clone().into_client_request()?;
        
        // Add subprotocols
        if !self.subprotocols.is_empty() {
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                self.subprotocols.join(", ").parse()?,
            );
        }
        
        // Add MCP version header
        request.headers_mut().insert(
            "X-MCP-Version",
            MCP_VERSION.parse()?,
        );
        
        match timeout(Duration::from_secs(10), connect_async(request)).await {
            Ok(Ok((ws_stream, _))) => {
                *self.ws_stream.lock().await = Some(ws_stream);
                *self.state.write().await = ConnectionState::Connected;
                
                self.handle_connection().await?;
                
                self.update_metrics(|m| {
                    m.last_activity = Some(std::time::Instant::now());
                }).await;
                
                Ok(())
            }
            Ok(Err(e)) => {
                *self.state.write().await = ConnectionState::Failed(e.to_string());
                Err(anyhow!("WebSocket connection failed: {}", e))
            }
            Err(_) => {
                *self.state.write().await = ConnectionState::Failed("Connection timeout".to_string());
                Err(anyhow!("WebSocket connection timeout"))
            }
        }
    }
    
    async fn send(&mut self, message: MessageType) -> Result<()> {
        let start = std::time::Instant::now();
        
        let data = serde_json::to_string(&message)?;
        let data_len = data.len() as u64;
        
        let mut stream_guard = self.ws_stream.lock().await;
        if let Some(stream) = stream_guard.as_mut() {
            stream.send(WsMessage::Text(data)).await
                .context("Failed to send WebSocket message")?;
            
            self.update_metrics(|m| {
                m.messages_sent += 1;
                m.bytes_sent += data_len;
                let latency = start.elapsed().as_millis() as f64;
                m.average_latency_ms = (m.average_latency_ms * (m.messages_sent - 1) as f64 + latency)
                    / m.messages_sent as f64;
            }).await;
            
            Ok(())
        } else {
            Err(anyhow!("WebSocket not connected"))
        }
    }
    
    async fn receive(&mut self) -> Result<Option<MessageType>> {
        let mut rx = self.message_rx.lock().await;
        Ok(rx.recv().await)
    }
    
    async fn request(&mut self, method: String, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        
        // Store pending request
        {
            let pending = Arc::new(Mutex::new(HashMap::new()));
            pending.lock().await.insert(id.clone(), tx);
            
            // Set up response handler
            let pending_clone = pending.clone();
            let mut message_rx = self.message_rx.lock().await;
            
            tokio::spawn(async move {
                while let Some(msg) = message_rx.recv().await {
                    if let MessageType::Response { id: resp_id, result, error } = msg {
                        if let Some(tx) = pending_clone.lock().await.remove(&resp_id) {
                            if let Some(err) = error {
                                let _ = tx.send(Err(anyhow!("RPC error: {} (code: {})", err.message, err.code)));
                            } else if let Some(res) = result {
                                let _ = tx.send(Ok(res));
                            } else {
                                let _ = tx.send(Err(anyhow!("Empty response")));
                            }
                        }
                    }
                }
            });
        }
        
        // Send request
        let request = MessageType::Request { id, method, params };
        self.send(request).await?;
        
        // Wait for response
        match timeout(self.capabilities.timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("Response channel closed")),
            Err(_) => Err(anyhow!("Request timeout")),
        }
    }
    
    async fn notify(&mut self, method: String, params: serde_json::Value) -> Result<()> {
        let notification = MessageType::Notification { method, params };
        self.send(notification).await
    }
    
    async fn is_connected(&self) -> bool {
        matches!(*self.state.read().await, ConnectionState::Connected)
    }
    
    fn connection_state(&self) -> ConnectionState {
        futures::executor::block_on(async {
            self.state.read().await.clone()
        })
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut stream) = self.ws_stream.lock().await.take() {
            let _ = stream.close(None).await;
        }
        
        *self.state.write().await = ConnectionState::Disconnected;
        Ok(())
    }
    
    fn capabilities(&self) -> &ProtocolCapabilities {
        &self.capabilities
    }
    
    async fn keep_alive(&mut self) -> Result<()> {
        // WebSocket handles keep-alive through ping/pong
        Ok(())
    }
    
    fn metrics(&self) -> ProtocolMetrics {
        futures::executor::block_on(async {
            self.metrics.lock().await.clone()
        })
    }
}

/// WebSocket message framer
pub struct WebSocketFramer;

impl MessageFramer for WebSocketFramer {
    fn frame(&self, message: &MessageType) -> Result<Bytes> {
        let json = serde_json::to_vec(message)?;
        Ok(Bytes::from(json))
    }
    
    fn unframe(&mut self, data: &mut Bytes) -> Result<Vec<MessageType>> {
        let mut messages = Vec::new();
        
        // Try to parse as many complete messages as possible
        while !data.is_empty() {
            match serde_json::from_slice::<MessageType>(data) {
                Ok(msg) => {
                    messages.push(msg);
                    data.clear(); // Assuming one message per frame
                }
                Err(_) => break, // Incomplete message, wait for more data
            }
        }
        
        Ok(messages)
    }
}

/// WebSocket connection pool
pub struct WebSocketConnectionPool {
    url: String,
    subprotocols: Vec<String>,
    ping_interval: Duration,
    pong_timeout: Duration,
    max_frame_size: usize,
    connections: Arc<Mutex<Vec<WebSocketProtocol>>>,
    max_connections: usize,
}

impl WebSocketConnectionPool {
    pub fn new(
        url: String,
        subprotocols: Vec<String>,
        ping_interval: Duration,
        pong_timeout: Duration,
        max_frame_size: usize,
        max_connections: usize,
    ) -> Self {
        Self {
            url,
            subprotocols,
            ping_interval,
            pong_timeout,
            max_frame_size,
            connections: Arc::new(Mutex::new(Vec::new())),
            max_connections,
        }
    }
}

#[async_trait]
impl ConnectionPool for WebSocketConnectionPool {
    type Connection = WebSocketProtocol;
    
    async fn get(&self) -> Result<Self::Connection> {
        let mut pool = self.connections.lock().await;
        
        if let Some(mut conn) = pool.pop() {
            if conn.is_connected().await {
                return Ok(conn);
            }
        }
        
        // Create new connection
        let mut conn = WebSocketProtocol::new(
            self.url.clone(),
            self.subprotocols.clone(),
            self.ping_interval,
            self.pong_timeout,
            self.max_frame_size,
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
            active_connections: 0,
            idle_connections: pool.len(),
            wait_time_ms: 0.0,
            timeouts: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_websocket_framer() {
        let mut framer = WebSocketFramer;
        let message = MessageType::Request {
            id: "test".to_string(),
            method: "test_method".to_string(),
            params: serde_json::json!({"key": "value"}),
        };
        
        let framed = framer.frame(&message).unwrap();
        assert!(!framed.is_empty());
        
        let mut data = framed;
        let messages = framer.unframe(&mut data).unwrap();
        assert_eq!(messages.len(), 1);
    }
}