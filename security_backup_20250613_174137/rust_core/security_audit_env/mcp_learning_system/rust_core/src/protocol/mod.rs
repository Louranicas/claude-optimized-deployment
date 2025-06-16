//! MCP Protocol Handler Module
//! 
//! Zero-copy, high-performance protocol handling for MCP messages

use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

use crate::error::{CoreError, Result};

/// Protocol message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum MessageType {
    /// Request message
    Request = 1,
    /// Response message
    Response = 2,
    /// Notification message
    Notification = 3,
    /// Error message
    Error = 4,
    /// Heartbeat message
    Heartbeat = 5,
    /// Learning data message
    LearningData = 6,
}

/// MCP Protocol Message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolMessage {
    /// Unique message ID
    pub id: uuid::Uuid,
    /// Message type
    pub message_type: MessageType,
    /// Timestamp in microseconds
    pub timestamp: u64,
    /// Message payload
    pub payload: Bytes,
    /// Optional metadata
    pub metadata: Option<DashMap<String, Bytes>>,
}

impl ProtocolMessage {
    /// Create a new protocol message
    pub fn new(message_type: MessageType, payload: Bytes) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            message_type,
            timestamp: chrono::Utc::now().timestamp_micros() as u64,
            payload,
            metadata: None,
        }
    }
    
    /// Add metadata to the message
    pub fn with_metadata(mut self, key: String, value: Bytes) -> Self {
        if self.metadata.is_none() {
            self.metadata = Some(DashMap::new());
        }
        if let Some(ref metadata) = self.metadata {
            metadata.insert(key, value);
        }
        self
    }
    
    /// Get the size of the message in bytes
    pub fn size(&self) -> usize {
        self.payload.len() + 
        std::mem::size_of::<MessageType>() +
        std::mem::size_of::<uuid::Uuid>() +
        std::mem::size_of::<u64>() +
        self.metadata.as_ref().map_or(0, |m| {
            m.iter().map(|entry| {
                entry.key().len() + entry.value().len()
            }).sum()
        })
    }
}

/// Protocol handler statistics
#[derive(Debug, Default)]
pub struct ProtocolStats {
    /// Total messages processed
    pub messages_processed: std::sync::atomic::AtomicU64,
    /// Total bytes processed
    pub bytes_processed: std::sync::atomic::AtomicU64,
    /// Error count
    pub error_count: std::sync::atomic::AtomicU64,
    /// Average latency in microseconds
    pub avg_latency_us: std::sync::atomic::AtomicU64,
}

/// Protocol handler for MCP messages
pub struct ProtocolHandler {
    /// Maximum concurrent connections
    max_connections: usize,
    /// Active connections
    connections: DashMap<uuid::Uuid, Connection>,
    /// Message channel sender
    message_tx: mpsc::Sender<ProtocolMessage>,
    /// Message channel receiver
    message_rx: Arc<RwLock<mpsc::Receiver<ProtocolMessage>>>,
    /// Protocol statistics
    stats: Arc<ProtocolStats>,
    /// Shutdown signal
    shutdown: Arc<tokio::sync::Notify>,
}

/// Individual connection state
struct Connection {
    id: uuid::Uuid,
    created_at: Instant,
    last_activity: Instant,
    messages_sent: u64,
    messages_received: u64,
}

impl ProtocolHandler {
    /// Create a new protocol handler
    pub fn new(max_connections: usize) -> Result<Self> {
        let (message_tx, message_rx) = mpsc::channel(10_000);
        
        Ok(Self {
            max_connections,
            connections: DashMap::new(),
            message_tx,
            message_rx: Arc::new(RwLock::new(message_rx)),
            stats: Arc::new(ProtocolStats::default()),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }
    
    /// Start the protocol handler
    #[instrument(skip_all)]
    pub async fn start(&self) -> Result<()> {
        info!("Starting protocol handler");
        
        // Start message processing task
        let stats = self.stats.clone();
        let message_rx = self.message_rx.clone();
        let shutdown = self.shutdown.clone();
        
        tokio::spawn(async move {
            let mut rx = message_rx.write().await;
            loop {
                tokio::select! {
                    Some(message) = rx.recv() => {
                        let start = Instant::now();
                        
                        // Process message
                        if let Err(e) = Self::process_message(message).await {
                            error!("Failed to process message: {}", e);
                            stats.error_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            stats.messages_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        
                        // Update latency
                        let latency = start.elapsed().as_micros() as u64;
                        stats.avg_latency_us.store(latency, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ = shutdown.notified() => {
                        info!("Protocol handler shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Process a single message
    async fn process_message(message: ProtocolMessage) -> Result<()> {
        debug!("Processing message: {:?}", message.id);
        
        match message.message_type {
            MessageType::Request => {
                // Handle request
                // TODO: Implement request handling
            }
            MessageType::Response => {
                // Handle response
                // TODO: Implement response handling
            }
            MessageType::Notification => {
                // Handle notification
                // TODO: Implement notification handling
            }
            MessageType::Error => {
                // Handle error
                warn!("Received error message: {:?}", message.id);
            }
            MessageType::Heartbeat => {
                // Handle heartbeat
                debug!("Heartbeat received: {:?}", message.id);
            }
            MessageType::LearningData => {
                // Handle learning data
                // TODO: Forward to learning system
            }
        }
        
        Ok(())
    }
    
    /// Send a message
    #[instrument(skip_all)]
    pub async fn send_message(&self, message: ProtocolMessage) -> Result<()> {
        // Check if we're at capacity
        if self.connections.len() >= self.max_connections {
            return Err(CoreError::resource_exhausted("Max connections reached"));
        }
        
        // Send message
        self.message_tx.send(message.clone()).await
            .map_err(|_| CoreError::internal("Failed to send message"))?;
        
        // Update stats
        self.stats.bytes_processed.fetch_add(
            message.size() as u64,
            std::sync::atomic::Ordering::Relaxed
        );
        
        Ok(())
    }
    
    /// Create a new connection
    #[instrument(skip_all)]
    pub fn create_connection(&self) -> Result<uuid::Uuid> {
        let conn_id = uuid::Uuid::new_v4();
        let connection = Connection {
            id: conn_id,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
        };
        
        self.connections.insert(conn_id, connection);
        info!("Created new connection: {}", conn_id);
        
        Ok(conn_id)
    }
    
    /// Close a connection
    #[instrument(skip_all)]
    pub fn close_connection(&self, conn_id: uuid::Uuid) -> Result<()> {
        if self.connections.remove(&conn_id).is_some() {
            info!("Closed connection: {}", conn_id);
            Ok(())
        } else {
            Err(CoreError::protocol("Connection not found"))
        }
    }
    
    /// Get protocol statistics
    pub fn stats(&self) -> &Arc<ProtocolStats> {
        &self.stats
    }
    
    /// Shutdown the protocol handler
    #[instrument(skip_all)]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down protocol handler");
        self.shutdown.notify_one();
        
        // Close all connections
        self.connections.clear();
        
        // Wait a bit for graceful shutdown
        sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_protocol_handler_creation() {
        let handler = ProtocolHandler::new(100);
        assert!(handler.is_ok());
    }
    
    #[tokio::test]
    async fn test_message_creation() {
        let payload = Bytes::from("test payload");
        let message = ProtocolMessage::new(MessageType::Request, payload);
        
        assert_eq!(message.message_type, MessageType::Request);
        assert_eq!(message.payload, Bytes::from("test payload"));
    }
    
    #[tokio::test]
    async fn test_connection_creation() {
        let handler = ProtocolHandler::new(100).unwrap();
        let conn_id = handler.create_connection().unwrap();
        
        assert!(handler.connections.contains_key(&conn_id));
        
        handler.close_connection(conn_id).unwrap();
        assert!(!handler.connections.contains_key(&conn_id));
    }
}