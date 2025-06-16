// MCP v2 Protocol - High-speed binary protocol for AI communication
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{RwLock};

/// MCP v2 Protocol Version
const PROTOCOL_VERSION: u8 = 2;
const MAGIC_BYTES: [u8; 4] = [0x4D, 0x43, 0x50, 0x32]; // "MCP2"

/// Message types in MCP v2
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    // Core messages
    Request = 0x01,
    Response = 0x02,
    Stream = 0x03,
    Error = 0x04,
    
    // Control messages
    Ping = 0x10,
    Pong = 0x11,
    Close = 0x12,
    Reset = 0x13,
    
    // Bulk operations
    BatchRequest = 0x20,
    BatchResponse = 0x21,
    
    // Subscription
    Subscribe = 0x30,
    Unsubscribe = 0x31,
    Event = 0x32,
}

/// MCP v2 Message Header (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    magic: [u8; 4],        // Magic bytes "MCP2"
    version: u8,           // Protocol version
    msg_type: u8,          // MessageType
    flags: u16,            // Flags (compression, encryption, etc.)
    sequence: u32,         // Sequence number for ordering
    length: u32,           // Payload length
}

/// Message flags
pub struct MessageFlags;
impl MessageFlags {
    pub const COMPRESSED: u16 = 0x0001;
    pub const ENCRYPTED: u16 = 0x0002;
    pub const PRIORITY: u16 = 0x0004;
    pub const NO_REPLY: u16 = 0x0008;
    pub const STREAM_START: u16 = 0x0010;
    pub const STREAM_END: u16 = 0x0020;
    pub const BATCH: u16 = 0x0040;
}

/// MCP v2 Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub correlation_id: Option<String>,
    pub timestamp: u64,
    pub sender: String,
    pub receiver: Option<String>,
    pub payload: MessagePayload,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Message payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessagePayload {
    // Search operations
    SearchRequest {
        query: String,
        filters: HashMap<String, String>,
        max_results: usize,
        timeout_ms: u64,
    },
    SearchResponse {
        results: Vec<serde_json::Value>,
        total_found: usize,
        execution_time_ms: u64,
    },
    
    // Stream operations
    StreamData {
        stream_id: String,
        chunk_index: u64,
        data: Vec<u8>,
        is_final: bool,
    },
    
    // Error
    Error {
        code: u32,
        message: String,
        details: Option<serde_json::Value>,
    },
    
    // Control
    Ping {
        timestamp: u64,
    },
    Pong {
        timestamp: u64,
        latency_ms: u64,
    },
    
    // Batch operations
    BatchRequest {
        requests: Vec<Message>,
    },
    BatchResponse {
        responses: Vec<Message>,
    },
    
    // Generic
    Custom(serde_json::Value),
}

/// MCP v2 Connection
pub struct McpV2Connection {
    stream: TcpStream,
    sequence: AtomicU64,
    compression_threshold: usize,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}

impl McpV2Connection {
    /// Create new connection from stream
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            sequence: AtomicU64::new(0),
            compression_threshold: 1024, // Compress messages > 1KB
            read_buffer: BytesMut::with_capacity(64 * 1024),
            write_buffer: BytesMut::with_capacity(64 * 1024),
        }
    }
    
    /// Send a message
    pub async fn send_message(&mut self, msg_type: MessageType, message: &Message) -> Result<()> {
        // Serialize message
        let payload = bincode::serialize(message)?;
        
        // Determine if compression needed
        let (flags, final_payload) = if payload.len() > self.compression_threshold {
            let compressed = self.compress_payload(&payload)?;
            (MessageFlags::COMPRESSED, compressed)
        } else {
            (0, payload)
        };
        
        // Create header
        let header = MessageHeader {
            magic: MAGIC_BYTES,
            version: PROTOCOL_VERSION,
            msg_type: msg_type as u8,
            flags,
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) as u32,
            length: final_payload.len() as u32,
        };
        
        // Write header
        self.write_header(&header).await?;
        
        // Write payload
        self.stream.write_all(&final_payload).await?;
        self.stream.flush().await?;
        
        Ok(())
    }
    
    /// Receive a message
    pub async fn receive_message(&mut self) -> Result<(MessageType, Message), Box<dyn std::error::Error>> {
        // Read header
        let header = self.read_header().await?;
        
        // Validate magic bytes
        if header.magic != MAGIC_BYTES {
            return Err("Invalid magic bytes".into());
        }
        
        // Read payload
        let mut payload = vec![0u8; header.length as usize];
        self.stream.read_exact(&mut payload).await?;
        
        // Decompress if needed
        let final_payload = if header.flags & MessageFlags::COMPRESSED != 0 {
            self.decompress_payload(&payload)?
        } else {
            payload
        };
        
        // Deserialize message
        let message: Message = bincode::deserialize(&final_payload)?;
        let msg_type = unsafe { std::mem::transmute(header.msg_type) };
        
        Ok((msg_type, message))
    }
    
    /// Write header to stream
    async fn write_header(&mut self, header: &MessageHeader) -> Result<()> {
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                header as *const MessageHeader as *const u8,
                std::mem::size_of::<MessageHeader>()
            )
        };
        
        self.stream.write_all(header_bytes).await?;
        Ok(())
    }
    
    /// Read header from stream
    async fn read_header(&mut self) -> Result<MessageHeader> {
        let mut header_bytes = [0u8; std::mem::size_of::<MessageHeader>()];
        self.stream.read_exact(&mut header_bytes).await?;
        
        let header = unsafe {
            std::ptr::read_unaligned(header_bytes.as_ptr() as *const MessageHeader)
        };
        
        Ok(header)
    }
    
    /// Compress payload
    fn compress_payload(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }
    
    /// Decompress payload
    fn decompress_payload(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }
}

/// MCP v2 Server
pub struct McpV2Server {
    listener: TcpListener,
    handlers: Arc<RwLock<HashMap<MessageType, Box<dyn MessageHandler>>>>,
}

impl McpV2Server {
    /// Create new MCP v2 server
    pub async fn new(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        
        Ok(Self {
            listener,
            handlers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Register message handler
    pub async fn register_handler(&self, msg_type: MessageType, handler: Box<dyn MessageHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(msg_type, handler);
    }
    
    /// Start server
    pub async fn start(&self) -> Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let handlers = self.handlers.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, handlers).await {
                    eprintln!("Connection error from {}: {}", addr, e);
                }
            });
        }
    }
    
    /// Handle individual connection
    async fn handle_connection(
        stream: TcpStream,
        handlers: Arc<RwLock<HashMap<MessageType, Box<dyn MessageHandler>>>>
    ) -> Result<()> {
        let mut conn = McpV2Connection::new(stream);
        
        loop {
            match conn.receive_message().await {
                Ok((msg_type, message)) => {
                    let handlers = handlers.read().await;
                    
                    if let Some(handler) = handlers.get(&msg_type) {
                        match handler.handle(message).await {
                            Ok(Some(response)) => {
                                conn.send_message(MessageType::Response, &response).await?;
                            }
                            Ok(None) => {
                                // No response needed
                            }
                            Err(e) => {
                                let error_response = Message {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    correlation_id: None,
                                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                                    sender: "server".to_string(),
                                    receiver: None,
                                    payload: MessagePayload::Error {
                                        code: 500,
                                        message: e.to_string(),
                                        details: None,
                                    },
                                    metadata: HashMap::new(),
                                };
                                
                                conn.send_message(MessageType::Error, &error_response).await?;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to receive message: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
}

/// Message handler trait
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle(&self, message: Message) -> crate::synthex::Result<Option<Message>>;
}

/// MCP v2 Client
pub struct McpV2Client {
    connections: Arc<RwLock<HashMap<String, McpV2Connection>>>,
    default_timeout_ms: u64,
}

impl McpV2Client {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            default_timeout_ms: 5000,
        }
    }
    
    /// Connect to server
    pub async fn connect(&self, name: &str, addr: &str) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        let conn = McpV2Connection::new(stream);
        
        let mut connections = self.connections.write().await;
        connections.insert(name.to_string(), conn);
        
        Ok(())
    }
    
    /// Send request and wait for response
    pub async fn request(
        &self,
        server: &str,
        payload: MessagePayload
    ) -> Result<Message> {
        let message = Message {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sender: "client".to_string(),
            receiver: Some(server.to_string()),
            payload,
            metadata: HashMap::new(),
        };
        
        let mut connections = self.connections.write().await;
        let conn = connections.get_mut(server)
            .ok_or_else(|| format!("No connection to server: {}", server))?;
        
        // Send request
        conn.send_message(MessageType::Request, &message).await?;
        
        // Wait for response
        let (msg_type, response) = conn.receive_message().await?;
        
        if msg_type == MessageType::Error {
            if let MessagePayload::Error { message, .. } = response.payload {
                return Err(message.into());
            }
        }
        
        Ok(response)
    }
}

// External dependencies
use bincode;
use async_trait;