//! Message Router Module
//! 
//! High-performance message routing with zero-copy semantics

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use bytes::Bytes;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender};
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

use crate::error::{CoreError, Result};
use crate::protocol::{ProtocolMessage, MessageType};
use crate::shared_memory::SharedMemoryRegion;

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Priority {
    /// Lowest priority
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority
    High = 2,
    /// Critical priority
    Critical = 3,
}

/// Routing rule for message dispatch
#[derive(Clone)]
pub struct RoutingRule {
    /// Rule ID
    pub id: String,
    /// Message type to match
    pub message_type: MessageType,
    /// Target queue
    pub target_queue: String,
    /// Priority override
    pub priority: Option<Priority>,
    /// Filter function
    pub filter: Option<Arc<dyn Fn(&ProtocolMessage) -> bool + Send + Sync>>,
}

impl std::fmt::Debug for RoutingRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingRule")
            .field("id", &self.id)
            .field("message_type", &self.message_type)
            .field("target_queue", &self.target_queue)
            .field("priority", &self.priority)
            .field("filter", &"<function>")
            .finish()
    }
}

/// Router statistics
#[derive(Debug, Default)]
pub struct RouterStats {
    /// Messages routed
    pub messages_routed: std::sync::atomic::AtomicU64,
    /// Messages dropped
    pub messages_dropped: std::sync::atomic::AtomicU64,
    /// Queue depth
    pub queue_depth: std::sync::atomic::AtomicU64,
    /// Routing latency in microseconds
    pub routing_latency_us: std::sync::atomic::AtomicU64,
}

/// Message queue implementation
struct MessageQueue {
    /// Queue name
    name: String,
    /// Priority queues
    queues: [Sender<ProtocolMessage>; 4],
    /// Receivers
    receivers: [Receiver<ProtocolMessage>; 4],
    /// Maximum queue size
    max_size: usize,
    /// Current size
    current_size: std::sync::atomic::AtomicUsize,
}

impl MessageQueue {
    fn new(name: String, max_size: usize) -> Self {
        // Create priority queues
        let mut queues = Vec::with_capacity(4);
        let mut receivers = Vec::with_capacity(4);
        
        for _ in 0..4 {
            let (tx, rx) = bounded(max_size / 4);
            queues.push(tx);
            receivers.push(rx);
        }
        
        Self {
            name,
            queues: queues.try_into().unwrap(),
            receivers: receivers.try_into().unwrap(),
            max_size,
            current_size: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    
    fn send(&self, message: ProtocolMessage, priority: Priority) -> Result<()> {
        let queue = &self.queues[priority as usize];
        
        // Check capacity
        if self.current_size.load(std::sync::atomic::Ordering::Relaxed) >= self.max_size {
            return Err(CoreError::resource_exhausted("Queue full"));
        }
        
        queue.try_send(message)
            .map_err(|_| CoreError::routing("Failed to enqueue message"))?;
        
        self.current_size.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    
    fn receive(&self) -> Option<ProtocolMessage> {
        // Try high priority queues first
        for i in (0..4).rev() {
            if let Ok(message) = self.receivers[i].try_recv() {
                self.current_size.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                return Some(message);
            }
        }
        None
    }
}

/// High-performance message router
pub struct MessageRouter {
    /// Routing rules
    rules: Arc<RwLock<Vec<RoutingRule>>>,
    /// Message queues
    queues: Arc<DashMap<String, Arc<MessageQueue>>>,
    /// Shared memory region
    shared_memory: Arc<SharedMemoryRegion>,
    /// Router statistics
    stats: Arc<RouterStats>,
    /// Message buffer size
    buffer_size: usize,
    /// Processing tasks
    tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal
    shutdown: Arc<tokio::sync::Notify>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(buffer_size: usize, shared_memory: Arc<SharedMemoryRegion>) -> Result<Self> {
        Ok(Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            queues: Arc::new(DashMap::new()),
            shared_memory,
            stats: Arc::new(RouterStats::default()),
            buffer_size,
            tasks: Arc::new(RwLock::new(Vec::new())),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }
    
    /// Start the message router
    #[instrument(skip_all)]
    pub async fn start(&self) -> Result<()> {
        info!("Starting message router");
        
        // Create default queues
        self.create_queue("default", self.buffer_size)?;
        self.create_queue("learning", self.buffer_size)?;
        self.create_queue("control", self.buffer_size / 4)?;
        
        // Add default routing rules
        self.add_rule(RoutingRule {
            id: "learning_rule".to_string(),
            message_type: MessageType::LearningData,
            target_queue: "learning".to_string(),
            priority: Some(Priority::High),
            filter: None,
        })?;
        
        self.add_rule(RoutingRule {
            id: "control_rule".to_string(),
            message_type: MessageType::Error,
            target_queue: "control".to_string(),
            priority: Some(Priority::Critical),
            filter: None,
        })?;
        
        // Start queue processors
        self.start_queue_processors().await?;
        
        Ok(())
    }
    
    /// Create a new message queue
    #[instrument(skip_all, fields(name = %name, size = size))]
    pub fn create_queue(&self, name: &str, size: usize) -> Result<()> {
        let queue = Arc::new(MessageQueue::new(name.to_string(), size));
        self.queues.insert(name.to_string(), queue);
        info!("Created queue: {}", name);
        Ok(())
    }
    
    /// Add a routing rule
    #[instrument(skip_all, fields(rule_id = %rule.id))]
    pub fn add_rule(&self, rule: RoutingRule) -> Result<()> {
        let mut rules = self.rules.write();
        rules.push(rule);
        info!("Added routing rule");
        Ok(())
    }
    
    /// Route a message
    #[instrument(skip_all, fields(message_id = %message.id))]
    pub async fn route_message(&self, message: ProtocolMessage) -> Result<()> {
        let start = Instant::now();
        
        // Find matching rules
        let rules = self.rules.read();
        let matching_rules: Vec<_> = rules.iter()
            .filter(|rule| {
                rule.message_type == message.message_type &&
                rule.filter.as_ref().map_or(true, |f| f(&message))
            })
            .collect();
        
        if matching_rules.is_empty() {
            // Route to default queue
            self.send_to_queue("default", message, Priority::Normal)?;
        } else {
            // Route to all matching queues
            for rule in matching_rules {
                let priority = rule.priority.unwrap_or(Priority::Normal);
                self.send_to_queue(&rule.target_queue, message.clone(), priority)?;
            }
        }
        
        // Update stats
        let latency = start.elapsed().as_micros() as u64;
        self.stats.routing_latency_us.store(latency, std::sync::atomic::Ordering::Relaxed);
        self.stats.messages_routed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Send message to a specific queue
    fn send_to_queue(&self, queue_name: &str, message: ProtocolMessage, priority: Priority) -> Result<()> {
        if let Some(queue) = self.queues.get(queue_name) {
            queue.send(message, priority)?;
            debug!("Message sent to queue: {}", queue_name);
        } else {
            warn!("Queue not found: {}, routing to default", queue_name);
            if let Some(default_queue) = self.queues.get("default") {
                default_queue.send(message, priority)?;
            } else {
                return Err(CoreError::routing("No default queue available"));
            }
        }
        
        Ok(())
    }
    
    /// Start queue processors
    async fn start_queue_processors(&self) -> Result<()> {
        let mut tasks = self.tasks.write();
        
        for queue_entry in self.queues.iter() {
            let queue_name = queue_entry.key().clone();
            let queue = queue_entry.value().clone();
            let shared_memory = self.shared_memory.clone();
            let shutdown = self.shutdown.clone();
            
            let task = tokio::spawn(async move {
                info!("Starting processor for queue: {}", queue_name);
                
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {
                            // Process messages from queue
                            while let Some(message) = queue.receive() {
                                // Process message based on type
                                match message.message_type {
                                    MessageType::LearningData => {
                                        // Write to shared memory for Python layer
                                        if let Err(e) = shared_memory.write_learning_data(&message).await {
                                            error!("Failed to write learning data: {}", e);
                                        }
                                    }
                                    _ => {
                                        // Handle other message types
                                        debug!("Processing message: {:?}", message.id);
                                    }
                                }
                            }
                        }
                        _ = shutdown.notified() => {
                            info!("Queue processor shutting down: {}", queue_name);
                            break;
                        }
                    }
                }
            });
            
            tasks.push(task);
        }
        
        Ok(())
    }
    
    /// Get router statistics
    pub fn stats(&self) -> &Arc<RouterStats> {
        &self.stats
    }
    
    /// Shutdown the router
    #[instrument(skip_all)]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down message router");
        
        // Signal shutdown
        self.shutdown.notify_waiters();
        
        // Wait for tasks to complete
        let mut tasks = self.tasks.write();
        for task in tasks.drain(..) {
            let _ = task.await;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_router_creation() {
        let shared_memory = Arc::new(SharedMemoryRegion::new(&crate::CoreConfig::default()).unwrap());
        let router = MessageRouter::new(1000, shared_memory);
        assert!(router.is_ok());
    }
    
    #[tokio::test]
    async fn test_queue_creation() {
        let shared_memory = Arc::new(SharedMemoryRegion::new(&crate::CoreConfig::default()).unwrap());
        let router = MessageRouter::new(1000, shared_memory).unwrap();
        
        router.create_queue("test_queue", 100).unwrap();
        assert!(router.queues.contains_key("test_queue"));
    }
    
    #[tokio::test]
    async fn test_message_routing() {
        let shared_memory = Arc::new(SharedMemoryRegion::new(&crate::CoreConfig::default()).unwrap());
        let router = MessageRouter::new(1000, shared_memory).unwrap();
        
        router.start().await.unwrap();
        
        let message = ProtocolMessage::new(
            MessageType::Request,
            Bytes::from("test payload")
        );
        
        let result = router.route_message(message).await;
        assert!(result.is_ok());
        
        let stats = router.stats();
        assert_eq!(stats.messages_routed.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}