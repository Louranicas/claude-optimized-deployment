//! Lock-free Messaging System
//! 
//! High-performance inter-module communication with sub-microsecond overhead.

use std::sync::Arc;
use crossbeam::queue::SegQueue;
use tokio::sync::Notify;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use parking_lot::Mutex;
use tracing::{trace, warn};

/// Generic message type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message<T> {
    pub id: u64,
    pub payload: T,
    pub timestamp: u64,
    pub priority: Priority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Lock-free message queue with notification
pub struct MessageQueue<T: Send + Sync> {
    /// Lock-free queue for each priority level
    queues: [Arc<SegQueue<Message<T>>>; 4],
    
    /// Notification for new messages
    notifier: Arc<Notify>,
    
    /// Message counter
    message_counter: AtomicU64,
    
    /// Queue statistics
    stats: Arc<QueueStats>,
}

struct QueueStats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    messages_dropped: AtomicU64,
    total_latency_ns: AtomicU64,
    queue_sizes: [AtomicUsize; 4],
}

impl<T: Send + Sync + Clone> MessageQueue<T> {
    /// Create a new message queue
    pub fn new() -> Self {
        Self {
            queues: [
                Arc::new(SegQueue::new()),
                Arc::new(SegQueue::new()),
                Arc::new(SegQueue::new()),
                Arc::new(SegQueue::new()),
            ],
            notifier: Arc::new(Notify::new()),
            message_counter: AtomicU64::new(0),
            stats: Arc::new(QueueStats {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                messages_dropped: AtomicU64::new(0),
                total_latency_ns: AtomicU64::new(0),
                queue_sizes: [
                    AtomicUsize::new(0),
                    AtomicUsize::new(0),
                    AtomicUsize::new(0),
                    AtomicUsize::new(0),
                ],
            }),
        }
    }
    
    /// Send a message with sub-microsecond overhead
    #[inline(always)]
    pub fn send(&self, payload: T, priority: Priority) -> Result<u64> {
        let start = Instant::now();
        
        let id = self.message_counter.fetch_add(1, Ordering::Relaxed);
        let message = Message {
            id,
            payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            priority,
        };
        
        let queue_idx = priority as usize;
        self.queues[queue_idx].push(message);
        
        // Update stats
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.queue_sizes[queue_idx].fetch_add(1, Ordering::Relaxed);
        
        // Notify waiters
        self.notifier.notify_one();
        
        let latency = start.elapsed().as_nanos() as u64;
        self.stats.total_latency_ns.fetch_add(latency, Ordering::Relaxed);
        
        trace!("Message {} sent with priority {:?}, latency: {}ns", id, priority, latency);
        
        Ok(id)
    }
    
    /// Receive a message (non-blocking)
    #[inline(always)]
    pub fn try_receive(&self) -> Option<Message<T>> {
        // Check queues in priority order
        for (idx, queue) in self.queues.iter().enumerate().rev() {
            if let Some(msg) = queue.pop() {
                self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
                self.stats.queue_sizes[idx].fetch_sub(1, Ordering::Relaxed);
                return Some(msg);
            }
        }
        None
    }
    
    /// Receive a message (blocking with timeout)
    pub async fn receive_timeout(&self, timeout: Duration) -> Option<Message<T>> {
        let deadline = Instant::now() + timeout;
        
        loop {
            if let Some(msg) = self.try_receive() {
                return Some(msg);
            }
            
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            
            // Wait for notification or timeout
            tokio::select! {
                _ = self.notifier.notified() => continue,
                _ = tokio::time::sleep(remaining) => return None,
            }
        }
    }
    
    /// Get queue statistics
    pub fn get_stats(&self) -> MessageQueueStats {
        let sent = self.stats.messages_sent.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        let avg_latency_ns = if sent > 0 {
            self.stats.total_latency_ns.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release / sent
        } else {
            0
        };
        
        MessageQueueStats {
            messages_sent: sent,
            messages_received: self.stats.messages_received.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            messages_dropped: self.stats.messages_dropped.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            avg_latency_ns,
            queue_sizes: [
                self.stats.queue_sizes[0].load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
                self.stats.queue_sizes[1].load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
                self.stats.queue_sizes[2].load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
                self.stats.queue_sizes[3].load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            ],
        }
    }
    
    /// Clear all queues
    pub fn clear(&self) {
        for (idx, queue) in self.queues.iter().enumerate() {
            let mut count = 0;
            while queue.pop().is_some() {
                count += 1;
            }
            if count > 0 {
                self.stats.messages_dropped.fetch_add(count, Ordering::Relaxed);
                self.stats.queue_sizes[idx].store(0, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageQueueStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub avg_latency_ns: u64,
    pub queue_sizes: [usize; 4],
}

/// Multi-producer, multi-consumer channel
pub struct Channel<T: Send + Sync> {
    queue: Arc<MessageQueue<T>>,
}

impl<T: Send + Sync + Clone> Channel<T> {
    pub fn new() -> (Sender<T>, Receiver<T>) {
        let queue = Arc::new(MessageQueue::new());
        (
            Sender { queue: queue.clone() },
            Receiver { queue },
        )
    }
}

/// Channel sender
pub struct Sender<T: Send + Sync> {
    queue: Arc<MessageQueue<T>>,
}

impl<T: Send + Sync + Clone> Sender<T> {
    #[inline(always)]
    pub fn send(&self, value: T) -> Result<()> {
        self.queue.send(value, Priority::Normal)?;
        Ok(())
    }
    
    #[inline(always)]
    pub fn send_priority(&self, value: T, priority: Priority) -> Result<()> {
        self.queue.send(value, priority)?;
        Ok(())
    }
}

impl<T: Send + Sync> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self { queue: self.queue.clone() }
    }
}

/// Channel receiver
pub struct Receiver<T: Send + Sync> {
    queue: Arc<MessageQueue<T>>,
}

impl<T: Send + Sync + Clone> Receiver<T> {
    #[inline(always)]
    pub fn try_recv(&self) -> Option<T> {
        self.queue.try_receive().map(|msg| msg.payload)
    }
    
    pub async fn recv(&self) -> Option<T> {
        self.queue.receive_timeout(Duration::from_secs(3600))
            .await
            .map(|msg| msg.payload)
    }
    
    pub async fn recv_timeout(&self, timeout: Duration) -> Option<T> {
        self.queue.receive_timeout(timeout)
            .await
            .map(|msg| msg.payload)
    }
}

impl<T: Send + Sync> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self { queue: self.queue.clone() }
    }
}

/// Broadcast channel for one-to-many communication
pub struct BroadcastChannel<T: Send + Sync + Clone> {
    subscribers: Arc<Mutex<Vec<Sender<T>>>>,
}

impl<T: Send + Sync + Clone + 'static> BroadcastChannel<T> {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Subscribe to the broadcast channel
    pub fn subscribe(&self) -> Receiver<T> {
        let (tx, rx) = Channel::new();
        self.subscribers.lock().push(tx);
        rx
    }
    
    /// Broadcast a message to all subscribers
    pub fn broadcast(&self, value: T) -> Result<usize> {
        let subscribers = self.subscribers.lock();
        let mut sent = 0;
        
        for subscriber in subscribers.iter() {
            if subscriber.send(value.clone()).is_ok() {
                sent += 1;
            }
        }
        
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_message_queue() {
        let queue = MessageQueue::<String>::new();
        
        // Test sending
        let id = queue.send("test".to_string(), Priority::Normal).unwrap();
        assert_eq!(id, 0);
        
        // Test receiving
        let msg = queue.try_receive().unwrap();
        assert_eq!(msg.payload, "test");
        assert_eq!(msg.priority, Priority::Normal);
        
        // Test stats
        let stats = queue.get_stats();
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_received, 1);
        assert!(stats.avg_latency_ns < 10000); // Should be under 10μs
    }
    
    #[tokio::test]
    async fn test_priority_ordering() {
        let queue = MessageQueue::<u32>::new();
        
        // Send messages with different priorities
        queue.send(1, Priority::Low).unwrap();
        queue.send(2, Priority::High).unwrap();
        queue.send(3, Priority::Normal).unwrap();
        queue.send(4, Priority::Critical).unwrap();
        
        // Should receive in priority order
        assert_eq!(queue.try_receive().unwrap().payload, 4); // Critical
        assert_eq!(queue.try_receive().unwrap().payload, 2); // High
        assert_eq!(queue.try_receive().unwrap().payload, 3); // Normal
        assert_eq!(queue.try_receive().unwrap().payload, 1); // Low
    }
    
    #[tokio::test]
    async fn test_channel() {
        let (tx, rx) = Channel::<String>::new();
        
        // Clone for multi-producer
        let tx2 = tx.clone();
        
        // Send from multiple producers
        tx.send("msg1".to_string()).unwrap();
        tx2.send("msg2".to_string()).unwrap();
        
        // Receive
        assert_eq!(rx.try_recv().unwrap(), "msg1");
        assert_eq!(rx.try_recv().unwrap(), "msg2");
    }
    
    #[tokio::test]
    async fn test_broadcast() {
        let broadcast = BroadcastChannel::<String>::new();
        
        // Create subscribers
        let rx1 = broadcast.subscribe();
        let rx2 = broadcast.subscribe();
        
        // Broadcast message
        let sent = broadcast.broadcast("hello".to_string()).unwrap();
        assert_eq!(sent, 2);
        
        // Both should receive
        assert_eq!(rx1.try_recv().unwrap(), "hello");
        assert_eq!(rx2.try_recv().unwrap(), "hello");
    }
}