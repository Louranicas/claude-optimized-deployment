//! Simple Actor Pattern Example
//! 
//! A minimal example showing the core actor pattern used in MCP V2

use tokio::sync::{mpsc, oneshot};
use std::time::Instant;

// Simple message type
#[derive(Debug)]
enum Message {
    Ping { id: u32, reply: oneshot::Sender<u32> },
    Shutdown,
}

// Simple actor that responds to pings
struct PingActor {
    processed: u32,
}

impl PingActor {
    fn new() -> Self {
        Self { processed: 0 }
    }
    
    async fn run(mut self, mut rx: mpsc::Receiver<Message>) {
        println!("🎭 Actor started");
        
        while let Some(msg) = rx.recv().await {
            match msg {
                Message::Ping { id, reply } => {
                    self.processed += 1;
                    // Echo back the ID
                    reply.send(id).ok();
                }
                Message::Shutdown => {
                    println!("🛑 Actor shutting down after processing {} messages", self.processed);
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!("🎬 Simple Actor Pattern Demo\n");
    
    // Create channel for actor communication
    let (tx, rx) = mpsc::channel(100);
    
    // Spawn the actor
    let actor_handle = tokio::spawn(PingActor::new().run(rx));
    
    // Send some messages
    println!("📤 Sending 5 ping messages...");
    for i in 0..5 {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(Message::Ping { id: i, reply: reply_tx }).await.unwrap();
        
        let response = reply_rx.await.unwrap();
        println!("📥 Received pong: {}", response);
    }
    
    // Performance test
    println!("\n⚡ Performance test: 10,000 messages...");
    let start = Instant::now();
    
    for i in 0..10_000 {
        let (reply_tx, _reply_rx) = oneshot::channel();
        tx.send(Message::Ping { id: i, reply: reply_tx }).await.unwrap();
    }
    
    let elapsed = start.elapsed();
    println!("✅ Processed 10,000 messages in {:?}", elapsed);
    println!("📊 Throughput: {:.0} messages/second", 10_000.0 / elapsed.as_secs_f64());
    
    // Shutdown
    tx.send(Message::Shutdown).await.unwrap();
    actor_handle.await.unwrap();
    
    println!("\n🎉 Demo complete!");
}