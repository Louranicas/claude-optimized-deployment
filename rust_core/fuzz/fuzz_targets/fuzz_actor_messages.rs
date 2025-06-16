#![no_main]

use libfuzzer_sys::fuzz_target;
use claude_optimized_deployment_rust::actors::{ActorSystem, Message, MessageError};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    // Create actor system for testing
    let system = ActorSystem::new();
    
    // Fuzz message creation and serialization
    if data.len() >= 4 {
        let msg_type = data[0];
        let priority = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        
        if data.len() >= 4 + payload_len {
            let payload = &data[4..4 + payload_len];
            
            // Create message with fuzzer data
            match Message::builder()
                .msg_type(msg_type)
                .priority(priority)
                .payload(payload.to_vec())
                .timeout(Duration::from_millis(100))
                .build()
            {
                Ok(message) => {
                    // Test message serialization
                    if let Ok(serialized) = message.serialize() {
                        // Verify round-trip
                        if let Ok(deserialized) = Message::deserialize(&serialized) {
                            assert_eq!(message.msg_type(), deserialized.msg_type());
                            assert_eq!(message.priority(), deserialized.priority());
                            assert_eq!(message.payload(), deserialized.payload());
                        }
                    }
                    
                    // Test actor send/receive
                    if let Ok(actor) = system.spawn_actor("fuzz_test") {
                        // Send should not panic
                        let _ = actor.send(message.clone());
                        
                        // Try receiving with timeout
                        let _ = actor.try_receive_timeout(Duration::from_millis(10));
                    }
                }
                Err(e) => {
                    // Verify error is expected
                    match e {
                        MessageError::InvalidType(_) => {},
                        MessageError::PayloadTooLarge(_) => {},
                        MessageError::InvalidTimeout => {},
                        _ => panic!("Unexpected error: {:?}", e),
                    }
                }
            }
        }
    }
    
    // Fuzz actor mailbox operations
    if let Ok(input) = std::str::from_utf8(data) {
        // Try parsing as actor commands
        for line in input.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            
            match parts[0] {
                "spawn" => {
                    if parts.len() > 1 {
                        let _ = system.spawn_actor(parts[1]);
                    }
                }
                "send" => {
                    if parts.len() > 2 {
                        if let Ok(actor) = system.get_actor(parts[1]) {
                            let _ = actor.send_text(parts[2]);
                        }
                    }
                }
                "broadcast" => {
                    if parts.len() > 1 {
                        let _ = system.broadcast(parts[1].as_bytes().to_vec());
                    }
                }
                _ => {
                    // Unknown command, ignore
                }
            }
        }
    }
    
    // Fuzz concurrent operations
    if data.len() >= 8 {
        let num_actors = (data[0] % 10) as usize + 1;
        let num_messages = (data[1] % 50) as usize;
        
        // Spawn actors
        let mut actors = Vec::new();
        for i in 0..num_actors {
            if let Ok(actor) = system.spawn_actor(&format!("actor_{}", i)) {
                actors.push(actor);
            }
        }
        
        // Send messages between actors
        let mut msg_idx = 2;
        for _ in 0..num_messages {
            if msg_idx + 3 < data.len() && !actors.is_empty() {
                let from_idx = data[msg_idx] as usize % actors.len();
                let to_idx = data[msg_idx + 1] as usize % actors.len();
                let msg_data = vec![data[msg_idx + 2], data[msg_idx + 3]];
                
                let _ = actors[to_idx].send_from(&actors[from_idx], msg_data);
                msg_idx += 4;
            }
        }
        
        // Verify system remains stable
        assert!(system.is_healthy());
    }
});