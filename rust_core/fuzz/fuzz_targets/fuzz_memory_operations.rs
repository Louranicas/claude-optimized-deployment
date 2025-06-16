#![no_main]

use libfuzzer_sys::fuzz_target;
use claude_optimized_deployment_rust::memory::{MemoryStore, VectorDB, MemoryError};
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let memory_store = Arc::new(MemoryStore::new());
    let vector_db = Arc::new(VectorDB::new(128)); // 128-dimensional vectors
    
    // Fuzz memory store operations
    if data.len() >= 2 {
        let op_type = data[0] % 4;
        let key_len = (data[1] % 32) as usize + 1;
        
        if data.len() >= 2 + key_len {
            let key = String::from_utf8_lossy(&data[2..2 + key_len]).to_string();
            let remaining = &data[2 + key_len..];
            
            match op_type {
                0 => {
                    // Store operation
                    if !remaining.is_empty() {
                        match memory_store.store(&key, remaining.to_vec()) {
                            Ok(_) => {
                                // Verify stored data
                                if let Ok(retrieved) = memory_store.get(&key) {
                                    assert_eq!(retrieved.as_ref(), Some(&remaining.to_vec()));
                                }
                            }
                            Err(e) => {
                                match e {
                                    MemoryError::KeyTooLong(_) => {},
                                    MemoryError::ValueTooLarge(_) => {},
                                    MemoryError::OutOfMemory => {},
                                    _ => panic!("Unexpected error: {:?}", e),
                                }
                            }
                        }
                    }
                }
                1 => {
                    // Retrieve operation
                    let _ = memory_store.get(&key);
                }
                2 => {
                    // Update operation
                    if !remaining.is_empty() {
                        let _ = memory_store.update(&key, remaining.to_vec());
                    }
                }
                3 => {
                    // Delete operation
                    let _ = memory_store.delete(&key);
                }
                _ => unreachable!(),
            }
        }
    }
    
    // Fuzz vector database operations
    if data.len() >= 132 {
        // Extract 128-dimensional vector
        let mut vector = Vec::with_capacity(128);
        for i in 0..128 {
            let byte = data[i];
            let float = (byte as f32) / 255.0; // Normalize to [0, 1]
            vector.push(float);
        }
        
        let metadata_start = 128;
        let metadata_len = (data[metadata_start] as usize).min(data.len() - metadata_start - 1);
        
        if data.len() >= metadata_start + 1 + metadata_len {
            let metadata = String::from_utf8_lossy(
                &data[metadata_start + 1..metadata_start + 1 + metadata_len]
            ).to_string();
            
            // Store vector
            match vector_db.store_vector(&metadata, vector.clone()) {
                Ok(id) => {
                    // Verify storage
                    if let Ok(retrieved) = vector_db.get_vector(&id) {
                        assert_eq!(retrieved.len(), 128);
                        // Verify similarity search works
                        let _ = vector_db.search_similar(&vector, 5);
                    }
                }
                Err(e) => {
                    match e {
                        MemoryError::InvalidDimension(_) => {},
                        MemoryError::InvalidVector => {},
                        _ => panic!("Unexpected error: {:?}", e),
                    }
                }
            }
        }
    }
    
    // Fuzz concurrent memory operations
    if data.len() >= 10 {
        use std::thread;
        
        let num_threads = (data[0] % 4) as usize + 1;
        let ops_per_thread = (data[1] % 10) as usize;
        
        let mut handles = vec![];
        
        for t in 0..num_threads {
            let store = Arc::clone(&memory_store);
            let thread_data = data.to_vec();
            
            let handle = thread::spawn(move || {
                for i in 0..ops_per_thread {
                    let idx = 2 + t * ops_per_thread + i;
                    if idx < thread_data.len() {
                        let key = format!("thread_{}_{}", t, i);
                        let value = vec![thread_data[idx]];
                        let _ = store.store(&key, value);
                        let _ = store.get(&key);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }
        
        // Verify memory store is still consistent
        assert!(memory_store.verify_consistency().is_ok());
    }
    
    // Fuzz memory pressure scenarios
    if let Ok(input) = std::str::from_utf8(data) {
        // Parse as memory commands
        for line in input.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "allocate" => {
                        if let Ok(size) = parts[1].parse::<usize>() {
                            let size = size.min(1024 * 1024); // Cap at 1MB
                            let _ = memory_store.allocate_buffer(size);
                        }
                    }
                    "gc" => {
                        memory_store.run_garbage_collection();
                    }
                    "compact" => {
                        let _ = memory_store.compact();
                    }
                    "stats" => {
                        let stats = memory_store.get_stats();
                        assert!(stats.total_bytes >= stats.used_bytes);
                    }
                    _ => {}
                }
            }
        }
    }
});