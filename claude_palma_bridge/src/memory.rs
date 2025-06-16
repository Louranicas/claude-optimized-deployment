// NAM/ANAM-Compatible Memory Interface
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct SharedMemoryStack {
    tensors: Arc<DashMap<String, String>>, // simplified for Claude Code
}

impl SharedMemoryStack {
    pub fn new() -> Self {
        println!("🧠 NAM/ANAM Memory Stack initialized");
        Self {
            tensors: Arc::new(DashMap::new()),
        }
    }

    pub fn write_tensor(&self, key: &str, value: &str) {
        self.tensors.insert(key.to_string(), value.to_string());
    }

    pub fn read_tensor(&self, key: &str) -> Option<String> {
        self.tensors.get(key).map(|v| v.to_string())
    }

    pub fn get_memory_stats(&self) -> (usize, Vec<String>) {
        let count = self.tensors.len();
        let keys: Vec<String> = self.tensors.iter().map(|entry| entry.key().clone()).collect();
        (count, keys)
    }
}