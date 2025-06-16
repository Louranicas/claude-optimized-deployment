//! Shared Memory Module
//! 
//! Zero-copy inter-process communication using memory-mapped files

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::path::{Path, PathBuf};
use bytes::{Bytes, BytesMut};
use memmap2::{MmapMut, MmapOptions};
use parking_lot::{Mutex, RwLock};
use crossbeam::queue::ArrayQueue;
use tracing::{debug, error, info, instrument, warn};

use crate::error::{CoreError, Result};
use crate::protocol::ProtocolMessage;
use crate::CoreConfig;

/// Shared memory region layout
#[repr(C)]
struct SharedMemoryLayout {
    /// Magic number for validation
    magic: u64,
    /// Version number
    version: u32,
    /// Total size
    total_size: u64,
    /// Ring buffer offset
    ring_buffer_offset: u64,
    /// Ring buffer size
    ring_buffer_size: u64,
    /// State cache offset
    state_cache_offset: u64,
    /// State cache size
    state_cache_size: u64,
    /// Message queue offset
    message_queue_offset: u64,
    /// Message queue size
    message_queue_size: u64,
}

const MAGIC_NUMBER: u64 = 0x4D43504C524E4E47; // "MCPLRNNG"
const VERSION: u32 = 1;

/// Ring buffer for zero-copy message passing
pub struct RingBuffer {
    /// Memory mapped region
    mmap: Arc<Mutex<MmapMut>>,
    /// Start offset in shared memory
    offset: usize,
    /// Buffer size
    size: usize,
    /// Write position
    write_pos: Arc<AtomicUsize>,
    /// Read position
    read_pos: Arc<AtomicUsize>,
    /// Number of messages
    message_count: Arc<AtomicU64>,
}

impl RingBuffer {
    fn new(mmap: Arc<Mutex<MmapMut>>, offset: usize, size: usize) -> Self {
        Self {
            mmap,
            offset,
            size,
            write_pos: Arc::new(AtomicUsize::new(0)),
            read_pos: Arc::new(AtomicUsize::new(0)),
            message_count: Arc::new(AtomicU64::new(0)),
        }
    }
    
    /// Write data to the ring buffer
    pub fn write(&self, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        if data_len > self.size / 2 {
            return Err(CoreError::shared_memory("Data too large for ring buffer"));
        }
        
        let mut mmap = self.mmap.lock();
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        // Check available space
        let available = if write_pos >= read_pos {
            self.size - (write_pos - read_pos)
        } else {
            read_pos - write_pos
        };
        
        if available < data_len + 8 { // 8 bytes for length header
            return Err(CoreError::resource_exhausted("Ring buffer full"));
        }
        
        // Write length header
        let len_bytes = (data_len as u64).to_le_bytes();
        let mut new_write_pos = write_pos;
        
        for &byte in &len_bytes {
            mmap[self.offset + new_write_pos] = byte;
            new_write_pos = (new_write_pos + 1) % self.size;
        }
        
        // Write data
        for &byte in data {
            mmap[self.offset + new_write_pos] = byte;
            new_write_pos = (new_write_pos + 1) % self.size;
        }
        
        // Update write position
        self.write_pos.store(new_write_pos, Ordering::Release);
        self.message_count.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Read data from the ring buffer
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        let mut mmap = self.mmap.lock();
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        if read_pos == write_pos {
            return Ok(None); // Buffer empty
        }
        
        // Read length header
        let mut len_bytes = [0u8; 8];
        let mut new_read_pos = read_pos;
        
        for i in 0..8 {
            len_bytes[i] = mmap[self.offset + new_read_pos];
            new_read_pos = (new_read_pos + 1) % self.size;
        }
        
        let data_len = u64::from_le_bytes(len_bytes) as usize;
        if data_len > self.size / 2 {
            return Err(CoreError::shared_memory("Invalid data length in ring buffer"));
        }
        
        // Read data
        let mut data = vec![0u8; data_len];
        for i in 0..data_len {
            data[i] = mmap[self.offset + new_read_pos];
            new_read_pos = (new_read_pos + 1) % self.size;
        }
        
        // Update read position
        self.read_pos.store(new_read_pos, Ordering::Release);
        
        Ok(Some(data))
    }
    
    /// Get the number of messages in the buffer
    pub fn message_count(&self) -> u64 {
        self.message_count.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
}

/// Shared memory region for IPC
pub struct SharedMemoryRegion {
    /// Memory mapped file
    mmap: Arc<Mutex<MmapMut>>,
    /// File path
    file_path: PathBuf,
    /// Ring buffer for messages
    ring_buffer: Arc<RingBuffer>,
    /// Configuration
    config: CoreConfig,
}

impl SharedMemoryRegion {
    /// Create a new shared memory region
    pub fn new(config: &CoreConfig) -> Result<Self> {
        let file_path = std::env::temp_dir().join("mcp_learning_shared.mem");
        
        // Create or open the memory mapped file
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file_path)
            .map_err(|e| CoreError::shared_memory(format!("Failed to open shared memory file: {}", e)))?;
        
        // Set file size
        file.set_len(config.shared_memory_size as u64)
            .map_err(|e| CoreError::shared_memory(format!("Failed to set file size: {}", e)))?;
        
        // Create memory map
        let mmap = unsafe {
            MmapOptions::new()
                .len(config.shared_memory_size)
                .map_mut(&file)
                .map_err(|e| CoreError::shared_memory(format!("Failed to map file: {}", e)))?
        };
        
        let mmap = Arc::new(Mutex::new(mmap));
        
        // Initialize layout
        Self::initialize_layout(&mmap, config)?;
        
        // Create ring buffer
        let ring_buffer = Arc::new(RingBuffer::new(
            mmap.clone(),
            std::mem::size_of::<SharedMemoryLayout>(),
            config.ring_buffer_size,
        ));
        
        info!("Created shared memory region at: {:?}", file_path);
        
        Ok(Self {
            mmap,
            file_path,
            ring_buffer,
            config: config.clone(),
        })
    }
    
    /// Initialize the shared memory layout
    fn initialize_layout(mmap: &Arc<Mutex<MmapMut>>, config: &CoreConfig) -> Result<()> {
        let mut mmap = mmap.lock();
        
        let layout = SharedMemoryLayout {
            magic: MAGIC_NUMBER,
            version: VERSION,
            total_size: config.shared_memory_size as u64,
            ring_buffer_offset: std::mem::size_of::<SharedMemoryLayout>() as u64,
            ring_buffer_size: config.ring_buffer_size as u64,
            state_cache_offset: (std::mem::size_of::<SharedMemoryLayout>() + config.ring_buffer_size) as u64,
            state_cache_size: config.state_cache_size as u64,
            message_queue_offset: (std::mem::size_of::<SharedMemoryLayout>() + 
                                  config.ring_buffer_size + 
                                  config.state_cache_size) as u64,
            message_queue_size: (config.shared_memory_size - 
                               std::mem::size_of::<SharedMemoryLayout>() - 
                               config.ring_buffer_size - 
                               config.state_cache_size) as u64,
        };
        
        // Write layout to the beginning of shared memory
        let layout_bytes = unsafe {
            std::slice::from_raw_parts(
                &layout as *const _ as *const u8,
                std::mem::size_of::<SharedMemoryLayout>()
            )
        };
        
        mmap[..layout_bytes.len()].copy_from_slice(layout_bytes);
        
        Ok(())
    }
    
    /// Write a protocol message to shared memory
    /// TODO: Implement proper serialization for ProtocolMessage
    pub async fn write_message(&self, _message: &ProtocolMessage) -> Result<()> {
        // Placeholder implementation
        debug!("Write message to shared memory - not implemented");
        Ok(())
    }
    
    /// Read a protocol message from shared memory
    /// TODO: Implement proper deserialization for ProtocolMessage
    pub async fn read_message(&self) -> Result<Option<ProtocolMessage>> {
        // Placeholder implementation
        debug!("Read message from shared memory - not implemented");
        Ok(None)
    }
    
    /// Write learning data to shared memory
    pub async fn write_learning_data(&self, message: &ProtocolMessage) -> Result<()> {
        // Learning data goes to a specific section of the ring buffer
        self.write_message(message).await
    }
    
    /// Get ring buffer statistics
    pub fn ring_buffer_stats(&self) -> (u64, usize, usize) {
        let message_count = self.ring_buffer.message_count();
        let write_pos = self.ring_buffer.write_pos.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        let read_pos = self.ring_buffer.read_pos.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        
        (message_count, write_pos, read_pos)
    }
    
    /// Get the file path of the shared memory
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }
    
    /// Flush changes to disk
    pub fn flush(&self) -> Result<()> {
        let mmap = self.mmap.lock();
        mmap.flush()
            .map_err(|e| CoreError::shared_memory(format!("Failed to flush shared memory: {}", e)))?;
        Ok(())
    }
}

impl Drop for SharedMemoryRegion {
    fn drop(&mut self) {
        // Clean up is handled automatically by the OS
        info!("Shared memory region dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_shared_memory_creation() {
        let config = CoreConfig::default();
        let shm = SharedMemoryRegion::new(&config);
        assert!(shm.is_ok());
    }
    
    #[tokio::test]
    async fn test_ring_buffer_write_read() {
        let config = CoreConfig::default();
        let shm = SharedMemoryRegion::new(&config).unwrap();
        
        let data = b"Hello, shared memory!";
        shm.ring_buffer.write(data).unwrap();
        
        let read_data = shm.ring_buffer.read().unwrap();
        assert_eq!(read_data, Some(data.to_vec()));
    }
    
    #[tokio::test]
    async fn test_message_roundtrip() {
        let config = CoreConfig::default();
        let shm = SharedMemoryRegion::new(&config).unwrap();
        
        let message = ProtocolMessage::new(
            crate::protocol::MessageType::Request,
            Bytes::from("test payload")
        );
        
        shm.write_message(&message).await.unwrap();
        let read_message = shm.read_message().await.unwrap();
        
        assert!(read_message.is_some());
        let read_message = read_message.unwrap();
        assert_eq!(read_message.id, message.id);
        assert_eq!(read_message.payload, message.payload);
    }
}