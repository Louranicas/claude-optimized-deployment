"""
Shared Memory Interface for Python-Rust Communication

Zero-copy message passing and state synchronization.
"""

import mmap
import struct
import asyncio
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
import msgpack
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)

# Constants matching Rust side
MAGIC_NUMBER = 0x4D43504C524E4E47  # "MCPLRNNG"
VERSION = 1
HEADER_SIZE = 88  # Size of SharedMemoryLayout struct


@dataclass
class SharedMemoryLayout:
    """Mirror of Rust SharedMemoryLayout struct"""
    magic: int
    version: int
    total_size: int
    ring_buffer_offset: int
    ring_buffer_size: int
    state_cache_offset: int
    state_cache_size: int
    message_queue_offset: int
    message_queue_size: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "SharedMemoryLayout":
        """Parse layout from bytes"""
        unpacked = struct.unpack("<QIQQQQQQQi", data[:HEADER_SIZE])
        return cls(*unpacked)


class RingBuffer:
    """Python implementation of zero-copy ring buffer"""
    
    def __init__(self, mmap_obj: mmap.mmap, offset: int, size: int):
        self.mmap = mmap_obj
        self.offset = offset
        self.size = size
        self.write_pos = 0
        self.read_pos = 0
        self._lock = threading.Lock()
    
    def write(self, data: bytes) -> bool:
        """Write data to ring buffer"""
        with self._lock:
            data_len = len(data)
            if data_len > self.size // 2:
                raise ValueError("Data too large for ring buffer")
            
            # Check available space
            if self.write_pos >= self.read_pos:
                available = self.size - (self.write_pos - self.read_pos)
            else:
                available = self.read_pos - self.write_pos
            
            if available < data_len + 8:  # 8 bytes for length header
                return False  # Buffer full
            
            # Write length header
            len_bytes = struct.pack("<Q", data_len)
            for i, byte in enumerate(len_bytes):
                self.mmap[self.offset + self.write_pos] = byte
                self.write_pos = (self.write_pos + 1) % self.size
            
            # Write data
            for byte in data:
                self.mmap[self.offset + self.write_pos] = byte
                self.write_pos = (self.write_pos + 1) % self.size
            
            return True
    
    def read(self) -> Optional[bytes]:
        """Read data from ring buffer"""
        with self._lock:
            if self.read_pos == self.write_pos:
                return None  # Buffer empty
            
            # Read length header
            len_bytes = bytearray(8)
            for i in range(8):
                len_bytes[i] = self.mmap[self.offset + self.read_pos]
                self.read_pos = (self.read_pos + 1) % self.size
            
            data_len = struct.unpack("<Q", len_bytes)[0]
            if data_len > self.size // 2:
                raise ValueError("Invalid data length in ring buffer")
            
            # Read data
            data = bytearray(data_len)
            for i in range(data_len):
                data[i] = self.mmap[self.offset + self.read_pos]
                self.read_pos = (self.read_pos + 1) % self.size
            
            return bytes(data)


class MessageQueue:
    """High-performance message queue using shared memory"""
    
    def __init__(self, ring_buffer: RingBuffer):
        self.ring_buffer = ring_buffer
        self._callbacks: List[Callable] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
    
    async def send(self, message: Dict[str, Any]) -> bool:
        """Send a message through the queue"""
        data = msgpack.packb(message)
        return await asyncio.get_event_loop().run_in_executor(
            None, self.ring_buffer.write, data
        )
    
    async def receive(self) -> Optional[Dict[str, Any]]:
        """Receive a message from the queue"""
        data = await asyncio.get_event_loop().run_in_executor(
            None, self.ring_buffer.read
        )
        if data:
            return msgpack.unpackb(data, raw=False)
        return None
    
    def subscribe(self, callback: Callable) -> None:
        """Subscribe to message events"""
        self._callbacks.append(callback)
    
    async def start_consumer(self) -> None:
        """Start consuming messages"""
        self._running = True
        self._task = asyncio.create_task(self._consume_loop())
    
    async def stop_consumer(self) -> None:
        """Stop consuming messages"""
        self._running = False
        if self._task:
            await self._task
    
    async def _consume_loop(self) -> None:
        """Internal consumption loop"""
        while self._running:
            message = await self.receive()
            if message:
                for callback in self._callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(message)
                        else:
                            await asyncio.get_event_loop().run_in_executor(
                                None, callback, message
                            )
                    except Exception as e:
                        logger.error(f"Error in message callback: {e}")
            else:
                await asyncio.sleep(0.001)  # Small delay when empty


class StateCache:
    """Distributed state cache using shared memory"""
    
    def __init__(self, mmap_obj: mmap.mmap, offset: int, size: int):
        self.mmap = mmap_obj
        self.offset = offset
        self.size = size
        self._index: Dict[str, Tuple[int, int]] = {}
        self._lock = threading.RLock()
        self._free_list: List[Tuple[int, int]] = [(0, size)]
    
    def set(self, key: str, value: Any) -> bool:
        """Set a value in the cache"""
        data = msgpack.packb(value)
        data_size = len(data) + len(key) + 8  # Include key and metadata
        
        with self._lock:
            # Find free space
            free_idx = None
            for i, (start, size) in enumerate(self._free_list):
                if size >= data_size:
                    free_idx = i
                    break
            
            if free_idx is None:
                return False  # No space available
            
            start, size = self._free_list.pop(free_idx)
            
            # Write to memory
            pos = self.offset + start
            
            # Write key length and key
            key_bytes = key.encode('utf-8')
            self.mmap[pos:pos+4] = struct.pack("<I", len(key_bytes))
            pos += 4
            self.mmap[pos:pos+len(key_bytes)] = key_bytes
            pos += len(key_bytes)
            
            # Write data length and data
            self.mmap[pos:pos+4] = struct.pack("<I", len(data))
            pos += 4
            self.mmap[pos:pos+len(data)] = data
            
            # Update index
            self._index[key] = (start, data_size)
            
            # Update free list if there's remaining space
            if size > data_size:
                self._free_list.append((start + data_size, size - data_size))
                self._free_list.sort()  # Keep sorted for efficiency
            
            return True
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache"""
        with self._lock:
            if key not in self._index:
                return None
            
            start, size = self._index[key]
            pos = self.offset + start
            
            # Read key length and verify key
            key_len = struct.unpack("<I", self.mmap[pos:pos+4])[0]
            pos += 4
            stored_key = self.mmap[pos:pos+key_len].decode('utf-8')
            pos += key_len
            
            if stored_key != key:
                logger.error(f"Key mismatch: expected {key}, got {stored_key}")
                return None
            
            # Read data
            data_len = struct.unpack("<I", self.mmap[pos:pos+4])[0]
            pos += 4
            data = self.mmap[pos:pos+data_len]
            
            return msgpack.unpackb(data, raw=False)
    
    def delete(self, key: str) -> bool:
        """Delete a value from the cache"""
        with self._lock:
            if key not in self._index:
                return False
            
            start, size = self._index.pop(key)
            
            # Add space back to free list
            self._free_list.append((start, size))
            self._free_list.sort()
            
            # Merge adjacent free blocks
            merged = []
            for start, size in self._free_list:
                if merged and merged[-1][0] + merged[-1][1] == start:
                    merged[-1] = (merged[-1][0], merged[-1][1] + size)
                else:
                    merged.append((start, size))
            self._free_list = merged
            
            return True


class SharedMemoryInterface:
    """Main interface for Python-Rust shared memory communication"""
    
    def __init__(self, shm_path: str = "/tmp/mcp_learning_shared.mem"):
        self.shm_path = Path(shm_path)
        self.mmap_obj: Optional[mmap.mmap] = None
        self.layout: Optional[SharedMemoryLayout] = None
        self.message_queue: Optional[MessageQueue] = None
        self.state_cache: Optional[StateCache] = None
        self._executor = ThreadPoolExecutor(max_workers=4)
    
    def connect(self) -> None:
        """Connect to shared memory"""
        if not self.shm_path.exists():
            raise FileNotFoundError(f"Shared memory file not found: {self.shm_path}")
        
        # Open memory mapped file
        with open(self.shm_path, "r+b") as f:
            self.mmap_obj = mmap.mmap(f.fileno(), 0)
        
        # Read layout
        layout_data = self.mmap_obj[:HEADER_SIZE]
        self.layout = SharedMemoryLayout.from_bytes(layout_data)
        
        # Verify magic number and version
        if self.layout.magic != MAGIC_NUMBER:
            raise ValueError("Invalid magic number in shared memory")
        if self.layout.version != VERSION:
            raise ValueError(f"Unsupported version: {self.layout.version}")
        
        # Initialize components
        ring_buffer = RingBuffer(
            self.mmap_obj,
            self.layout.ring_buffer_offset,
            self.layout.ring_buffer_size
        )
        self.message_queue = MessageQueue(ring_buffer)
        
        self.state_cache = StateCache(
            self.mmap_obj,
            self.layout.state_cache_offset,
            self.layout.state_cache_size
        )
        
        logger.info(f"Connected to shared memory: {self.shm_path}")
    
    def disconnect(self) -> None:
        """Disconnect from shared memory"""
        if self.mmap_obj:
            self.mmap_obj.close()
            self.mmap_obj = None
        self._executor.shutdown(wait=True)
        logger.info("Disconnected from shared memory")
    
    async def send_learning_update(self, update: Dict[str, Any]) -> bool:
        """Send a learning update to Rust core"""
        if not self.message_queue:
            raise RuntimeError("Not connected to shared memory")
        
        message = {
            "type": "learning_update",
            "timestamp": datetime.utcnow().isoformat(),
            "data": update
        }
        
        return await self.message_queue.send(message)
    
    async def receive_training_data(self) -> Optional[Dict[str, Any]]:
        """Receive training data from Rust core"""
        if not self.message_queue:
            raise RuntimeError("Not connected to shared memory")
        
        message = await self.message_queue.receive()
        if message and message.get("type") == "training_data":
            return message.get("data")
        return None
    
    def cache_model(self, model_id: str, model_data: bytes) -> bool:
        """Cache a trained model in shared memory"""
        if not self.state_cache:
            raise RuntimeError("Not connected to shared memory")
        
        return self.state_cache.set(f"model:{model_id}", model_data)
    
    def get_cached_model(self, model_id: str) -> Optional[bytes]:
        """Get a cached model from shared memory"""
        if not self.state_cache:
            raise RuntimeError("Not connected to shared memory")
        
        return self.state_cache.get(f"model:{model_id}")
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# Example usage
async def example_usage():
    """Example of using the shared memory interface"""
    
    with SharedMemoryInterface() as shm:
        # Start message consumer
        await shm.message_queue.start_consumer()
        
        # Send a learning update
        update = {
            "model_id": "test_model",
            "accuracy": 0.95,
            "loss": 0.05,
            "iteration": 1000
        }
        success = await shm.send_learning_update(update)
        print(f"Sent update: {success}")
        
        # Cache a model
        model_data = b"pretend_this_is_model_data"
        cached = shm.cache_model("test_model", model_data)
        print(f"Cached model: {cached}")
        
        # Retrieve cached model
        retrieved = shm.get_cached_model("test_model")
        print(f"Retrieved model: {len(retrieved) if retrieved else 0} bytes")
        
        # Stop consumer
        await shm.message_queue.stop_consumer()


if __name__ == "__main__":
    asyncio.run(example_usage())