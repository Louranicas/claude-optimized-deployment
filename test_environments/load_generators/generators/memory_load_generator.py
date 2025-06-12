#!/usr/bin/env python3
"""
Memory Load Generator
====================

Advanced memory load generation with various allocation patterns, memory pressure simulation,
and garbage collection stress testing. Supports realistic memory usage patterns.
"""

import asyncio
import gc
import time
import random
import logging
import threading
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import psutil
import numpy as np
from collections import deque

logger = logging.getLogger(__name__)

@dataclass
class MemoryLoadConfiguration:
    """Configuration for memory load generation"""
    max_memory_mb: int = 1024  # Maximum memory to allocate in MB
    allocation_size_mb: int = 10  # Size of each allocation in MB
    allocation_pattern: str = "steady"  # steady, burst, fragmented, leak_simulation
    fragmentation_level: float = 0.3  # 0.0 to 1.0
    gc_pressure: bool = True  # Enable garbage collection pressure
    leak_simulation: bool = False  # Simulate memory leaks
    adaptive: bool = True  # Adapt based on system memory

class MemoryBlock:
    """Represents a memory allocation block"""
    def __init__(self, size_mb: int, block_id: str, data_type: str = "random"):
        self.size_mb = size_mb
        self.block_id = block_id
        self.data_type = data_type
        self.allocated_at = time.time()
        self.data = self._generate_data(size_mb, data_type)
    
    def _generate_data(self, size_mb: int, data_type: str):
        """Generate data of specified size and type"""
        # Calculate number of elements (assuming 8 bytes per float64)
        num_elements = (size_mb * 1024 * 1024) // 8
        
        if data_type == "random":
            return np.random.rand(num_elements)
        elif data_type == "zeros":
            return np.zeros(num_elements)
        elif data_type == "ones":
            return np.ones(num_elements)
        elif data_type == "sequential":
            return np.arange(num_elements, dtype=np.float64)
        elif data_type == "sparse":
            data = np.zeros(num_elements)
            # Fill only 10% with random values
            sparse_indices = np.random.choice(num_elements, num_elements // 10, replace=False)
            data[sparse_indices] = np.random.rand(len(sparse_indices))
            return data
        else:
            return np.random.rand(num_elements)
    
    def access_data(self, access_pattern: str = "random"):
        """Access data with specified pattern to simulate usage"""
        if self.data is None:
            return
        
        try:
            if access_pattern == "random":
                # Random access
                indices = np.random.randint(0, len(self.data), 1000)
                _ = self.data[indices].sum()
            elif access_pattern == "sequential":
                # Sequential access
                chunk_size = min(10000, len(self.data))
                _ = self.data[:chunk_size].sum()
            elif access_pattern == "strided":
                # Strided access (every 10th element)
                _ = self.data[::10].sum()
            elif access_pattern == "write":
                # Write operations
                if len(self.data) > 1000:
                    indices = np.random.randint(0, len(self.data), 100)
                    self.data[indices] = np.random.rand(100)
        except Exception as e:
            logger.debug(f"Data access error for block {self.block_id}: {e}")

class MemoryLoadGenerator:
    """
    Advanced Memory Load Generator
    
    Generates realistic memory workloads with various allocation patterns,
    fragmentation simulation, and adaptive memory management.
    """
    
    def __init__(self, config: Optional[MemoryLoadConfiguration] = None):
        self.config = config or MemoryLoadConfiguration()
        self.running = False
        self.current_memory_mb = 0
        self.target_memory_mb = 0
        self.allocated_blocks: Dict[str, MemoryBlock] = {}
        self.allocation_counter = 0
        self.deallocation_queue = deque()
        
        # Memory management
        self.peak_memory_mb = 0
        self.allocation_history = []
        self.fragmentation_blocks: List[MemoryBlock] = []
        self.leaked_blocks: Set[str] = set()  # For leak simulation
        
        # Monitoring
        self.performance_samples = []
        self.last_gc_time = time.time()
        self.gc_stats = {'collections': 0, 'freed_objects': 0}
        
        # Threading
        self.access_thread = None
        self.gc_thread = None
        self.monitor_thread = None
    
    async def execute_pattern(self, pattern):
        """Execute a memory load pattern"""
        logger.info(f"Starting memory load pattern: {pattern.name}")
        self.running = True
        
        try:
            # Start background threads
            self._start_background_threads()
            
            # Execute pattern points
            for point in pattern.points:
                if not self.running:
                    break
                
                # Update target memory based on pattern intensity
                self.target_memory_mb = int(self.config.max_memory_mb * point.intensity)
                
                # Adjust memory allocation to match target
                await self._adjust_memory_to_target()
                
                # Wait for next point
                if pattern.points.index(point) < len(pattern.points) - 1:
                    next_point = pattern.points[pattern.points.index(point) + 1]
                    wait_time = next_point.timestamp - point.timestamp
                    await asyncio.sleep(max(1.0, wait_time))
            
            logger.info(f"Completed memory load pattern: {pattern.name}")
            
        except Exception as e:
            logger.error(f"Memory load pattern execution failed: {e}")
            raise
        finally:
            await self.stop()
    
    async def _adjust_memory_to_target(self):
        """Adjust current memory allocation to match target"""
        current_mb = sum(block.size_mb for block in self.allocated_blocks.values())
        self.current_memory_mb = current_mb
        
        if self.target_memory_mb > current_mb:
            # Need to allocate more memory
            await self._allocate_memory(self.target_memory_mb - current_mb)
        elif self.target_memory_mb < current_mb:
            # Need to free some memory
            await self._deallocate_memory(current_mb - self.target_memory_mb)
        
        # Update peak memory tracking
        self.peak_memory_mb = max(self.peak_memory_mb, self.current_memory_mb)
    
    async def _allocate_memory(self, amount_mb: int):
        """Allocate specified amount of memory"""
        pattern = self.config.allocation_pattern
        
        if pattern == "steady":
            await self._allocate_steady(amount_mb)
        elif pattern == "burst":
            await self._allocate_burst(amount_mb)
        elif pattern == "fragmented":
            await self._allocate_fragmented(amount_mb)
        elif pattern == "leak_simulation":
            await self._allocate_with_leaks(amount_mb)
        else:
            await self._allocate_steady(amount_mb)
    
    async def _allocate_steady(self, amount_mb: int):
        """Allocate memory in steady, predictable chunks"""
        chunk_size = self.config.allocation_size_mb
        chunks_needed = max(1, amount_mb // chunk_size)
        
        for i in range(chunks_needed):
            if not self.running:
                break
            
            block_id = f"steady_{self.allocation_counter}"
            self.allocation_counter += 1
            
            try:
                block = MemoryBlock(chunk_size, block_id, "random")
                self.allocated_blocks[block_id] = block
                
                # Record allocation
                self.allocation_history.append({
                    'timestamp': time.time(),
                    'action': 'allocate',
                    'block_id': block_id,
                    'size_mb': chunk_size,
                    'pattern': 'steady'
                })
                
                # Small delay to avoid overwhelming the system
                if i % 10 == 0:
                    await asyncio.sleep(0.01)
                
            except MemoryError:
                logger.warning(f"Memory allocation failed for block {block_id}")
                break
            except Exception as e:
                logger.error(f"Unexpected error during allocation: {e}")
                break
    
    async def _allocate_burst(self, amount_mb: int):
        """Allocate memory in sudden bursts"""
        burst_count = random.randint(3, 7)
        burst_size = amount_mb // burst_count
        
        for burst in range(burst_count):
            if not self.running:
                break
            
            # Allocate burst
            chunks_in_burst = max(1, burst_size // self.config.allocation_size_mb)
            
            for i in range(chunks_in_burst):
                block_id = f"burst_{burst}_{i}_{self.allocation_counter}"
                self.allocation_counter += 1
                
                try:
                    block = MemoryBlock(self.config.allocation_size_mb, block_id, "random")
                    self.allocated_blocks[block_id] = block
                    
                    self.allocation_history.append({
                        'timestamp': time.time(),
                        'action': 'allocate',
                        'block_id': block_id,
                        'size_mb': self.config.allocation_size_mb,
                        'pattern': 'burst',
                        'burst_id': burst
                    })
                    
                except MemoryError:
                    logger.warning(f"Memory allocation failed for burst block {block_id}")
                    break
            
            # Rest between bursts
            if burst < burst_count - 1:
                await asyncio.sleep(random.uniform(0.5, 2.0))
    
    async def _allocate_fragmented(self, amount_mb: int):
        """Allocate memory in a fragmented pattern"""
        # Create various sized allocations to cause fragmentation
        total_allocated = 0
        
        while total_allocated < amount_mb and self.running:
            # Random allocation sizes to create fragmentation
            size_mb = random.choice([1, 2, 5, 10, 20, 50])
            if total_allocated + size_mb > amount_mb:
                size_mb = amount_mb - total_allocated
            
            block_id = f"frag_{self.allocation_counter}"
            self.allocation_counter += 1
            
            try:
                # Use different data types for fragmentation
                data_type = random.choice(["random", "zeros", "sparse", "sequential"])
                block = MemoryBlock(size_mb, block_id, data_type)
                self.allocated_blocks[block_id] = block
                total_allocated += size_mb
                
                # Some blocks will be marked for early deallocation
                if random.random() < self.config.fragmentation_level:
                    self.deallocation_queue.append(block_id)
                
                self.allocation_history.append({
                    'timestamp': time.time(),
                    'action': 'allocate',
                    'block_id': block_id,
                    'size_mb': size_mb,
                    'pattern': 'fragmented',
                    'data_type': data_type
                })
                
                # Occasionally free some blocks to create holes
                if len(self.deallocation_queue) > 5 and random.random() < 0.3:
                    for _ in range(random.randint(1, 3)):
                        if self.deallocation_queue:
                            await self._deallocate_specific_block(self.deallocation_queue.popleft())
                
                await asyncio.sleep(0.01)
                
            except MemoryError:
                logger.warning(f"Memory allocation failed for fragmented block {block_id}")
                break
    
    async def _allocate_with_leaks(self, amount_mb: int):
        """Allocate memory with simulated leaks"""
        chunks_needed = max(1, amount_mb // self.config.allocation_size_mb)
        
        for i in range(chunks_needed):
            if not self.running:
                break
            
            block_id = f"leak_{self.allocation_counter}"
            self.allocation_counter += 1
            
            try:
                block = MemoryBlock(self.config.allocation_size_mb, block_id, "random")
                self.allocated_blocks[block_id] = block
                
                # Simulate leak by marking some blocks as "leaked"
                if random.random() < 0.2:  # 20% chance of "leak"
                    self.leaked_blocks.add(block_id)
                
                self.allocation_history.append({
                    'timestamp': time.time(),
                    'action': 'allocate',
                    'block_id': block_id,
                    'size_mb': self.config.allocation_size_mb,
                    'pattern': 'leak_simulation',
                    'leaked': block_id in self.leaked_blocks
                })
                
                await asyncio.sleep(0.02)
                
            except MemoryError:
                logger.warning(f"Memory allocation failed for leak block {block_id}")
                break
    
    async def _deallocate_memory(self, amount_mb: int):
        """Deallocate specified amount of memory"""
        deallocated_mb = 0
        blocks_to_remove = []
        
        # Prioritize non-leaked blocks for deallocation
        available_blocks = [
            (block_id, block) for block_id, block in self.allocated_blocks.items()
            if block_id not in self.leaked_blocks
        ]
        
        # Sort by allocation time (deallocate older blocks first)
        available_blocks.sort(key=lambda x: x[1].allocated_at)
        
        for block_id, block in available_blocks:
            if deallocated_mb >= amount_mb:
                break
            
            blocks_to_remove.append(block_id)
            deallocated_mb += block.size_mb
        
        # Remove selected blocks
        for block_id in blocks_to_remove:
            await self._deallocate_specific_block(block_id)
    
    async def _deallocate_specific_block(self, block_id: str):
        """Deallocate a specific memory block"""
        if block_id in self.allocated_blocks:
            block = self.allocated_blocks[block_id]
            del self.allocated_blocks[block_id]
            
            # Remove from leaked blocks if present
            self.leaked_blocks.discard(block_id)
            
            self.allocation_history.append({
                'timestamp': time.time(),
                'action': 'deallocate',
                'block_id': block_id,
                'size_mb': block.size_mb
            })
            
            # Force garbage collection if enabled
            if self.config.gc_pressure and random.random() < 0.1:
                gc.collect()
                self.gc_stats['collections'] += 1
    
    def _start_background_threads(self):
        """Start background threads for memory access and monitoring"""
        self.access_thread = threading.Thread(target=self._memory_access_worker, daemon=True)
        self.access_thread.start()
        
        if self.config.gc_pressure:
            self.gc_thread = threading.Thread(target=self._gc_pressure_worker, daemon=True)
            self.gc_thread.start()
        
        self.monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitor_thread.start()
    
    def _memory_access_worker(self):
        """Background worker for memory access patterns"""
        while self.running:
            try:
                if self.allocated_blocks:
                    # Randomly select blocks to access
                    block_ids = list(self.allocated_blocks.keys())
                    if block_ids:
                        # Access 10% of allocated blocks each cycle
                        access_count = max(1, len(block_ids) // 10)
                        selected_blocks = random.sample(block_ids, min(access_count, len(block_ids)))
                        
                        for block_id in selected_blocks:
                            if block_id in self.allocated_blocks and self.running:
                                block = self.allocated_blocks[block_id]
                                access_pattern = random.choice(["random", "sequential", "strided"])
                                block.access_data(access_pattern)
                
                time.sleep(0.5)  # Access every 500ms
                
            except Exception as e:
                logger.debug(f"Memory access worker error: {e}")
                time.sleep(1.0)
    
    def _gc_pressure_worker(self):
        """Background worker for garbage collection pressure"""
        while self.running:
            try:
                # Create temporary objects to increase GC pressure
                temp_objects = []
                for _ in range(100):
                    temp_objects.append({
                        'data': [random.random() for _ in range(1000)],
                        'timestamp': time.time(),
                        'id': random.randint(1, 1000000)
                    })
                
                # Force garbage collection
                collected = gc.collect()
                self.gc_stats['freed_objects'] += collected
                self.last_gc_time = time.time()
                
                # Clear temporary objects
                temp_objects.clear()
                
                time.sleep(2.0)  # GC pressure every 2 seconds
                
            except Exception as e:
                logger.debug(f"GC pressure worker error: {e}")
                time.sleep(5.0)
    
    def _monitoring_worker(self):
        """Background worker for performance monitoring"""
        while self.running:
            try:
                # Collect memory statistics
                process = psutil.Process()
                memory_info = process.memory_info()
                virtual_memory = psutil.virtual_memory()
                
                sample = {
                    'timestamp': time.time(),
                    'allocated_blocks': len(self.allocated_blocks),
                    'allocated_memory_mb': sum(block.size_mb for block in self.allocated_blocks.values()),
                    'process_memory_mb': memory_info.rss / (1024 * 1024),
                    'system_memory_percent': virtual_memory.percent,
                    'leaked_blocks': len(self.leaked_blocks),
                    'peak_memory_mb': self.peak_memory_mb,
                    'gc_collections': self.gc_stats['collections']
                }
                
                self.performance_samples.append(sample)
                
                # Keep only last 1000 samples
                if len(self.performance_samples) > 1000:
                    self.performance_samples = self.performance_samples[-1000:]
                
                # Adaptive control
                if self.config.adaptive and virtual_memory.percent > 90:
                    logger.warning("High system memory usage detected, reducing allocation target")
                    self.target_memory_mb = int(self.target_memory_mb * 0.8)
                
                time.sleep(5.0)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.debug(f"Monitoring worker error: {e}")
                time.sleep(10.0)
    
    async def stop(self):
        """Stop the memory load generator"""
        logger.info("Stopping memory load generator")
        self.running = False
        
        # Wait for threads to finish
        if self.access_thread and self.access_thread.is_alive():
            self.access_thread.join(timeout=5.0)
        if self.gc_thread and self.gc_thread.is_alive():
            self.gc_thread.join(timeout=5.0)
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        
        # Free all allocated memory
        self.allocated_blocks.clear()
        self.leaked_blocks.clear()
        self.deallocation_queue.clear()
        
        # Force garbage collection
        gc.collect()
        
        logger.info("Memory load generator stopped")
    
    async def reduce_intensity(self, factor: float):
        """Reduce memory load intensity by a factor"""
        self.target_memory_mb = int(self.target_memory_mb * factor)
        await self._adjust_memory_to_target()
        logger.info(f"Reduced memory load target to {self.target_memory_mb} MB")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the memory load generator"""
        return {
            'generator_id': 'memory_load_generator',
            'generator_type': 'memory',
            'status': 'running' if self.running else 'stopped',
            'current_memory_mb': self.current_memory_mb,
            'target_memory_mb': self.target_memory_mb,
            'peak_memory_mb': self.peak_memory_mb,
            'allocated_blocks': len(self.allocated_blocks),
            'leaked_blocks': len(self.leaked_blocks),
            'allocation_pattern': self.config.allocation_pattern,
            'metrics': {
                'performance_samples': len(self.performance_samples),
                'gc_collections': self.gc_stats['collections'],
                'gc_freed_objects': self.gc_stats['freed_objects'],
                'allocation_history_length': len(self.allocation_history),
                'fragmentation_level': self.config.fragmentation_level,
                'last_gc_time': self.last_gc_time
            }
        }
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get detailed memory statistics"""
        if not self.performance_samples:
            return {}
        
        recent_samples = self.performance_samples[-60:]  # Last 5 minutes
        
        allocated_memory = [s['allocated_memory_mb'] for s in recent_samples]
        process_memory = [s['process_memory_mb'] for s in recent_samples]
        system_memory = [s['system_memory_percent'] for s in recent_samples]
        
        return {
            'allocated_memory': {
                'current': allocated_memory[-1] if allocated_memory else 0,
                'average': np.mean(allocated_memory) if allocated_memory else 0,
                'max': np.max(allocated_memory) if allocated_memory else 0,
                'min': np.min(allocated_memory) if allocated_memory else 0
            },
            'process_memory': {
                'current': process_memory[-1] if process_memory else 0,
                'average': np.mean(process_memory) if process_memory else 0,
                'max': np.max(process_memory) if process_memory else 0,
                'min': np.min(process_memory) if process_memory else 0
            },
            'system_memory': {
                'current': system_memory[-1] if system_memory else 0,
                'average': np.mean(system_memory) if system_memory else 0,
                'max': np.max(system_memory) if system_memory else 0,
                'min': np.min(system_memory) if system_memory else 0
            },
            'allocation_pattern': self.config.allocation_pattern,
            'leak_simulation': len(self.leaked_blocks) > 0,
            'fragmentation_blocks': len(self.fragmentation_blocks)
        }


# Example usage
async def example_usage():
    """Example usage of MemoryLoadGenerator"""
    config = MemoryLoadConfiguration(
        max_memory_mb=512,
        allocation_size_mb=20,
        allocation_pattern="fragmented",
        fragmentation_level=0.4,
        gc_pressure=True,
        adaptive=True
    )
    
    generator = MemoryLoadGenerator(config)
    
    # Create a simple test pattern
    from patterns.pattern_engine import PatternEngine
    
    pattern_engine = PatternEngine()
    pattern = pattern_engine.generate_pattern("ramp_up", 120, 0.8)
    
    # Execute pattern
    await generator.execute_pattern(pattern)
    
    # Get status and statistics
    status = generator.get_status()
    stats = generator.get_memory_statistics()
    
    print(f"Memory Generator Status: {status}")
    print(f"Memory Statistics: {stats}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())