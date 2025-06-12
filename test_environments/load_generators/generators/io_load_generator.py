#!/usr/bin/env python3
"""
I/O Load Generator
==================

Advanced I/O load generation with various patterns including sequential/random access,
different file sizes, concurrent operations, and realistic I/O workloads.
"""

import asyncio
import os
import tempfile
import random
import time
import threading
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import aiofiles
import psutil
import numpy as np
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class IOLoadConfiguration:
    """Configuration for I/O load generation"""
    base_path: str = None  # Base directory for I/O operations
    max_file_size_mb: int = 100  # Maximum file size in MB
    min_file_size_mb: int = 1  # Minimum file size in MB
    concurrent_operations: int = 10  # Number of concurrent I/O operations
    io_pattern: str = "mixed"  # sequential, random, mixed, database, log_file
    read_write_ratio: float = 0.7  # 0.0 = all writes, 1.0 = all reads
    sync_operations: bool = False  # Use synchronous I/O operations
    direct_io: bool = False  # Use direct I/O (bypass cache)
    cleanup_files: bool = True  # Clean up created files after test

class IOOperation:
    """Represents an I/O operation"""
    def __init__(self, operation_type: str, file_path: str, size_bytes: int, 
                 offset: int = 0, data: bytes = None):
        self.operation_type = operation_type  # read, write, append, seek
        self.file_path = file_path
        self.size_bytes = size_bytes
        self.offset = offset
        self.data = data
        self.start_time = None
        self.end_time = None
        self.success = False
        self.error_message = None
    
    @property
    def duration_ms(self) -> float:
        """Get operation duration in milliseconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

class IOLoadGenerator:
    """
    Advanced I/O Load Generator
    
    Generates realistic I/O workloads with various patterns including
    database-like operations, log file simulation, and mixed workloads.
    """
    
    def __init__(self, config: Optional[IOLoadConfiguration] = None):
        self.config = config or IOLoadConfiguration()
        self.running = False
        self.current_load = 0.0
        self.target_load = 0.0
        
        # Set up base path
        if not self.config.base_path:
            self.config.base_path = tempfile.mkdtemp(prefix="io_load_test_")
        else:
            os.makedirs(self.config.base_path, exist_ok=True)
        
        # File management
        self.active_files: Dict[str, Dict[str, Any]] = {}
        self.operation_queue = asyncio.Queue()
        self.completed_operations: List[IOOperation] = []
        self.file_counter = 0
        
        # Performance monitoring
        self.performance_samples = []
        self.io_stats = {
            'total_operations': 0,
            'read_operations': 0,
            'write_operations': 0,
            'bytes_read': 0,
            'bytes_written': 0,
            'average_latency_ms': 0.0,
            'operations_per_second': 0.0
        }
        
        # Thread pool for synchronous operations
        self.executor = None
        self.worker_tasks = []
    
    async def execute_pattern(self, pattern):
        """Execute an I/O load pattern"""
        logger.info(f"Starting I/O load pattern: {pattern.name}")
        self.running = True
        
        try:
            # Initialize executor and workers
            self.executor = ThreadPoolExecutor(max_workers=self.config.concurrent_operations)
            
            # Start I/O workers
            for i in range(self.config.concurrent_operations):
                task = asyncio.create_task(self._io_worker(f"worker_{i}"))
                self.worker_tasks.append(task)
            
            # Start monitoring
            monitor_task = asyncio.create_task(self._monitor_performance())
            
            # Execute pattern points
            for point in pattern.points:
                if not self.running:
                    break
                
                # Update target load
                self.target_load = point.intensity
                
                # Generate I/O operations based on intensity
                await self._generate_io_operations(point.intensity)
                
                # Wait for next point
                if pattern.points.index(point) < len(pattern.points) - 1:
                    next_point = pattern.points[pattern.points.index(point) + 1]
                    wait_time = next_point.timestamp - point.timestamp
                    await asyncio.sleep(max(1.0, wait_time))
            
            # Stop monitoring
            monitor_task.cancel()
            
            logger.info(f"Completed I/O load pattern: {pattern.name}")
            
        except Exception as e:
            logger.error(f"I/O load pattern execution failed: {e}")
            raise
        finally:
            await self.stop()
    
    async def _generate_io_operations(self, intensity: float):
        """Generate I/O operations based on intensity"""
        # Calculate operations per second based on intensity
        base_ops_per_second = 50  # Base rate
        ops_per_second = int(base_ops_per_second * intensity)
        
        if ops_per_second == 0:
            return
        
        # Generate operations for this second
        operations_to_generate = max(1, ops_per_second)
        
        for _ in range(operations_to_generate):
            operation = await self._create_io_operation()
            if operation:
                await self.operation_queue.put(operation)
    
    async def _create_io_operation(self) -> Optional[IOOperation]:
        """Create an I/O operation based on configuration"""
        pattern = self.config.io_pattern
        
        if pattern == "sequential":
            return await self._create_sequential_operation()
        elif pattern == "random":
            return await self._create_random_operation()
        elif pattern == "mixed":
            return await self._create_mixed_operation()
        elif pattern == "database":
            return await self._create_database_operation()
        elif pattern == "log_file":
            return await self._create_log_file_operation()
        else:
            return await self._create_mixed_operation()
    
    async def _create_sequential_operation(self) -> IOOperation:
        """Create sequential I/O operation"""
        # Determine read vs write
        is_read = random.random() < self.config.read_write_ratio
        
        if is_read and self.active_files:
            # Sequential read from existing file
            file_path = random.choice(list(self.active_files.keys()))
            file_info = self.active_files[file_path]
            
            # Read sequential chunks
            chunk_size = random.randint(4096, 65536)  # 4KB to 64KB
            offset = file_info.get('read_position', 0)
            
            # Update read position
            file_info['read_position'] = offset + chunk_size
            
            return IOOperation("read", file_path, chunk_size, offset)
        else:
            # Sequential write (append to file)
            file_path = await self._get_or_create_file()
            chunk_size = random.randint(4096, 65536)
            data = self._generate_test_data(chunk_size)
            
            return IOOperation("append", file_path, chunk_size, data=data)
    
    async def _create_random_operation(self) -> IOOperation:
        """Create random I/O operation"""
        is_read = random.random() < self.config.read_write_ratio
        
        if is_read and self.active_files:
            # Random read from existing file
            file_path = random.choice(list(self.active_files.keys()))
            file_info = self.active_files[file_path]
            file_size = file_info.get('size', 0)
            
            if file_size > 0:
                chunk_size = random.randint(4096, 32768)
                max_offset = max(0, file_size - chunk_size)
                offset = random.randint(0, max_offset) if max_offset > 0 else 0
                
                return IOOperation("read", file_path, chunk_size, offset)
        
        # Random write to file
        file_path = await self._get_or_create_file()
        file_info = self.active_files[file_path]
        file_size = file_info.get('size', 0)
        
        chunk_size = random.randint(4096, 32768)
        
        if file_size > 0:
            # Random position write
            max_offset = max(0, file_size - chunk_size)
            offset = random.randint(0, max_offset) if max_offset > 0 else 0
        else:
            offset = 0
        
        data = self._generate_test_data(chunk_size)
        return IOOperation("write", file_path, chunk_size, offset, data)
    
    async def _create_mixed_operation(self) -> IOOperation:
        """Create mixed I/O operation (combination of patterns)"""
        operation_type = random.choice([
            "sequential_read", "sequential_write", 
            "random_read", "random_write",
            "append", "large_read", "large_write"
        ])
        
        if operation_type == "sequential_read":
            return await self._create_sequential_operation()
        elif operation_type == "random_read":
            return await self._create_random_operation()
        elif operation_type == "large_read":
            return await self._create_large_io_operation("read")
        elif operation_type == "large_write":
            return await self._create_large_io_operation("write")
        else:
            return await self._create_sequential_operation()
    
    async def _create_database_operation(self) -> IOOperation:
        """Create database-like I/O operation"""
        operations = ["index_read", "table_scan", "update", "insert", "log_write"]
        operation_type = random.choice(operations)
        
        if operation_type == "index_read":
            # Small random reads (simulating index lookups)
            file_path = await self._get_or_create_file("index")
            chunk_size = random.randint(512, 4096)  # Small reads
            file_info = self.active_files[file_path]
            file_size = file_info.get('size', 0)
            
            if file_size > 0:
                offset = random.randint(0, max(0, file_size - chunk_size))
            else:
                offset = 0
            
            return IOOperation("read", file_path, chunk_size, offset)
            
        elif operation_type == "table_scan":
            # Large sequential reads (table scans)
            file_path = await self._get_or_create_file("table")
            chunk_size = random.randint(32768, 131072)  # 32KB to 128KB
            file_info = self.active_files[file_path]
            offset = file_info.get('scan_position', 0)
            
            # Update scan position
            file_info['scan_position'] = offset + chunk_size
            
            return IOOperation("read", file_path, chunk_size, offset)
            
        elif operation_type in ["update", "insert"]:
            # Write operations
            file_path = await self._get_or_create_file("table")
            chunk_size = random.randint(1024, 8192)  # 1KB to 8KB
            data = self._generate_test_data(chunk_size)
            
            if operation_type == "update":
                # Random position update
                file_info = self.active_files[file_path]
                file_size = file_info.get('size', 0)
                offset = random.randint(0, max(0, file_size - chunk_size)) if file_size > 0 else 0
                return IOOperation("write", file_path, chunk_size, offset, data)
            else:
                # Append (insert)
                return IOOperation("append", file_path, chunk_size, data=data)
                
        else:  # log_write
            # Sequential log writes
            file_path = await self._get_or_create_file("log")
            chunk_size = random.randint(256, 2048)  # Small log entries
            data = self._generate_log_data(chunk_size)
            
            return IOOperation("append", file_path, chunk_size, data=data)
    
    async def _create_log_file_operation(self) -> IOOperation:
        """Create log file I/O operation"""
        # Log files are mostly sequential appends with occasional reads
        if random.random() < 0.9:  # 90% writes
            file_path = await self._get_or_create_file("log")
            chunk_size = random.randint(128, 1024)  # Small log entries
            data = self._generate_log_data(chunk_size)
            
            return IOOperation("append", file_path, chunk_size, data=data)
        else:
            # Occasional log file read (e.g., log rotation, analysis)
            if self.active_files:
                file_path = random.choice([f for f in self.active_files.keys() if "log" in f])
                if file_path:
                    chunk_size = random.randint(4096, 16384)
                    file_info = self.active_files[file_path]
                    file_size = file_info.get('size', 0)
                    offset = max(0, file_size - chunk_size) if file_size > chunk_size else 0
                    
                    return IOOperation("read", file_path, chunk_size, offset)
            
            # Fallback to write
            return await self._create_log_file_operation()
    
    async def _create_large_io_operation(self, operation_type: str) -> IOOperation:
        """Create large I/O operation"""
        file_path = await self._get_or_create_file("large")
        chunk_size = random.randint(1024*1024, 10*1024*1024)  # 1MB to 10MB
        
        if operation_type == "read" and self.active_files.get(file_path, {}).get('size', 0) > 0:
            file_info = self.active_files[file_path]
            file_size = file_info['size']
            offset = random.randint(0, max(0, file_size - chunk_size)) if file_size > chunk_size else 0
            return IOOperation("read", file_path, chunk_size, offset)
        else:
            data = self._generate_test_data(chunk_size)
            return IOOperation("write", file_path, chunk_size, 0, data)
    
    async def _get_or_create_file(self, file_type: str = "data") -> str:
        """Get existing file or create new one"""
        # Look for existing files of this type
        existing_files = [f for f in self.active_files.keys() if file_type in f]
        
        # Randomly decide to use existing file or create new one
        if existing_files and random.random() < 0.7:  # 70% chance to reuse
            return random.choice(existing_files)
        
        # Create new file
        self.file_counter += 1
        filename = f"{file_type}_file_{self.file_counter}.dat"
        file_path = os.path.join(self.config.base_path, filename)
        
        # Initialize file info
        self.active_files[file_path] = {
            'size': 0,
            'created_at': time.time(),
            'read_position': 0,
            'scan_position': 0,
            'type': file_type
        }
        
        return file_path
    
    def _generate_test_data(self, size_bytes: int) -> bytes:
        """Generate test data of specified size"""
        # Generate random data with some patterns for realism
        if size_bytes < 1024:
            # Small data - mostly random
            return os.urandom(size_bytes)
        else:
            # Larger data - mix of patterns and random
            pattern_data = b"TEST_DATA_PATTERN_" * (size_bytes // 18)
            random_data = os.urandom(size_bytes - len(pattern_data))
            return pattern_data + random_data
    
    def _generate_log_data(self, size_bytes: int) -> bytes:
        """Generate realistic log data"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_levels = ["INFO", "WARN", "ERROR", "DEBUG"]
        log_level = random.choice(log_levels)
        
        messages = [
            "User authentication successful",
            "Database query executed",
            "Cache miss for key",
            "HTTP request processed",
            "Service health check passed",
            "Configuration updated",
            "Memory usage at 75%",
            "Background task completed"
        ]
        
        message = random.choice(messages)
        log_entry = f"{timestamp} [{log_level}] {message} - id:{random.randint(1000, 9999)}\n"
        
        # Pad to requested size
        while len(log_entry.encode()) < size_bytes:
            log_entry += f"Additional data {random.randint(1, 1000)} "
        
        return log_entry.encode()[:size_bytes]
    
    async def _io_worker(self, worker_id: str):
        """I/O worker that processes operations from the queue"""
        logger.debug(f"Starting I/O worker: {worker_id}")
        
        while self.running:
            try:
                # Get operation from queue
                operation = await asyncio.wait_for(
                    self.operation_queue.get(), 
                    timeout=1.0
                )
                
                # Execute operation
                await self._execute_operation(operation)
                
                # Mark task as done
                self.operation_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"I/O worker {worker_id} error: {e}")
                await asyncio.sleep(1.0)
        
        logger.debug(f"I/O worker {worker_id} stopped")
    
    async def _execute_operation(self, operation: IOOperation):
        """Execute a single I/O operation"""
        operation.start_time = time.time()
        
        try:
            if operation.operation_type == "read":
                await self._execute_read(operation)
            elif operation.operation_type == "write":
                await self._execute_write(operation)
            elif operation.operation_type == "append":
                await self._execute_append(operation)
            elif operation.operation_type == "seek":
                await self._execute_seek(operation)
            
            operation.success = True
            
        except Exception as e:
            operation.error_message = str(e)
            logger.debug(f"I/O operation failed: {operation.operation_type} on {operation.file_path}: {e}")
        
        finally:
            operation.end_time = time.time()
            self.completed_operations.append(operation)
            
            # Update statistics
            self._update_io_stats(operation)
            
            # Keep only last 1000 operations
            if len(self.completed_operations) > 1000:
                self.completed_operations = self.completed_operations[-1000:]
    
    async def _execute_read(self, operation: IOOperation):
        """Execute read operation"""
        try:
            async with aiofiles.open(operation.file_path, 'rb') as f:
                await f.seek(operation.offset)
                data = await f.read(operation.size_bytes)
                
                # Simulate data processing
                if data:
                    # Simple checksum calculation to simulate work
                    checksum = sum(data) % 256
                
        except FileNotFoundError:
            # File doesn't exist, create it first
            await self._create_empty_file(operation.file_path)
            raise
    
    async def _execute_write(self, operation: IOOperation):
        """Execute write operation"""
        async with aiofiles.open(operation.file_path, 'r+b') as f:
            await f.seek(operation.offset)
            await f.write(operation.data)
            
            if self.config.sync_operations:
                await f.fsync()
        
        # Update file size
        self._update_file_size(operation.file_path)
    
    async def _execute_append(self, operation: IOOperation):
        """Execute append operation"""
        async with aiofiles.open(operation.file_path, 'ab') as f:
            await f.write(operation.data)
            
            if self.config.sync_operations:
                await f.fsync()
        
        # Update file size
        self._update_file_size(operation.file_path)
    
    async def _execute_seek(self, operation: IOOperation):
        """Execute seek operation"""
        async with aiofiles.open(operation.file_path, 'rb') as f:
            await f.seek(operation.offset)
    
    async def _create_empty_file(self, file_path: str):
        """Create an empty file"""
        async with aiofiles.open(file_path, 'wb') as f:
            pass
        
        # Initialize file info if not exists
        if file_path not in self.active_files:
            self.active_files[file_path] = {
                'size': 0,
                'created_at': time.time(),
                'read_position': 0,
                'scan_position': 0,
                'type': 'data'
            }
    
    def _update_file_size(self, file_path: str):
        """Update file size information"""
        try:
            size = os.path.getsize(file_path)
            if file_path in self.active_files:
                self.active_files[file_path]['size'] = size
        except OSError:
            pass
    
    def _update_io_stats(self, operation: IOOperation):
        """Update I/O statistics"""
        self.io_stats['total_operations'] += 1
        
        if operation.operation_type == "read":
            self.io_stats['read_operations'] += 1
            self.io_stats['bytes_read'] += operation.size_bytes
        else:
            self.io_stats['write_operations'] += 1
            self.io_stats['bytes_written'] += operation.size_bytes
        
        # Update average latency
        if operation.success and operation.duration_ms > 0:
            current_avg = self.io_stats['average_latency_ms']
            total_ops = self.io_stats['total_operations']
            
            self.io_stats['average_latency_ms'] = (
                (current_avg * (total_ops - 1) + operation.duration_ms) / total_ops
            )
    
    async def _monitor_performance(self):
        """Monitor I/O performance"""
        last_stats_time = time.time()
        last_operation_count = 0
        
        while self.running:
            try:
                current_time = time.time()
                current_operations = self.io_stats['total_operations']
                
                # Calculate operations per second
                time_diff = current_time - last_stats_time
                if time_diff >= 1.0:  # Update every second
                    ops_diff = current_operations - last_operation_count
                    self.io_stats['operations_per_second'] = ops_diff / time_diff
                    
                    last_stats_time = current_time
                    last_operation_count = current_operations
                
                # Collect system I/O statistics
                disk_io = psutil.disk_io_counters()
                
                sample = {
                    'timestamp': current_time,
                    'operations_per_second': self.io_stats['operations_per_second'],
                    'average_latency_ms': self.io_stats['average_latency_ms'],
                    'active_files': len(self.active_files),
                    'queue_size': self.operation_queue.qsize(),
                    'total_operations': self.io_stats['total_operations'],
                    'bytes_read': self.io_stats['bytes_read'],
                    'bytes_written': self.io_stats['bytes_written']
                }
                
                if disk_io:
                    sample.update({
                        'system_read_bytes': disk_io.read_bytes,
                        'system_write_bytes': disk_io.write_bytes,
                        'system_read_count': disk_io.read_count,
                        'system_write_count': disk_io.write_count
                    })
                
                self.performance_samples.append(sample)
                
                # Keep only last 1000 samples
                if len(self.performance_samples) > 1000:
                    self.performance_samples = self.performance_samples[-1000:]
                
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(5.0)
    
    async def stop(self):
        """Stop the I/O load generator"""
        logger.info("Stopping I/O load generator")
        self.running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # Shutdown executor
        if self.executor:
            self.executor.shutdown(wait=True)
        
        # Clean up files if requested
        if self.config.cleanup_files:
            await self._cleanup_files()
        
        logger.info("I/O load generator stopped")
    
    async def _cleanup_files(self):
        """Clean up created files"""
        try:
            for file_path in list(self.active_files.keys()):
                if os.path.exists(file_path):
                    os.remove(file_path)
            
            # Remove base directory if empty
            if os.path.exists(self.config.base_path):
                try:
                    os.rmdir(self.config.base_path)
                except OSError:
                    pass  # Directory not empty
            
            logger.info(f"Cleaned up {len(self.active_files)} test files")
            
        except Exception as e:
            logger.error(f"File cleanup error: {e}")
    
    async def reduce_intensity(self, factor: float):
        """Reduce I/O load intensity by a factor"""
        self.target_load = max(0.0, self.target_load * factor)
        logger.info(f"Reduced I/O load intensity to {self.target_load:.2f}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the I/O load generator"""
        return {
            'generator_id': 'io_load_generator',
            'generator_type': 'io',
            'status': 'running' if self.running else 'stopped',
            'current_load': self.current_load,
            'target_load': self.target_load,
            'active_files': len(self.active_files),
            'queue_size': self.operation_queue.qsize() if self.operation_queue else 0,
            'io_pattern': self.config.io_pattern,
            'concurrent_operations': self.config.concurrent_operations,
            'metrics': self.io_stats.copy()
        }
    
    def get_io_statistics(self) -> Dict[str, Any]:
        """Get detailed I/O statistics"""
        if not self.performance_samples:
            return {}
        
        recent_samples = self.performance_samples[-60:]  # Last minute
        
        ops_per_second = [s['operations_per_second'] for s in recent_samples if 'operations_per_second' in s]
        latencies = [s['average_latency_ms'] for s in recent_samples if 'average_latency_ms' in s]
        
        return {
            'operations_per_second': {
                'current': ops_per_second[-1] if ops_per_second else 0,
                'average': np.mean(ops_per_second) if ops_per_second else 0,
                'max': np.max(ops_per_second) if ops_per_second else 0
            },
            'latency_ms': {
                'current': latencies[-1] if latencies else 0,
                'average': np.mean(latencies) if latencies else 0,
                'max': np.max(latencies) if latencies else 0
            },
            'io_pattern': self.config.io_pattern,
            'read_write_ratio': self.config.read_write_ratio,
            'file_statistics': {
                'active_files': len(self.active_files),
                'total_size_mb': sum(info.get('size', 0) for info in self.active_files.values()) / (1024 * 1024),
                'file_types': list(set(info.get('type', 'unknown') for info in self.active_files.values()))
            }
        }


# Example usage
async def example_usage():
    """Example usage of IOLoadGenerator"""
    config = IOLoadConfiguration(
        max_file_size_mb=50,
        concurrent_operations=5,
        io_pattern="database",
        read_write_ratio=0.8,
        cleanup_files=True
    )
    
    generator = IOLoadGenerator(config)
    
    # Create a simple test pattern
    from patterns.pattern_engine import PatternEngine
    
    pattern_engine = PatternEngine()
    pattern = pattern_engine.generate_pattern("burst", 120, 0.7)
    
    # Execute pattern
    await generator.execute_pattern(pattern)
    
    # Get status and statistics
    status = generator.get_status()
    stats = generator.get_io_statistics()
    
    print(f"I/O Generator Status: {status}")
    print(f"I/O Statistics: {stats}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())