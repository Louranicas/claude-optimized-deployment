"""
Advanced Document Processing Optimizations

SYNTHEX Agent 5 - Additional Performance Optimizations
Adaptive processing, connection pooling, and advanced memory management
"""

import asyncio
import time
import weakref
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Tuple, Set
from pathlib import Path
import threading
import queue
import psutil
from collections import defaultdict, deque
import hashlib
import mmap
import os

from .document_processor import DocumentProcessor, ParsedDocument, DocumentMetadata
from .object_pool import ObjectPool, PooledObject
from .lru_cache import LRUCache, CacheConfig

__all__ = [
    "AdaptiveProcessor",
    "ConnectionPool", 
    "FileWatcher",
    "DocumentBatch",
    "MemoryManager",
    "ProcessingStrategy",
    "OptimizedDocumentManager"
]


@dataclass
class ProcessingProfile:
    """Performance profile for adaptive processing"""
    avg_processing_time_ms: float = 0
    avg_memory_usage_mb: float = 0
    success_rate: float = 1.0
    preferred_chunk_size: int = 1000
    preferred_worker_count: int = 2
    last_updated: float = 0
    sample_count: int = 0


class ProcessingStrategy(ABC):
    """Abstract base class for processing strategies"""
    
    @abstractmethod
    async def process(self, documents: List[Path], options: Dict[str, Any]) -> List[ParsedDocument]:
        """Process documents using this strategy"""
        pass
    
    @abstractmethod
    def estimate_resources(self, documents: List[Path]) -> Tuple[float, float]:
        """Estimate required time and memory"""
        pass


class SequentialStrategy(ProcessingStrategy):
    """Sequential document processing strategy"""
    
    def __init__(self, processor: DocumentProcessor):
        self.processor = processor
    
    async def process(self, documents: List[Path], options: Dict[str, Any]) -> List[ParsedDocument]:
        """Process documents sequentially"""
        results = []
        for doc_path in documents:
            try:
                doc = await self.processor.process_document(doc_path, options)
                results.append(doc)
            except Exception as e:
                print(f"Error processing {doc_path}: {e}")
                # Create minimal document for failed processing
                metadata = DocumentMetadata(
                    path=str(doc_path),
                    size_bytes=0,
                    hash="",
                    created_at=time.time(),
                    modified_at=time.time()
                )
                results.append(ParsedDocument(metadata=metadata, content=""))
        return results
    
    def estimate_resources(self, documents: List[Path]) -> Tuple[float, float]:
        """Estimate resources for sequential processing"""
        total_size = sum(doc.stat().st_size for doc in documents if doc.exists())
        # Rough estimates: 1MB/s processing, 2x memory overhead
        estimated_time = total_size / (1024 * 1024)  # seconds
        estimated_memory = (total_size * 2) / (1024 * 1024)  # MB
        return estimated_time, estimated_memory


class ParallelStrategy(ProcessingStrategy):
    """Parallel document processing strategy"""
    
    def __init__(self, processor: DocumentProcessor, worker_count: int = 4):
        self.processor = processor
        self.worker_count = worker_count
    
    async def process(self, documents: List[Path], options: Dict[str, Any]) -> List[ParsedDocument]:
        """Process documents in parallel"""
        semaphore = asyncio.Semaphore(self.worker_count)
        
        async def process_single(doc_path: Path) -> ParsedDocument:
            async with semaphore:
                try:
                    return await self.processor.process_document(doc_path, options)
                except Exception as e:
                    print(f"Error processing {doc_path}: {e}")
                    metadata = DocumentMetadata(
                        path=str(doc_path),
                        size_bytes=0,
                        hash="",
                        created_at=time.time(),
                        modified_at=time.time()
                    )
                    return ParsedDocument(metadata=metadata, content="")
        
        tasks = [process_single(doc_path) for doc_path in documents]
        return await asyncio.gather(*tasks)
    
    def estimate_resources(self, documents: List[Path]) -> Tuple[float, float]:
        """Estimate resources for parallel processing"""
        total_size = sum(doc.stat().st_size for doc in documents if doc.exists())
        # Parallel processing: divide time by workers, multiply memory by workers
        estimated_time = total_size / (1024 * 1024 * self.worker_count)
        estimated_memory = (total_size * 2 * self.worker_count) / (1024 * 1024)
        return estimated_time, estimated_memory


class AdaptiveProcessor:
    """
    Adaptive document processor that selects optimal processing strategies
    based on document characteristics and system resources
    """
    
    def __init__(self, base_processor: DocumentProcessor):
        self.base_processor = base_processor
        self.profiles: Dict[str, ProcessingProfile] = defaultdict(ProcessingProfile)
        self.strategies: Dict[str, ProcessingStrategy] = {
            "sequential": SequentialStrategy(base_processor),
            "parallel_2": ParallelStrategy(base_processor, 2),
            "parallel_4": ParallelStrategy(base_processor, 4),
            "parallel_8": ParallelStrategy(base_processor, 8),
        }
        self.learning_enabled = True
    
    def _get_profile_key(self, documents: List[Path]) -> str:
        """Generate profile key based on document characteristics"""
        total_size = sum(doc.stat().st_size for doc in documents if doc.exists())
        doc_count = len(documents)
        avg_size = total_size / doc_count if doc_count > 0 else 0
        
        # Categorize based on size and count
        if doc_count == 1:
            if avg_size < 1024 * 1024:  # < 1MB
                return "single_small"
            elif avg_size < 10 * 1024 * 1024:  # < 10MB
                return "single_medium"
            else:
                return "single_large"
        elif doc_count < 10:
            return "batch_small"
        elif doc_count < 50:
            return "batch_medium"
        else:
            return "batch_large"
    
    def _select_strategy(self, documents: List[Path]) -> str:
        """Select optimal processing strategy"""
        profile_key = self._get_profile_key(documents)
        profile = self.profiles[profile_key]
        
        # Check system resources
        memory = psutil.virtual_memory()
        cpu_count = psutil.cpu_count()
        
        # If we have performance data, use it
        if profile.sample_count > 0:
            # Use learned preferences
            if memory.available > 2 * 1024 * 1024 * 1024:  # > 2GB available
                if profile.preferred_worker_count <= cpu_count:
                    return f"parallel_{profile.preferred_worker_count}"
            return "sequential"
        
        # Default strategy selection based on heuristics
        doc_count = len(documents)
        total_size = sum(doc.stat().st_size for doc in documents if doc.exists())
        
        if doc_count == 1 or total_size < 10 * 1024 * 1024:  # Small workload
            return "sequential"
        elif memory.available > 1024 * 1024 * 1024 and cpu_count >= 4:  # Good resources
            return "parallel_4"
        elif cpu_count >= 2:
            return "parallel_2"
        else:
            return "sequential"
    
    async def process_documents(
        self, 
        documents: List[Path], 
        options: Optional[Dict[str, Any]] = None
    ) -> List[ParsedDocument]:
        """Process documents using adaptive strategy selection"""
        options = options or {}
        profile_key = self._get_profile_key(documents)
        strategy_name = self._select_strategy(documents)
        strategy = self.strategies[strategy_name]
        
        # Measure performance if learning is enabled
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            results = await strategy.process(documents, options)
            success = True
        except Exception as e:
            print(f"Strategy {strategy_name} failed: {e}")
            # Fallback to sequential
            results = await self.strategies["sequential"].process(documents, options)
            success = False
        
        # Update profile if learning is enabled
        if self.learning_enabled:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            processing_time = (end_time - start_time) * 1000  # ms
            memory_used = end_memory - start_memory
            
            profile = self.profiles[profile_key]
            
            # Update running averages
            if profile.sample_count == 0:
                profile.avg_processing_time_ms = processing_time
                profile.avg_memory_usage_mb = memory_used
                profile.success_rate = 1.0 if success else 0.0
            else:
                # Exponential moving average
                alpha = 0.1
                profile.avg_processing_time_ms = (
                    alpha * processing_time + 
                    (1 - alpha) * profile.avg_processing_time_ms
                )
                profile.avg_memory_usage_mb = (
                    alpha * memory_used + 
                    (1 - alpha) * profile.avg_memory_usage_mb
                )
                profile.success_rate = (
                    alpha * (1.0 if success else 0.0) + 
                    (1 - alpha) * profile.success_rate
                )
            
            profile.sample_count += 1
            profile.last_updated = time.time()
            
            # Update preferred settings based on performance
            if success and processing_time < profile.avg_processing_time_ms:
                if "parallel" in strategy_name:
                    worker_count = int(strategy_name.split("_")[1])
                    profile.preferred_worker_count = worker_count
        
        return results
    
    def get_profile_stats(self) -> Dict[str, Any]:
        """Get performance profile statistics"""
        stats = {}
        for key, profile in self.profiles.items():
            stats[key] = {
                "avg_time_ms": profile.avg_processing_time_ms,
                "avg_memory_mb": profile.avg_memory_usage_mb,
                "success_rate": profile.success_rate,
                "preferred_workers": profile.preferred_worker_count,
                "sample_count": profile.sample_count
            }
        return stats


class ConnectionPool:
    """
    Connection pool for file operations and external resources
    """
    
    def __init__(self, max_connections: int = 50):
        self.max_connections = max_connections
        self._pool = queue.Queue(maxsize=max_connections)
        self._active_connections = set()
        self._lock = threading.Lock()
        
        # Pre-populate pool
        for _ in range(min(10, max_connections)):
            self._pool.put(self._create_connection())
    
    def _create_connection(self) -> Any:
        """Create a new connection (placeholder for actual implementation)"""
        return {"id": id(self), "created_at": time.time()}
    
    def acquire(self) -> Any:
        """Acquire a connection from the pool"""
        try:
            connection = self._pool.get_nowait()
        except queue.Empty:
            # Pool is empty, create new connection if under limit
            with self._lock:
                if len(self._active_connections) < self.max_connections:
                    connection = self._create_connection()
                else:
                    # Wait for a connection to become available
                    connection = self._pool.get()
        
        with self._lock:
            self._active_connections.add(id(connection))
        
        return connection
    
    def release(self, connection: Any):
        """Release a connection back to the pool"""
        with self._lock:
            self._active_connections.discard(id(connection))
        
        try:
            self._pool.put_nowait(connection)
        except queue.Full:
            # Pool is full, discard connection
            pass
    
    def get_stats(self) -> Dict[str, int]:
        """Get connection pool statistics"""
        with self._lock:
            return {
                "total_connections": len(self._active_connections) + self._pool.qsize(),
                "active_connections": len(self._active_connections),
                "available_connections": self._pool.qsize(),
                "max_connections": self.max_connections
            }


class FileWatcher:
    """
    File system watcher for automatic document processing
    """
    
    def __init__(self, processor: AdaptiveProcessor):
        self.processor = processor
        self.watched_dirs: Set[Path] = set()
        self.file_queue = asyncio.Queue()
        self.processing_task: Optional[asyncio.Task] = None
        self.watching = False
    
    def add_watch_directory(self, directory: Path, pattern: str = "*.txt"):
        """Add directory to watch list"""
        self.watched_dirs.add((directory, pattern))
    
    async def start_watching(self):
        """Start file watching and processing"""
        self.watching = True
        self.processing_task = asyncio.create_task(self._process_queue())
        
        # Simulate file watching (replace with actual file system events)
        asyncio.create_task(self._watch_files())
    
    async def stop_watching(self):
        """Stop file watching"""
        self.watching = False
        if self.processing_task:
            self.processing_task.cancel()
    
    async def _watch_files(self):
        """Monitor directories for file changes"""
        known_files = set()
        
        while self.watching:
            for directory, pattern in self.watched_dirs:
                if directory.exists():
                    for file_path in directory.glob(pattern):
                        file_key = (file_path, file_path.stat().st_mtime)
                        if file_key not in known_files:
                            known_files.add(file_key)
                            await self.file_queue.put(file_path)
            
            await asyncio.sleep(1)  # Check every second
    
    async def _process_queue(self):
        """Process queued files"""
        batch = []
        batch_timeout = 5.0  # seconds
        last_batch_time = time.time()
        
        while self.watching:
            try:
                # Wait for file or timeout
                file_path = await asyncio.wait_for(
                    self.file_queue.get(), 
                    timeout=1.0
                )
                batch.append(file_path)
                
                # Process batch if it's full or timeout reached
                current_time = time.time()
                if (len(batch) >= 10 or 
                    current_time - last_batch_time > batch_timeout):
                    
                    if batch:
                        await self._process_batch(batch)
                        batch.clear()
                        last_batch_time = current_time
                
            except asyncio.TimeoutError:
                # Process any pending files
                if batch:
                    await self._process_batch(batch)
                    batch.clear()
                    last_batch_time = time.time()
    
    async def _process_batch(self, file_paths: List[Path]):
        """Process a batch of files"""
        try:
            results = await self.processor.process_documents(file_paths)
            print(f"Processed batch of {len(file_paths)} files")
        except Exception as e:
            print(f"Error processing batch: {e}")


@dataclass
class DocumentBatch:
    """Batch of documents for efficient processing"""
    documents: List[Path] = field(default_factory=list)
    priority: int = 0
    created_at: float = field(default_factory=time.time)
    options: Dict[str, Any] = field(default_factory=dict)
    
    def add_document(self, doc_path: Path):
        """Add document to batch"""
        self.documents.append(doc_path)
    
    def get_total_size(self) -> int:
        """Get total size of all documents in batch"""
        return sum(doc.stat().st_size for doc in self.documents if doc.exists())
    
    def is_ready(self, max_size_mb: int = 100, max_age_seconds: int = 30) -> bool:
        """Check if batch is ready for processing"""
        total_size_mb = self.get_total_size() / (1024 * 1024)
        age_seconds = time.time() - self.created_at
        
        return (total_size_mb >= max_size_mb or 
                age_seconds >= max_age_seconds or 
                len(self.documents) >= 50)


class MemoryManager:
    """
    Advanced memory management for document processing
    """
    
    def __init__(self, max_memory_mb: int = 1024):
        self.max_memory_mb = max_memory_mb
        self.document_cache = weakref.WeakValueDictionary()
        self.memory_pressure_threshold = 0.8
        self.cleanup_callbacks: List[Callable[[], None]] = []
    
    def register_cleanup_callback(self, callback: Callable[[], None]):
        """Register callback for memory pressure cleanup"""
        self.cleanup_callbacks.append(callback)
    
    def check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure"""
        try:
            memory = psutil.virtual_memory()
            process_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            # Check both system and process memory
            system_pressure = memory.percent / 100 > self.memory_pressure_threshold
            process_pressure = process_memory > self.max_memory_mb
            
            return system_pressure or process_pressure
        except Exception:
            return False
    
    async def cleanup_memory(self, force: bool = False):
        """Perform memory cleanup"""
        if not force and not self.check_memory_pressure():
            return
        
        # Run cleanup callbacks
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                print(f"Cleanup callback failed: {e}")
        
        # Clear weak references
        self.document_cache.clear()
        
        # Force garbage collection
        import gc
        gc.collect()
    
    def get_memory_stats(self) -> Dict[str, float]:
        """Get current memory statistics"""
        try:
            memory = psutil.virtual_memory()
            process = psutil.Process()
            
            return {
                "system_total_mb": memory.total / 1024 / 1024,
                "system_available_mb": memory.available / 1024 / 1024,
                "system_used_percent": memory.percent,
                "process_rss_mb": process.memory_info().rss / 1024 / 1024,
                "process_vms_mb": process.memory_info().vms / 1024 / 1024,
                "cached_documents": len(self.document_cache)
            }
        except Exception:
            return {}


class OptimizedDocumentManager:
    """
    High-level document manager with all optimizations
    """
    
    def __init__(
        self,
        cache_size: int = 100,
        max_memory_mb: int = 1024,
        enable_adaptive: bool = True,
        enable_watching: bool = False
    ):
        # Create base processor
        from .document_processor import create_optimized_processor
        self.processor, self.parallel_processor = create_optimized_processor(
            cache_size=cache_size
        )
        
        # Initialize optimization components
        self.memory_manager = MemoryManager(max_memory_mb)
        self.connection_pool = ConnectionPool()
        
        if enable_adaptive:
            self.adaptive_processor = AdaptiveProcessor(self.processor)
        else:
            self.adaptive_processor = None
        
        if enable_watching:
            self.file_watcher = FileWatcher(
                self.adaptive_processor or self.processor
            )
        else:
            self.file_watcher = None
        
        # Document batching
        self.pending_batches: List[DocumentBatch] = []
        self.batch_processor_task: Optional[asyncio.Task] = None
        
        # Register memory cleanup
        self.memory_manager.register_cleanup_callback(
            lambda: self.processor.cache.cache.clear()
        )
    
    async def process_document(
        self, 
        path: Path, 
        options: Optional[Dict[str, Any]] = None
    ) -> ParsedDocument:
        """Process single document with all optimizations"""
        # Check memory pressure
        if self.memory_manager.check_memory_pressure():
            await self.memory_manager.cleanup_memory()
        
        # Use adaptive processor if available
        if self.adaptive_processor:
            results = await self.adaptive_processor.process_documents([path], options)
            return results[0] if results else None
        else:
            return await self.processor.process_document(path, options)
    
    async def process_documents_batch(
        self,
        paths: List[Path],
        options: Optional[Dict[str, Any]] = None
    ) -> List[ParsedDocument]:
        """Process multiple documents optimally"""
        # Use adaptive processor if available
        if self.adaptive_processor:
            return await self.adaptive_processor.process_documents(paths, options)
        else:
            return await self.parallel_processor.process_documents(paths, options)
    
    def add_to_batch(
        self,
        path: Path,
        priority: int = 0,
        options: Optional[Dict[str, Any]] = None
    ):
        """Add document to processing batch"""
        # Find or create appropriate batch
        batch = None
        for b in self.pending_batches:
            if b.priority == priority and not b.is_ready():
                batch = b
                break
        
        if not batch:
            batch = DocumentBatch(priority=priority, options=options or {})
            self.pending_batches.append(batch)
        
        batch.add_document(path)
        
        # Start batch processor if not running
        if not self.batch_processor_task:
            self.batch_processor_task = asyncio.create_task(self._process_batches())
    
    async def _process_batches(self):
        """Process document batches automatically"""
        while True:
            ready_batches = [b for b in self.pending_batches if b.is_ready()]
            
            for batch in ready_batches:
                try:
                    await self.process_documents_batch(
                        batch.documents, 
                        batch.options
                    )
                    self.pending_batches.remove(batch)
                except Exception as e:
                    print(f"Error processing batch: {e}")
            
            await asyncio.sleep(1)
    
    async def start_watching(self, directories: List[Tuple[Path, str]]):
        """Start watching directories for new documents"""
        if not self.file_watcher:
            return
        
        for directory, pattern in directories:
            self.file_watcher.add_watch_directory(directory, pattern)
        
        await self.file_watcher.start_watching()
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        status = {
            "memory": self.memory_manager.get_memory_stats(),
            "connections": self.connection_pool.get_stats(),
            "cache": self.processor.cache.get_stats().to_dict(),
            "pending_batches": len(self.pending_batches),
            "documents_in_batches": sum(len(b.documents) for b in self.pending_batches)
        }
        
        if self.adaptive_processor:
            status["adaptive_profiles"] = self.adaptive_processor.get_profile_stats()
        
        return status
    
    async def cleanup(self):
        """Clean up all resources"""
        if self.file_watcher:
            await self.file_watcher.stop_watching()
        
        if self.batch_processor_task:
            self.batch_processor_task.cancel()
        
        await self.memory_manager.cleanup_memory(force=True)


# Example usage
async def demo_optimized_processing():
    """Demonstrate optimized document processing"""
    manager = OptimizedDocumentManager(
        cache_size=50,
        max_memory_mb=512,
        enable_adaptive=True,
        enable_watching=False
    )
    
    # Create some test documents
    import tempfile
    test_dir = Path(tempfile.mkdtemp())
    
    # Create test files
    for i in range(5):
        test_file = test_dir / f"test_{i}.txt"
        test_file.write_text(f"Test document {i}
" * 1000)
    
    # Process documents
    test_files = list(test_dir.glob("*.txt"))
    
    print("Processing documents with optimizations...")
    start_time = time.time()
    
    results = await manager.process_documents_batch(test_files)
    
    end_time = time.time()
    
    print(f"Processed {len(results)} documents in {end_time - start_time:.2f}s")
    
    # Show system status
    status = await manager.get_system_status()
    print(f"System status: {status}")
    
    # Cleanup
    await manager.cleanup()
    import shutil
    shutil.rmtree(test_dir)


if __name__ == "__main__":
    asyncio.run(demo_optimized_processing())