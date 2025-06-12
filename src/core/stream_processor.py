"""
Stream Processing Module for Memory Optimization

This module provides streaming utilities to process data in chunks rather than
loading everything into memory at once, reducing garbage collection pressure.
"""

import asyncio
import json
import csv
import io
from abc import ABC, abstractmethod
from typing import (
    Iterator, AsyncIterator, TypeVar, Generic, Callable, Any, Optional,
    Dict, List, Union, Tuple, AsyncGenerator, Generator
)
from dataclasses import dataclass
from datetime import datetime
import logging
from contextlib import asynccontextmanager, contextmanager

from .object_pool import ObjectPool, PooledObject, pooled, DictPool, ListPool
from .gc_optimization import with_gc_optimization

logger = logging.getLogger(__name__)

T = TypeVar('T')
U = TypeVar('U')


@dataclass
class StreamMetrics:
    """Metrics for stream processing performance"""
    items_processed: int = 0
    bytes_processed: int = 0
    chunks_processed: int = 0
    processing_time_ms: float = 0
    peak_memory_mb: float = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class StreamProcessor(ABC, Generic[T, U]):
    """Abstract base class for stream processors"""
    
    @abstractmethod
    async def process_item(self, item: T) -> U:
        """Process a single item"""
        pass
        
    @abstractmethod
    async def process_chunk(self, chunk: List[T]) -> List[U]:
        """Process a chunk of items"""
        pass


class ChunkedStreamProcessor(StreamProcessor[T, U]):
    """
    Stream processor that handles data in configurable chunks.
    
    Reduces memory pressure by processing data in small batches
    and triggering garbage collection between chunks.
    """
    
    def __init__(
        self,
        chunk_size: int = 1000,
        max_memory_mb: int = 512,
        enable_gc_optimization: bool = True
    ):
        self.chunk_size = chunk_size
        self.max_memory_mb = max_memory_mb
        self.enable_gc_optimization = enable_gc_optimization
        self.metrics = StreamMetrics()
        
    async def process_item(self, item: T) -> U:
        """Process a single item - override in subclasses"""
        return item  # Default passthrough
        
    async def process_chunk(self, chunk: List[T]) -> List[U]:
        """Process a chunk of items"""
        results = []
        for item in chunk:
            result = await self.process_item(item)
            results.append(result)
        return results
        
    async def process_stream(
        self,
        stream: AsyncIterator[T],
        output_handler: Optional[Callable[[List[U]], None]] = None
    ) -> StreamMetrics:
        """
        Process a stream of items in chunks.
        
        Args:
            stream: AsyncIterator of items to process
            output_handler: Optional handler for processed chunks
            
        Returns:
            StreamMetrics with processing statistics
        """
        self.metrics = StreamMetrics(start_time=datetime.now())
        
        chunk = []
        
        try:
            async for item in stream:
                chunk.append(item)
                self.metrics.items_processed += 1
                
                # Estimate memory usage (rough)
                if hasattr(item, '__sizeof__'):
                    self.metrics.bytes_processed += item.__sizeof__()
                
                # Process chunk when full
                if len(chunk) >= self.chunk_size:
                    await self._process_and_output_chunk(chunk, output_handler)
                    chunk.clear()
                    
                    # Memory pressure check
                    if self.enable_gc_optimization:
                        import psutil
                        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                        self.metrics.peak_memory_mb = max(self.metrics.peak_memory_mb, current_memory)
                        
                        if current_memory > self.max_memory_mb:
                            from .gc_optimization import gc_optimizer
                            gc_optimizer.trigger_gc(force=True)
                            
            # Process final chunk
            if chunk:
                await self._process_and_output_chunk(chunk, output_handler)
                
        finally:
            self.metrics.end_time = datetime.now()
            if self.metrics.start_time:
                delta = self.metrics.end_time - self.metrics.start_time
                self.metrics.processing_time_ms = delta.total_seconds() * 1000
                
        return self.metrics
        
    async def _process_and_output_chunk(
        self,
        chunk: List[T],
        output_handler: Optional[Callable[[List[U]], None]]
    ):
        """Process a chunk and handle output"""
        if not chunk:
            return
            
        # Process chunk
        results = await self.process_chunk(chunk)
        self.metrics.chunks_processed += 1
        
        # Handle output
        if output_handler:
            output_handler(results)
            
        logger.debug(
            f"Processed chunk {self.metrics.chunks_processed} "
            f"with {len(chunk)} items"
        )


class JsonStreamProcessor(ChunkedStreamProcessor[Dict[str, Any], Dict[str, Any]]):
    """Stream processor for JSON data"""
    
    def __init__(self, transform_func: Optional[Callable[[Dict], Dict]] = None, **kwargs):
        super().__init__(**kwargs)
        self.transform_func = transform_func or (lambda x: x)
        
    async def process_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Transform a JSON object"""
        return self.transform_func(item)


class CsvStreamProcessor(ChunkedStreamProcessor[List[str], Dict[str, Any]]):
    """Stream processor for CSV data"""
    
    def __init__(self, headers: List[str], **kwargs):
        super().__init__(**kwargs)
        self.headers = headers
        
    async def process_item(self, item: List[str]) -> Dict[str, Any]:
        """Convert CSV row to dictionary"""
        with pooled(DictPool) as result:
            for i, header in enumerate(self.headers):
                if i < len(item):
                    result[header] = item[i]
            return dict(result)  # Return regular dict, not pooled


class StreamingJsonReader:
    """
    Streaming JSON reader that processes large JSON files without
    loading them entirely into memory.
    """
    
    @staticmethod
    async def read_json_lines(file_path: str) -> AsyncIterator[Dict[str, Any]]:
        """Read JSONL (JSON Lines) format file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON on line {line_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return
            
    @staticmethod
    async def read_json_array(
        file_path: str,
        chunk_size: int = 1000
    ) -> AsyncIterator[Dict[str, Any]]:
        """Read JSON array file in chunks"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Simple JSON array streaming (for basic cases)
                content = file.read()
                data = json.loads(content)
                
                if isinstance(data, list):
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        for item in chunk:
                            yield item
                        # Allow other tasks to run
                        await asyncio.sleep(0)
                else:
                    yield data
                    
        except Exception as e:
            logger.error(f"Error reading JSON array from {file_path}: {e}")
            return


class StreamingCsvReader:
    """Streaming CSV reader for large CSV files"""
    
    @staticmethod
    async def read_csv(
        file_path: str,
        delimiter: str = ',',
        chunk_size: int = 1000
    ) -> AsyncIterator[List[str]]:
        """Read CSV file in streaming fashion"""
        try:
            with open(file_path, 'r', encoding='utf-8', newline='') as file:
                reader = csv.reader(file, delimiter=delimiter)
                
                rows_processed = 0
                for row in reader:
                    yield row
                    rows_processed += 1
                    
                    # Yield control periodically
                    if rows_processed % chunk_size == 0:
                        await asyncio.sleep(0)
                        
        except Exception as e:
            logger.error(f"Error reading CSV from {file_path}: {e}")
            return


class MemoryEfficientBuffer(Generic[T]):
    """
    Memory-efficient buffer that uses object pooling and streaming.
    
    Automatically flushes when buffer gets too large to prevent
    memory accumulation.
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        flush_threshold: float = 0.8,
        auto_flush_handler: Optional[Callable[[List[T]], None]] = None
    ):
        self.max_size = max_size
        self.flush_threshold = flush_threshold
        self.auto_flush_handler = auto_flush_handler
        self._buffer: List[T] = []
        self._flush_size = int(max_size * flush_threshold)
        
    def add(self, item: T):
        """Add item to buffer"""
        self._buffer.append(item)
        
        # Auto-flush if threshold reached
        if len(self._buffer) >= self._flush_size and self.auto_flush_handler:
            self.flush()
            
    def add_batch(self, items: List[T]):
        """Add multiple items to buffer"""
        for item in items:
            self.add(item)
            
    def flush(self) -> List[T]:
        """Flush buffer and return contents"""
        if not self._buffer:
            return []
            
        flushed_items = self._buffer.copy()
        self._buffer.clear()
        
        if self.auto_flush_handler:
            self.auto_flush_handler(flushed_items)
            
        return flushed_items
        
    def size(self) -> int:
        """Get current buffer size"""
        return len(self._buffer)
        
    def is_full(self) -> bool:
        """Check if buffer is at capacity"""
        return len(self._buffer) >= self.max_size
        
    def get_items(self) -> List[T]:
        """Get buffer contents without flushing"""
        return self._buffer.copy()


class StreamingAggregator(Generic[T, U]):
    """
    Streaming aggregator that processes data in chunks and maintains
    running aggregations without keeping all data in memory.
    """
    
    def __init__(
        self,
        aggregation_func: Callable[[List[T]], U],
        chunk_size: int = 1000,
        max_memory_mb: int = 256
    ):
        self.aggregation_func = aggregation_func
        self.chunk_size = chunk_size
        self.max_memory_mb = max_memory_mb
        self.results: List[U] = []
        self.current_chunk: List[T] = []
        
    async def add_item(self, item: T):
        """Add item to aggregation"""
        self.current_chunk.append(item)
        
        if len(self.current_chunk) >= self.chunk_size:
            await self._process_chunk()
            
    async def add_items(self, items: List[T]):
        """Add multiple items"""
        for item in items:
            await self.add_item(item)
            
    async def _process_chunk(self):
        """Process current chunk"""
        if not self.current_chunk:
            return
            
        # Apply aggregation function
        result = self.aggregation_func(self.current_chunk)
        self.results.append(result)
        
        # Clear chunk
        self.current_chunk.clear()
        
        # Memory pressure check
        import psutil
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        if current_memory > self.max_memory_mb:
            from .gc_optimization import gc_optimizer
            gc_optimizer.trigger_gc(force=True)
            
    async def finalize(self) -> List[U]:
        """Finalize aggregation and return results"""
        # Process remaining items
        await self._process_chunk()
        
        return self.results.copy()


# Utility functions for common streaming operations
@with_gc_optimization
async def stream_map(
    stream: AsyncIterator[T],
    transform_func: Callable[[T], U],
    chunk_size: int = 1000
) -> AsyncIterator[U]:
    """Map function over stream with memory optimization"""
    chunk = []
    
    async for item in stream:
        chunk.append(item)
        
        if len(chunk) >= chunk_size:
            # Process chunk
            for chunk_item in chunk:
                yield transform_func(chunk_item)
            chunk.clear()
            
    # Process remaining items
    for item in chunk:
        yield transform_func(item)


@with_gc_optimization
async def stream_filter(
    stream: AsyncIterator[T],
    predicate: Callable[[T], bool],
    chunk_size: int = 1000
) -> AsyncIterator[T]:
    """Filter stream with memory optimization"""
    chunk = []
    
    async for item in stream:
        chunk.append(item)
        
        if len(chunk) >= chunk_size:
            # Process chunk
            for chunk_item in chunk:
                if predicate(chunk_item):
                    yield chunk_item
            chunk.clear()
            
    # Process remaining items
    for item in chunk:
        if predicate(item):
            yield item


async def stream_reduce(
    stream: AsyncIterator[T],
    reduce_func: Callable[[U, T], U],
    initial: U,
    chunk_size: int = 1000
) -> U:
    """Reduce stream with memory optimization"""
    accumulator = initial
    chunk = []
    
    async for item in stream:
        chunk.append(item)
        
        if len(chunk) >= chunk_size:
            # Process chunk
            for chunk_item in chunk:
                accumulator = reduce_func(accumulator, chunk_item)
            chunk.clear()
            
            # Trigger GC between chunks
            from .gc_optimization import gc_optimizer
            gc_optimizer.trigger_gc()
            
    # Process remaining items
    for item in chunk:
        accumulator = reduce_func(accumulator, item)
        
    return accumulator


# Context managers for streaming operations
@asynccontextmanager
async def streaming_json_processor(
    file_path: str,
    transform_func: Optional[Callable[[Dict], Dict]] = None,
    chunk_size: int = 1000
):
    """Context manager for streaming JSON processing"""
    processor = JsonStreamProcessor(transform_func, chunk_size=chunk_size)
    stream = StreamingJsonReader.read_json_lines(file_path)
    
    try:
        yield processor, stream
    finally:
        # Cleanup
        del processor
        from .gc_optimization import gc_optimizer
        gc_optimizer.trigger_gc()


@asynccontextmanager
async def streaming_csv_processor(
    file_path: str,
    headers: List[str],
    chunk_size: int = 1000
):
    """Context manager for streaming CSV processing"""
    processor = CsvStreamProcessor(headers, chunk_size=chunk_size)
    stream = StreamingCsvReader.read_csv(file_path, chunk_size=chunk_size)
    
    try:
        yield processor, stream
    finally:
        # Cleanup
        del processor
        from .gc_optimization import gc_optimizer
        gc_optimizer.trigger_gc()