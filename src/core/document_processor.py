"""
Document Processing Optimization Module

SYNTHEX Agent 5 Performance Optimization Implementation
Provides high-performance document parsing, caching, and parallel processing
"""

import asyncio
import hashlib
import mmap
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, 
    Set, Tuple, Union, TypeVar, Generic
)
import aiofiles
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing as mp
from functools import lru_cache, wraps
import pickle
import zlib

from .lru_cache import LRUCache, CacheConfig, CacheStats
from .object_pool import ObjectPool, PooledObject, pooled, PoolManager
from .stream_processor import ChunkedStreamProcessor, StreamMetrics, MemoryEfficientBuffer
from .parallel_executor import ParallelExecutor, Task, TaskType, TaskResult

__all__ = [
    "DocumentMetadata",
    "ParsedDocument",
    "DocumentCache",
    "DocumentParser",
    "TextDocumentParser",
    "MarkdownDocumentParser",
    "DocumentProcessor",
    "DocumentIndex",
    "ChapterIndex",
    "ParallelDocumentProcessor",
    "StreamingDocumentReader",
    "DocumentProcessingMetrics",
    "create_optimized_processor"
]

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class DocumentMetadata:
    """Metadata for processed documents"""
    path: str
    size_bytes: int
    hash: str
    created_at: datetime
    modified_at: datetime
    encoding: str = "utf-8"
    mime_type: str = "text/plain"
    chapters: List[str] = field(default_factory=list)
    word_count: int = 0
    line_count: int = 0
    processing_time_ms: float = 0


@dataclass
class ParsedDocument:
    """Parsed document with content and metadata"""
    metadata: DocumentMetadata
    content: str
    chapters: Dict[str, str] = field(default_factory=dict)
    index: Optional['DocumentIndex'] = None
    cached: bool = False
    
    def get_chapter(self, chapter_name: str) -> Optional[str]:
        """Get chapter content by name"""
        return self.chapters.get(chapter_name)
    
    def search(self, query: str, max_results: int = 10) -> List[Tuple[int, str]]:
        """Search document content"""
        if self.index:
            return self.index.search(query, max_results)
        # Fallback to simple search
        results = []
        lines = self.content.split('
')
        query_lower = query.lower()
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                results.append((i, line))
                if len(results) >= max_results:
                    break
        return results


class DocumentCache:
    """
    High-performance document cache with compression and persistence
    """
    
    def __init__(
        self,
        max_size: int = 100,
        ttl_seconds: float = 3600,
        cache_dir: Optional[Path] = None,
        enable_compression: bool = True,
        enable_persistence: bool = True
    ):
        self.cache = LRUCache[str, ParsedDocument](
            CacheConfig(
                max_size=max_size,
                default_ttl=ttl_seconds,
                enable_stats=True,
                eviction_callback=self._on_eviction
            )
        )
        self.cache_dir = cache_dir or Path.home() / ".cache" / "document_processor"
        self.enable_compression = enable_compression
        self.enable_persistence = enable_persistence
        
        if self.enable_persistence:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, path: str, options: Dict[str, Any]) -> str:
        """Generate cache key from path and options"""
        key_data = f"{path}:{sorted(options.items())}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get file path for cached document"""
        return self.cache_dir / f"{cache_key}.cache"
    
    def _serialize_document(self, doc: ParsedDocument) -> bytes:
        """Serialize document for caching"""
        data = pickle.dumps(doc)
        if self.enable_compression:
            data = zlib.compress(data, level=6)
        return data
    
    def _deserialize_document(self, data: bytes) -> ParsedDocument:
        """Deserialize cached document"""
        if self.enable_compression:
            data = zlib.decompress(data)
        return pickle.loads(data)
    
    def _on_eviction(self, key: str, doc: ParsedDocument):
        """Handle document eviction from cache"""
        if self.enable_persistence:
            try:
                cache_path = self._get_cache_path(key)
                cache_path.unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Failed to remove persisted cache: {e}")
    
    async def get(
        self, 
        path: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[ParsedDocument]:
        """Get document from cache"""
        options = options or {}
        cache_key = self._get_cache_key(path, options)
        
        # Try in-memory cache first
        doc = self.cache.get(cache_key)
        if doc:
            doc.cached = True
            return doc
        
        # Try persistent cache
        if self.enable_persistence:
            cache_path = self._get_cache_path(cache_key)
            if cache_path.exists():
                try:
                    async with aiofiles.open(cache_path, 'rb') as f:
                        data = await f.read()
                    doc = self._deserialize_document(data)
                    doc.cached = True
                    # Restore to in-memory cache
                    self.cache.put(cache_key, doc)
                    return doc
                except Exception as e:
                    logger.warning(f"Failed to load cached document: {e}")
                    cache_path.unlink(missing_ok=True)
        
        return None
    
    async def put(
        self, 
        path: str, 
        doc: ParsedDocument,
        options: Optional[Dict[str, Any]] = None
    ):
        """Store document in cache"""
        options = options or {}
        cache_key = self._get_cache_key(path, options)
        
        # Store in memory
        self.cache.put(cache_key, doc)
        
        # Store persistently
        if self.enable_persistence:
            try:
                cache_path = self._get_cache_path(cache_key)
                data = self._serialize_document(doc)
                async with aiofiles.open(cache_path, 'wb') as f:
                    await f.write(data)
            except Exception as e:
                logger.warning(f"Failed to persist document cache: {e}")
    
    def invalidate(self, path: str, options: Optional[Dict[str, Any]] = None):
        """Invalidate cached document"""
        options = options or {}
        cache_key = self._get_cache_key(path, options)
        self.cache.delete(cache_key)
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        return self.cache.get_stats()
    
    async def clear(self):
        """Clear all cached documents"""
        self.cache.clear()
        if self.enable_persistence:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink(missing_ok=True)


class DocumentParser(ABC):
    """Abstract base class for document parsers"""
    
    @abstractmethod
    async def parse(
        self, 
        content: str, 
        metadata: DocumentMetadata
    ) -> ParsedDocument:
        """Parse document content"""
        pass
    
    @abstractmethod
    def supports_mime_type(self, mime_type: str) -> bool:
        """Check if parser supports given MIME type"""
        pass


class TextDocumentParser(DocumentParser, PooledObject):
    """Basic text document parser with pooling support"""
    
    def __init__(self):
        super().__init__()
        self.supported_types = {"text/plain", "text/*"}
    
    async def parse(
        self, 
        content: str, 
        metadata: DocumentMetadata
    ) -> ParsedDocument:
        """Parse plain text document"""
        lines = content.split('
')
        
        # Basic chapter detection (lines starting with specific patterns)
        chapters = {}
        current_chapter = None
        chapter_content = []
        
        for line in lines:
            # Simple chapter detection
            if line.strip() and (
                line.startswith("Chapter ") or 
                line.startswith("# ") or
                line.startswith("## ")
            ):
                if current_chapter:
                    chapters[current_chapter] = '
'.join(chapter_content)
                current_chapter = line.strip()
                chapter_content = []
                metadata.chapters.append(current_chapter)
            elif current_chapter:
                chapter_content.append(line)
        
        # Add last chapter
        if current_chapter:
            chapters[current_chapter] = '
'.join(chapter_content)
        
        # Update metadata
        metadata.word_count = len(content.split())
        metadata.line_count = len(lines)
        
        return ParsedDocument(
            metadata=metadata,
            content=content,
            chapters=chapters
        )
    
    def supports_mime_type(self, mime_type: str) -> bool:
        """Check if parser supports MIME type"""
        return any(
            mime_type.startswith(supported.replace("*", ""))
            for supported in self.supported_types
        )
    
    def reset(self):
        """Reset parser state for reuse"""
        super().reset()
        # Clear any parser-specific state


class MarkdownDocumentParser(TextDocumentParser):
    """Markdown document parser with enhanced chapter detection"""
    
    def __init__(self):
        super().__init__()
        self.supported_types = {"text/markdown", "text/x-markdown"}
    
    async def parse(
        self, 
        content: str, 
        metadata: DocumentMetadata
    ) -> ParsedDocument:
        """Parse markdown document with better structure detection"""
        lines = content.split('
')
        chapters = {}
        current_chapter = None
        chapter_content = []
        chapter_level = 0
        
        for line in lines:
            # Markdown heading detection
            if line.startswith('#'):
                heading_level = len(line.split()[0])
                if heading_level <= 2:  # Only h1 and h2 as chapters
                    if current_chapter:
                        chapters[current_chapter] = '
'.join(chapter_content)
                    current_chapter = line.strip()
                    chapter_content = []
                    chapter_level = heading_level
                    metadata.chapters.append(current_chapter)
                else:
                    chapter_content.append(line)
            elif current_chapter:
                chapter_content.append(line)
            else:
                # Content before first chapter
                if "Introduction" not in chapters:
                    chapters["Introduction"] = ""
                    current_chapter = "Introduction"
                chapter_content.append(line)
        
        # Add last chapter
        if current_chapter:
            chapters[current_chapter] = '
'.join(chapter_content)
        
        # Update metadata
        metadata.word_count = len(content.split())
        metadata.line_count = len(lines)
        metadata.mime_type = "text/markdown"
        
        doc = ParsedDocument(
            metadata=metadata,
            content=content,
            chapters=chapters
        )
        
        # Build index for markdown documents
        doc.index = DocumentIndex()
        await doc.index.build(content)
        
        return doc


class DocumentIndex:
    """Fast document index for searching"""
    
    def __init__(self):
        self.line_index: List[str] = []
        self.word_index: Dict[str, Set[int]] = {}
        self.chapter_index: Dict[str, Tuple[int, int]] = {}
    
    async def build(self, content: str):
        """Build index from document content"""
        self.line_index = content.split('
')
        
        # Build word index
        for i, line in enumerate(self.line_index):
            words = line.lower().split()
            for word in words:
                # Remove common punctuation
                word = word.strip('.,!?;:"')
                if word:
                    if word not in self.word_index:
                        self.word_index[word] = set()
                    self.word_index[word].add(i)
    
    def search(self, query: str, max_results: int = 10) -> List[Tuple[int, str]]:
        """Search for query in document"""
        query_words = query.lower().split()
        matching_lines = set()
        
        # Find lines containing all query words
        for word in query_words:
            word = word.strip('.,!?;:"')
            if word in self.word_index:
                if not matching_lines:
                    matching_lines = self.word_index[word].copy()
                else:
                    matching_lines &= self.word_index[word]
        
        # Return matching lines
        results = []
        for line_num in sorted(matching_lines)[:max_results]:
            if line_num < len(self.line_index):
                results.append((line_num, self.line_index[line_num]))
        
        return results
    
    def get_chapter_lines(self, chapter_name: str) -> Optional[List[str]]:
        """Get lines for a specific chapter"""
        if chapter_name in self.chapter_index:
            start, end = self.chapter_index[chapter_name]
            return self.line_index[start:end]
        return None


class ChapterIndex:
    """Specialized index for fast chapter lookup"""
    
    def __init__(self):
        self.chapters: Dict[str, Dict[str, Any]] = {}
        self.chapter_order: List[str] = []
    
    def add_chapter(
        self, 
        name: str, 
        content: str, 
        start_pos: int, 
        end_pos: int
    ):
        """Add chapter to index"""
        self.chapters[name] = {
            "content": content,
            "start_pos": start_pos,
            "end_pos": end_pos,
            "word_count": len(content.split()),
            "line_count": len(content.split('
'))
        }
        self.chapter_order.append(name)
    
    def get_chapter(self, name: str) -> Optional[Dict[str, Any]]:
        """Get chapter by name"""
        return self.chapters.get(name)
    
    def get_chapter_names(self) -> List[str]:
        """Get ordered list of chapter names"""
        return self.chapter_order.copy()
    
    def search_chapters(self, query: str) -> List[Tuple[str, int]]:
        """Search across all chapters"""
        results = []
        query_lower = query.lower()
        
        for name, info in self.chapters.items():
            content_lower = info["content"].lower()
            count = content_lower.count(query_lower)
            if count > 0:
                results.append((name, count))
        
        # Sort by occurrence count
        results.sort(key=lambda x: x[1], reverse=True)
        return results


class ParserPool:
    """Object pool for document parsers"""
    
    _pools: Dict[type, ObjectPool] = {}
    
    @classmethod
    def get_parser(cls, parser_class: type) -> DocumentParser:
        """Get parser from pool"""
        if parser_class not in cls._pools:
            cls._pools[parser_class] = ObjectPool(
                factory=parser_class,
                max_size=10,
                name=parser_class.__name__
            )
        return cls._pools[parser_class].acquire()
    
    @classmethod
    def release_parser(cls, parser: DocumentParser):
        """Release parser back to pool"""
        parser_class = type(parser)
        if parser_class in cls._pools:
            cls._pools[parser_class].release(parser)


class StreamingDocumentReader:
    """Streaming document reader for large files"""
    
    def __init__(self, chunk_size: int = 8192):
        self.chunk_size = chunk_size
    
    async def read_file(self, path: Path) -> AsyncIterator[str]:
        """Read file in chunks"""
        async with aiofiles.open(path, 'r', encoding='utf-8') as f:
            while True:
                chunk = await f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk
    
    async def read_file_mmap(self, path: Path) -> str:
        """Read file using memory mapping for large files"""
        with open(path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                return mmapped.read().decode('utf-8')
    
    async def read_lines(self, path: Path) -> AsyncIterator[str]:
        """Read file line by line"""
        async with aiofiles.open(path, 'r', encoding='utf-8') as f:
            async for line in f:
                yield line.rstrip('
')


@dataclass
class DocumentProcessingMetrics:
    """Metrics for document processing performance"""
    total_documents: int = 0
    total_bytes: int = 0
    total_time_ms: float = 0
    cache_hits: int = 0
    cache_misses: int = 0
    parsing_time_ms: float = 0
    indexing_time_ms: float = 0
    
    @property
    def average_time_ms(self) -> float:
        """Average processing time per document"""
        return self.total_time_ms / self.total_documents if self.total_documents > 0 else 0
    
    @property
    def throughput_mbps(self) -> float:
        """Processing throughput in MB/s"""
        if self.total_time_ms > 0:
            return (self.total_bytes / 1024 / 1024) / (self.total_time_ms / 1000)
        return 0
    
    @property
    def cache_hit_rate(self) -> float:
        """Cache hit rate"""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0


class DocumentProcessor:
    """
    Main document processor with caching, lazy loading, and optimization
    """
    
    def __init__(
        self,
        cache: Optional[DocumentCache] = None,
        parsers: Optional[List[DocumentParser]] = None,
        enable_lazy_loading: bool = True,
        enable_streaming: bool = True,
        max_file_size_mb: int = 100
    ):
        self.cache = cache or DocumentCache()
        self.parsers = parsers or [
            TextDocumentParser(),
            MarkdownDocumentParser()
        ]
        self.enable_lazy_loading = enable_lazy_loading
        self.enable_streaming = enable_streaming
        self.max_file_size_mb = max_file_size_mb
        self.metrics = DocumentProcessingMetrics()
        self.reader = StreamingDocumentReader()
    
    def _get_parser(self, mime_type: str) -> Optional[DocumentParser]:
        """Get appropriate parser for MIME type"""
        for parser in self.parsers:
            if parser.supports_mime_type(mime_type):
                return parser
        return None
    
    async def _detect_mime_type(self, path: Path) -> str:
        """Detect MIME type from file extension"""
        suffix = path.suffix.lower()
        mime_map = {
            ".txt": "text/plain",
            ".md": "text/markdown",
            ".markdown": "text/markdown",
            ".rst": "text/x-rst",
            ".html": "text/html",
            ".xml": "text/xml"
        }
        return mime_map.get(suffix, "text/plain")
    
    async def _create_metadata(self, path: Path) -> DocumentMetadata:
        """Create document metadata"""
        stat = path.stat()
        content_sample = ""
        
        # Read small sample for hash
        async with aiofiles.open(path, 'r', encoding='utf-8') as f:
            content_sample = await f.read(1024)
        
        return DocumentMetadata(
            path=str(path),
            size_bytes=stat.st_size,
            hash=hashlib.sha256(content_sample.encode()).hexdigest(),
            created_at=datetime.fromtimestamp(stat.st_ctime),
            modified_at=datetime.fromtimestamp(stat.st_mtime),
            mime_type=await self._detect_mime_type(path)
        )
    
    async def process_document(
        self,
        path: Union[str, Path],
        options: Optional[Dict[str, Any]] = None
    ) -> ParsedDocument:
        """Process a document with caching and optimization"""
        start_time = time.time()
        path = Path(path)
        options = options or {}
        
        # Check cache first
        cached_doc = await self.cache.get(str(path), options)
        if cached_doc:
            self.metrics.cache_hits += 1
            self.metrics.total_documents += 1
            return cached_doc
        
        self.metrics.cache_misses += 1
        
        # Create metadata
        metadata = await self._create_metadata(path)
        
        # Read content
        content = ""
        if metadata.size_bytes > self.max_file_size_mb * 1024 * 1024:
            # Use memory mapping for large files
            if self.enable_streaming:
                content = await self.reader.read_file_mmap(path)
            else:
                raise ValueError(f"File too large: {metadata.size_bytes} bytes")
        else:
            # Regular reading for smaller files
            async with aiofiles.open(path, 'r', encoding='utf-8') as f:
                content = await f.read()
        
        # Get appropriate parser
        parser = self._get_parser(metadata.mime_type)
        if not parser:
            parser = TextDocumentParser()  # Fallback
        
        # Use parser from pool if available
        if isinstance(parser, PooledObject):
            parser = ParserPool.get_parser(type(parser))
        
        # Parse document
        parse_start = time.time()
        try:
            doc = await parser.parse(content, metadata)
            self.metrics.parsing_time_ms += (time.time() - parse_start) * 1000
        finally:
            # Return parser to pool
            if isinstance(parser, PooledObject):
                ParserPool.release_parser(parser)
        
        # Build index if enabled
        if options.get("build_index", True) and not doc.index:
            index_start = time.time()
            doc.index = DocumentIndex()
            await doc.index.build(content)
            self.metrics.indexing_time_ms += (time.time() - index_start) * 1000
        
        # Update metrics
        processing_time = (time.time() - start_time) * 1000
        metadata.processing_time_ms = processing_time
        self.metrics.total_documents += 1
        self.metrics.total_bytes += metadata.size_bytes
        self.metrics.total_time_ms += processing_time
        
        # Cache the result
        await self.cache.put(str(path), doc, options)
        
        return doc
    
    async def process_lazy(
        self,
        path: Union[str, Path],
        options: Optional[Dict[str, Any]] = None
    ) -> 'LazyDocument':
        """Process document with lazy loading"""
        return LazyDocument(self, path, options)
    
    def get_metrics(self) -> DocumentProcessingMetrics:
        """Get processing metrics"""
        return self.metrics
    
    async def clear_cache(self):
        """Clear document cache"""
        await self.cache.clear()


class LazyDocument:
    """Lazy-loaded document that loads content on demand"""
    
    def __init__(
        self,
        processor: DocumentProcessor,
        path: Union[str, Path],
        options: Optional[Dict[str, Any]] = None
    ):
        self.processor = processor
        self.path = Path(path)
        self.options = options or {}
        self._document: Optional[ParsedDocument] = None
        self._metadata: Optional[DocumentMetadata] = None
    
    async def get_metadata(self) -> DocumentMetadata:
        """Get document metadata without loading content"""
        if self._metadata is None:
            self._metadata = await self.processor._create_metadata(self.path)
        return self._metadata
    
    async def get_document(self) -> ParsedDocument:
        """Load full document"""
        if self._document is None:
            self._document = await self.processor.process_document(
                self.path, 
                self.options
            )
        return self._document
    
    async def get_chapter(self, chapter_name: str) -> Optional[str]:
        """Load specific chapter"""
        doc = await self.get_document()
        return doc.get_chapter(chapter_name)
    
    async def search(self, query: str, max_results: int = 10) -> List[Tuple[int, str]]:
        """Search document"""
        doc = await self.get_document()
        return doc.search(query, max_results)


class ParallelDocumentProcessor:
    """Process multiple documents in parallel"""
    
    def __init__(
        self,
        processor: Optional[DocumentProcessor] = None,
        max_workers: int = 4,
        enable_progress: bool = True
    ):
        self.processor = processor or DocumentProcessor()
        self.executor = ParallelExecutor(
            max_workers_thread=max_workers,
            enable_progress=enable_progress
        )
    
    async def process_documents(
        self,
        paths: List[Union[str, Path]],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, ParsedDocument]:
        """Process multiple documents in parallel"""
        options = options or {}
        
        # Create tasks for each document
        tasks = []
        for i, path in enumerate(paths):
            task = Task(
                name=f"process_{Path(path).name}",
                func=self._process_single,
                args=(path, options),
                task_type=TaskType.IO_BOUND,
                retry_count=2
            )
            tasks.append(task)
        
        # Execute in parallel
        results = await self.executor.execute_tasks(tasks)
        
        # Map results
        processed = {}
        for path, result in zip(paths, results.values()):
            if result.success:
                processed[str(path)] = result.result
            else:
                logger.error(f"Failed to process {path}: {result.error}")
        
        return processed
    
    async def _process_single(self, path: Union[str, Path], options: Dict[str, Any]) -> ParsedDocument:
        """Process single document (wrapped for executor)"""
        return await self.processor.process_document(path, options)
    
    async def process_directory(
        self,
        directory: Union[str, Path],
        pattern: str = "*.txt",
        recursive: bool = True,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, ParsedDocument]:
        """Process all matching documents in directory"""
        directory = Path(directory)
        
        # Find matching files
        if recursive:
            paths = list(directory.rglob(pattern))
        else:
            paths = list(directory.glob(pattern))
        
        logger.info(f"Found {len(paths)} documents to process")
        
        # Process in parallel
        return await self.process_documents(paths, options)


class BackgroundDocumentProcessor:
    """Process documents in background with progress tracking"""
    
    def __init__(self, processor: Optional[DocumentProcessor] = None):
        self.processor = processor or DocumentProcessor()
        self._tasks: Dict[str, asyncio.Task] = {}
        self._progress: Dict[str, float] = {}
    
    async def process_async(
        self,
        path: Union[str, Path],
        options: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[ParsedDocument], None]] = None
    ) -> str:
        """Start background processing"""
        task_id = hashlib.sha256(str(path).encode()).hexdigest()[:8]
        
        async def process_with_progress():
            self._progress[task_id] = 0.0
            try:
                # Simulate progress updates
                self._progress[task_id] = 0.1
                doc = await self.processor.process_document(path, options)
                self._progress[task_id] = 1.0
                
                if callback:
                    callback(doc)
                
                return doc
            except Exception as e:
                self._progress[task_id] = -1.0
                raise e
            finally:
                # Clean up after delay
                await asyncio.sleep(60)
                self._tasks.pop(task_id, None)
                self._progress.pop(task_id, None)
        
        # Start background task
        task = asyncio.create_task(process_with_progress())
        self._tasks[task_id] = task
        
        return task_id
    
    def get_progress(self, task_id: str) -> float:
        """Get processing progress (0.0-1.0, -1.0 for error)"""
        return self._progress.get(task_id, 0.0)
    
    async def get_result(self, task_id: str) -> Optional[ParsedDocument]:
        """Get processing result if complete"""
        task = self._tasks.get(task_id)
        if task and task.done():
            return await task
        return None
    
    def cancel(self, task_id: str) -> bool:
        """Cancel background processing"""
        task = self._tasks.get(task_id)
        if task and not task.done():
            task.cancel()
            return True
        return False


def create_optimized_processor(
    cache_size: int = 100,
    cache_ttl: float = 3600,
    enable_persistence: bool = True,
    enable_compression: bool = True,
    max_workers: int = 4
) -> Tuple[DocumentProcessor, ParallelDocumentProcessor]:
    """
    Create optimized document processor with recommended settings
    
    Returns:
        Tuple of (DocumentProcessor, ParallelDocumentProcessor)
    """
    # Create cache with optimization
    cache = DocumentCache(
        max_size=cache_size,
        ttl_seconds=cache_ttl,
        enable_persistence=enable_persistence,
        enable_compression=enable_compression
    )
    
    # Create parsers
    parsers = [
        TextDocumentParser(),
        MarkdownDocumentParser()
    ]
    
    # Register parser pools
    for parser_class in [TextDocumentParser, MarkdownDocumentParser]:
        PoolManager.register_pool(
            parser_class.__name__,
            ObjectPool(
                factory=parser_class,
                max_size=max_workers * 2,
                name=parser_class.__name__
            )
        )
    
    # Create processors
    processor = DocumentProcessor(
        cache=cache,
        parsers=parsers,
        enable_lazy_loading=True,
        enable_streaming=True
    )
    
    parallel_processor = ParallelDocumentProcessor(
        processor=processor,
        max_workers=max_workers,
        enable_progress=True
    )
    
    return processor, parallel_processor


# Example usage and benchmarks
async def benchmark_document_processing():
    """Benchmark document processing performance"""
    import tempfile
    import random
    import string
    
    # Create test documents
    test_dir = Path(tempfile.mkdtemp())
    doc_sizes = [1, 10, 50, 100]  # MB
    docs = []
    
    for size_mb in doc_sizes:
        # Generate random content
        content = ''.join(
            random.choices(string.ascii_letters + string.whitespace, 
            k=size_mb * 1024 * 1024)
        )
        
        # Add some structure
        lines = content.split('
')
        structured = []
        for i, line in enumerate(lines):
            if i % 100 == 0:
                structured.append(f"# Chapter {i // 100}")
            structured.append(line)
        
        doc_path = test_dir / f"test_{size_mb}mb.md"
        doc_path.write_text('\n'.join(structured))\n        docs.append(doc_path)\n\n    # Create processors\n    processor, parallel_processor = create_optimized_processor()\n\n    # Benchmark single document processing\n    print("Single Document Processing:")\n    for doc_path in docs:\n        start = time.time()\n        doc = await processor.process_document(doc_path)\n        elapsed = time.time() - start\n\n        size_mb = doc.metadata.size_bytes / 1024 / 1024\n        throughput = size_mb / elapsed if elapsed > 0 else 0\n\n        print(f"  {doc_path.name}: {elapsed:.2f}s ({throughput:.2f} MB/s)")\n        print(f"    Chapters: {len(doc.chapters)}")\n        print(f"    Cached: {doc.cached}")\n\n    # Benchmark cached access\n    print("\nCached Access:")\n    for doc_path in docs:\n        start = time.time()\n        doc = await processor.process_document(doc_path)\n        elapsed = time.time() - start\n\n        print(f"  {doc_path.name}: {elapsed:.4f}s (cached: {doc.cached})")\n\n    # Benchmark parallel processing\n    print("\nParallel Processing:")\n    start = time.time()\n    results = await parallel_processor.process_documents(docs)\n    elapsed = time.time() - start\n\n    total_size_mb = sum(doc.metadata.size_bytes for doc in results.values()) / 1024 / 1024\n    throughput = total_size_mb / elapsed if elapsed > 0 else 0\n\n    print(f"  Processed {len(results)} documents in {elapsed:.2f}s")\n    print(f"  Total throughput: {throughput:.2f} MB/s")\n\n    # Show metrics\n    metrics = processor.get_metrics()\n    print(f"\nMetrics:")\n    print(f"  Total documents: {metrics.total_documents}")\n    print(f"  Cache hit rate: {metrics.cache_hit_rate:.2%}")\n    print(f"  Average time: {metrics.average_time_ms:.2f}ms")\n    print(f"  Throughput: {metrics.throughput_mbps:.2f} MB/s")\n\n    # Cleanup\n    import shutil\n    shutil.rmtree(test_dir)\n\n\nif __name__ == "__main__":\n    # Run benchmarks\n    asyncio.run(benchmark_document_processing())