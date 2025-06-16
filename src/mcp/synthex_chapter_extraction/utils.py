"""
SYNTHEX Chapter Extraction MCP Server - Utility Functions
========================================================

Utility functions and helpers for the SYNTHEX Chapter Extraction MCP Server.
Provides common functionality for file operations, text processing, 
performance monitoring, and integration with CORE components.

Features:
- File system operations and monitoring
- Text processing utilities
- Performance measurement tools
- Security helpers
- Format detection and validation
- Caching mechanisms
- Error handling utilities

Author: SYNTHEX Collaborative Intelligence
"""

import asyncio
import hashlib
import mimetypes
import os
import re
import time
import unicodedata
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from functools import wraps
import logging

logger = logging.getLogger(__name__)


class FileSystemMonitor:
    """Monitor file system changes in the downloads folder."""
    
    def __init__(self, folder_path: Union[str, Path], callback=None):
        self.folder_path = Path(folder_path)
        self.callback = callback
        self.monitoring = False
        self.last_scan = {}
        
    async def start_monitoring(self, interval: float = 1.0):
        """Start monitoring the folder for changes."""
        self.monitoring = True
        logger.info(f"Started monitoring {self.folder_path}")
        
        while self.monitoring:
            try:
                await self._scan_folder()
                await asyncio.sleep(interval)
            except Exception as e:
                logger.error(f"Error during folder monitoring: {e}")
                await asyncio.sleep(interval)
    
    def stop_monitoring(self):
        """Stop monitoring the folder."""
        self.monitoring = False
        logger.info("Stopped folder monitoring")
    
    async def _scan_folder(self):
        """Scan folder for changes."""
        if not self.folder_path.exists():
            return
        
        current_scan = {}
        
        for file_path in self.folder_path.iterdir():
            if file_path.is_file():
                stat = file_path.stat()
                current_scan[str(file_path)] = {
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'created': stat.st_ctime
                }
        
        # Detect changes
        if self.last_scan:
            # New files
            new_files = set(current_scan.keys()) - set(self.last_scan.keys())
            for file_path in new_files:
                if self.callback:
                    await self.callback('created', file_path, current_scan[file_path])
            
            # Modified files
            for file_path in current_scan:
                if file_path in self.last_scan:
                    if current_scan[file_path]['modified'] > self.last_scan[file_path]['modified']:
                        if self.callback:
                            await self.callback('modified', file_path, current_scan[file_path])
            
            # Deleted files
            deleted_files = set(self.last_scan.keys()) - set(current_scan.keys())
            for file_path in deleted_files:
                if self.callback:
                    await self.callback('deleted', file_path, self.last_scan[file_path])
        
        self.last_scan = current_scan


class TextProcessor:
    """Text processing utilities for chapter extraction."""
    
    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize text for processing."""
        # Unicode normalization
        text = unicodedata.normalize('NFKD', text)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove control characters
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]', '', text)
        
        return text.strip()
    
    @staticmethod
    def clean_chapter_title(title: str) -> str:
        """Clean and normalize chapter title."""
        title = title.strip()
        
        # Remove common prefixes
        title = re.sub(r'^(Chapter|CHAPTER|chapter)\s*\d*[:\.]?\s*', '', title)
        
        # Remove excessive punctuation
        title = re.sub(r'[^\w\s\-\(\)]+', '', title)
        
        # Normalize whitespace
        title = re.sub(r'\s+', ' ', title)
        
        return title.strip()
    
    @staticmethod
    def extract_metadata(text: str) -> Dict[str, Any]:
        """Extract metadata from text."""
        metadata = {
            'character_count': len(text),
            'word_count': len(text.split()),
            'line_count': text.count('
'),
            'paragraph_count': len([p for p in text.split('\n
') if p.strip()]),
            'sentence_count': len(re.findall(r'[.!?]+', text)),
            'avg_word_length': 0,
            'avg_sentence_length': 0,
            'reading_time_minutes': 0
        }
        
        words = text.split()
        if words:
            metadata['avg_word_length'] = sum(len(word) for word in words) / len(words)
        
        sentences = re.findall(r'[^.!?]*[.!?]', text)
        if sentences:
            sentence_words = [len(sentence.split()) for sentence in sentences]
            metadata['avg_sentence_length'] = sum(sentence_words) / len(sentence_words)
        
        # Estimate reading time (average 200 words per minute)
        metadata['reading_time_minutes'] = metadata['word_count'] / 200
        
        return metadata
    
    @staticmethod
    def create_text_preview(text: str, max_length: int = 200) -> str:
        """Create a preview of text."""
        if len(text) <= max_length:
            return text
        
        # Try to break at sentence boundary
        truncated = text[:max_length]
        sentence_end = max(truncated.rfind('.'), truncated.rfind('!'), truncated.rfind('?'))
        
        if sentence_end > max_length * 0.5:  # If we can break at a reasonable sentence
            return truncated[:sentence_end + 1]
        else:
            # Break at word boundary
            word_boundary = truncated.rfind(' ')
            if word_boundary > 0:
                return truncated[:word_boundary] + "..."
            else:
                return truncated + "..."


class FormatDetector:
    """Detect and validate file formats."""
    
    SUPPORTED_FORMATS = {
        '.pdf': 'application/pdf',
        '.epub': 'application/epub+zip',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.doc': 'application/msword',
        '.txt': 'text/plain',
        '.md': 'text/markdown',
        '.html': 'text/html',
        '.htm': 'text/html',
        '.rtf': 'application/rtf',
        '.odt': 'application/vnd.oasis.opendocument.text',
        '.tex': 'application/x-tex'
    }
    
    @classmethod
    def is_supported_format(cls, file_path: Union[str, Path]) -> bool:
        """Check if file format is supported."""
        suffix = Path(file_path).suffix.lower()
        return suffix in cls.SUPPORTED_FORMATS
    
    @classmethod
    def get_mime_type(cls, file_path: Union[str, Path]) -> Optional[str]:
        """Get MIME type for file."""
        suffix = Path(file_path).suffix.lower()
        
        # Check our known formats first
        if suffix in cls.SUPPORTED_FORMATS:
            return cls.SUPPORTED_FORMATS[suffix]
        
        # Fall back to system detection
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type
    
    @classmethod
    def validate_file(cls, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Validate file for processing."""
        file_path = Path(file_path)
        
        validation = {
            'valid': False,
            'format_supported': False,
            'readable': False,
            'size_ok': False,
            'mime_type': None,
            'file_size': 0,
            'errors': []
        }
        
        try:
            # Check if file exists
            if not file_path.exists():
                validation['errors'].append(f"File does not exist: {file_path}")
                return validation
            
            # Check if it's a file
            if not file_path.is_file():
                validation['errors'].append(f"Path is not a file: {file_path}")
                return validation
            
            # Check format support
            validation['format_supported'] = cls.is_supported_format(file_path)
            if not validation['format_supported']:
                validation['errors'].append(f"Unsupported format: {file_path.suffix}")
            
            # Check readability
            validation['readable'] = os.access(file_path, os.R_OK)
            if not validation['readable']:
                validation['errors'].append(f"File not readable: {file_path}")
            
            # Check file size
            stat = file_path.stat()
            validation['file_size'] = stat.st_size
            max_size = 100 * 1024 * 1024  # 100MB default limit
            validation['size_ok'] = stat.st_size <= max_size
            if not validation['size_ok']:
                validation['errors'].append(f"File too large: {stat.st_size} bytes (max: {max_size})")
            
            # Get MIME type
            validation['mime_type'] = cls.get_mime_type(file_path)
            
            # Overall validation
            validation['valid'] = (
                validation['format_supported'] and 
                validation['readable'] and 
                validation['size_ok']
            )
            
        except Exception as e:
            validation['errors'].append(f"Validation error: {str(e)}")
        
        return validation


class PerformanceMonitor:
    """Monitor performance metrics."""
    
    def __init__(self):
        self.metrics = {}
        self.start_times = {}
    
    def start_timer(self, operation: str) -> str:
        """Start timing an operation."""
        timer_id = f"{operation}_{int(time.time() * 1000000)}"
        self.start_times[timer_id] = time.time()
        return timer_id
    
    def end_timer(self, timer_id: str) -> float:
        """End timing and return duration."""
        if timer_id not in self.start_times:
            return 0.0
        
        duration = time.time() - self.start_times[timer_id]
        del self.start_times[timer_id]
        return duration
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record a metric value."""
        if name not in self.metrics:
            self.metrics[name] = []
        
        self.metrics[name].append({
            'value': value,
            'timestamp': time.time(),
            'tags': tags or {}
        })
        
        # Keep only recent metrics (last 1000 entries)
        if len(self.metrics[name]) > 1000:
            self.metrics[name] = self.metrics[name][-1000:]
    
    def get_metrics_summary(self, name: str) -> Dict[str, float]:
        """Get summary statistics for a metric."""
        if name not in self.metrics or not self.metrics[name]:
            return {}
        
        values = [m['value'] for m in self.metrics[name]]
        values.sort()
        
        count = len(values)
        summary = {
            'count': count,
            'min': min(values),
            'max': max(values),
            'mean': sum(values) / count,
            'p50': values[count // 2],
            'p95': values[int(count * 0.95)] if count > 20 else values[-1],
            'p99': values[int(count * 0.99)] if count > 100 else values[-1]
        }
        
        return summary


class CacheManager:
    """Simple in-memory cache with TTL support."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        
        # Check TTL
        if time.time() > entry['expires']:
            self.delete(key)
            return None
        
        # Update access time
        self.access_times[key] = time.time()
        return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        if ttl is None:
            ttl = self.default_ttl
        
        # Evict if necessary
        if len(self.cache) >= self.max_size:
            self._evict_lru()
        
        self.cache[key] = {
            'value': value,
            'expires': time.time() + ttl,
            'created': time.time()
        }
        self.access_times[key] = time.time()
    
    def delete(self, key: str) -> bool:
        """Delete value from cache."""
        if key in self.cache:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
        self.access_times.clear()
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.access_times:
            return
        
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self.delete(lru_key)
    
    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if current_time > entry['expires']
        ]
        
        for key in expired_keys:
            self.delete(key)
        
        return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        current_time = time.time()
        expired_count = sum(
            1 for entry in self.cache.values()
            if current_time > entry['expires']
        )
        
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'expired_entries': expired_count,
            'hit_rate': getattr(self, '_hit_rate', 0.0)
        }


class SecurityHelpers:
    """Security utility functions."""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe usage."""
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        filename = re.sub(r'[^\w\-_\.]', '_', filename)
        
        # Remove multiple underscores
        filename = re.sub(r'_+', '_', filename)
        
        # Ensure reasonable length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
        
        return filename
    
    @staticmethod
    def validate_path(path: str, allowed_dirs: List[str]) -> bool:
        """Validate that path is within allowed directories."""
        try:
            abs_path = os.path.abspath(path)
            
            for allowed_dir in allowed_dirs:
                allowed_abs = os.path.abspath(allowed_dir)
                if abs_path.startswith(allowed_abs):
                    return True
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def hash_file(file_path: Union[str, Path]) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    @staticmethod
    def check_file_header(file_path: Union[str, Path], max_bytes: int = 1024) -> Dict[str, Any]:
        """Check file header for format validation."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(max_bytes)
            
            info = {
                'size': len(header),
                'is_text': True,
                'encoding': 'utf-8',
                'format_indicators': []
            }
            
            # Check for binary content
            try:
                header.decode('utf-8')
            except UnicodeDecodeError:
                info['is_text'] = False
                info['encoding'] = 'binary'
            
            # Check for format signatures
            if header.startswith(b'%PDF'):
                info['format_indicators'].append('pdf')
            elif header.startswith(b'PK\x03\x04') and b'mimetype' in header:
                info['format_indicators'].append('epub')
            elif header.startswith(b'PK\x03\x04'):
                info['format_indicators'].append('zip/docx')
            elif header.startswith(b'{\rtf'):
                info['format_indicators'].append('rtf')
            elif b'<html' in header.lower() or b'<!doctype html' in header.lower():
                info['format_indicators'].append('html')
            
            return info
            
        except Exception as e:
            return {'error': str(e)}


# Decorators for common functionality

def performance_monitor(operation_name: str):
    """Decorator to monitor performance of functions."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            monitor = PerformanceMonitor()
            timer_id = monitor.start_timer(operation_name)
            
            try:
                result = await func(*args, **kwargs)
                duration = monitor.end_timer(timer_id)
                logger.info(f"{operation_name} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = monitor.end_timer(timer_id)
                logger.error(f"{operation_name} failed after {duration:.3f}s: {e}")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            monitor = PerformanceMonitor()
            timer_id = monitor.start_timer(operation_name)
            
            try:
                result = func(*args, **kwargs)
                duration = monitor.end_timer(timer_id)
                logger.info(f"{operation_name} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = monitor.end_timer(timer_id)
                logger.error(f"{operation_name} failed after {duration:.3f}s: {e}")
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def cache_result(cache_manager: CacheManager, key_func=None, ttl=None):
    """Decorator to cache function results."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl)
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl)
            return result
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def validate_input(validator_func):
    """Decorator to validate function inputs."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            validation_result = validator_func(*args, **kwargs)
            if not validation_result.get('valid', False):
                raise ValueError(f"Input validation failed: {validation_result.get('error', 'Unknown error')}")
            
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            validation_result = validator_func(*args, **kwargs)
            if not validation_result.get('valid', False):
                raise ValueError(f"Input validation failed: {validation_result.get('error', 'Unknown error')}")
            
            return func(*args, **kwargs)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


# Global instances
global_cache = CacheManager()
global_performance_monitor = PerformanceMonitor()


def get_global_cache() -> CacheManager:
    """Get the global cache manager."""
    return global_cache


def get_global_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor."""
    return global_performance_monitor