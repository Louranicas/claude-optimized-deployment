"""
LRU Cache with TTL support for memory-bounded data structures.

This module provides a comprehensive caching solution with:
- LRU (Least Recently Used) eviction policy
- TTL (Time To Live) expiration
- Thread-safe operations
- Memory monitoring
- Configurable size limits
- Cleanup scheduling
"""

from __future__ import annotations
import asyncio
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Generic, Iterator, Optional, TypeVar, Union, Callable
from threading import RLock
import logging

__all__ = [
    "CacheConfig",
    "CacheEntry", 
    "CacheStats",
    "LRUCache",
    "TTLCache",
    "TTLDict",
    "create_lru_cache",
    "create_ttl_dict"
]


logger = logging.getLogger(__name__)

K = TypeVar('K')  # Key type
V = TypeVar('V')  # Value type


@dataclass
class CacheConfig:
    """Configuration for LRU cache."""
    max_size: int = 1000
    default_ttl: Optional[float] = None  # seconds, None for no TTL
    cleanup_interval: float = 60.0  # seconds
    enable_stats: bool = True
    memory_limit_mb: Optional[float] = None  # MB limit
    eviction_callback: Optional[Callable[[K, V], None]] = None


@dataclass
class CacheEntry:
    """Cache entry with TTL support."""
    value: Any
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    ttl: Optional[float] = None  # seconds from creation
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.ttl is None:
            return False
        return time.time() > (self.created_at + self.ttl)
    
    def touch(self) -> None:
        """Update access time."""
        self.accessed_at = time.time()
    
    def age_seconds(self) -> float:
        """Get age in seconds."""
        return time.time() - self.created_at


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    memory_bytes: int = 0
    total_size: int = 0
    
    def hit_rate(self) -> float:
        """Calculate hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "memory_bytes": self.memory_bytes,
            "memory_mb": self.memory_bytes / (1024 * 1024),
            "total_size": self.total_size,
            "hit_rate": self.hit_rate()
        }


class LRUCache(Generic[K, V]):
    """
    Thread-safe LRU cache with TTL support.
    
    Features:
    - LRU eviction when max_size is reached
    - TTL-based expiration
    - Memory monitoring
    - Thread-safe operations
    - Statistics tracking
    - Cleanup scheduling
    """
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize LRU cache."""
        self.config = config or CacheConfig()
        self._cache: OrderedDict[K, CacheEntry] = OrderedDict()
        self._lock = RLock()
        self._stats = CacheStats()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._closed = False
        
        # Start cleanup task if TTL is enabled
        if self.config.default_ttl is not None or self.config.cleanup_interval > 0:
            self._start_cleanup_task()
    
    def _start_cleanup_task(self) -> None:
        """Start background cleanup task."""
        async def cleanup_loop():
            while not self._closed:
                try:
                    await asyncio.sleep(self.config.cleanup_interval)
                    self._cleanup_expired()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Cache cleanup error: {e}")
        
        try:
            loop = asyncio.get_event_loop()
            self._cleanup_task = loop.create_task(cleanup_loop())
        except RuntimeError:
            # No event loop running, cleanup will be manual
            pass
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size in bytes."""
        try:
            import sys
            return sys.getsizeof(obj)
        except Exception:
            # Fallback estimation
            if isinstance(obj, str):
                return len(obj.encode('utf-8'))
            elif isinstance(obj, (int, float)):
                return 8
            elif isinstance(obj, (list, tuple)):
                return sum(self._estimate_size(item) for item in obj)
            elif isinstance(obj, dict):
                return sum(
                    self._estimate_size(k) + self._estimate_size(v)
                    for k, v in obj.items()
                )
            else:
                return 1024  # Default estimate
    
    def _cleanup_expired(self) -> int:
        """Remove expired entries. Returns number of removed entries."""
        removed_count = 0
        current_time = time.time()
        
        with self._lock:
            expired_keys = []
            
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                entry = self._cache.pop(key, None)
                if entry:
                    self._stats.memory_bytes -= entry.size_bytes
                    self._stats.expirations += 1
                    removed_count += 1
                    
                    # Call eviction callback
                    if self.config.eviction_callback:
                        try:
                            self.config.eviction_callback(key, entry.value)
                        except Exception as e:
                            logger.error(f"Eviction callback error: {e}")
            
            self._stats.total_size = len(self._cache)
        
        if removed_count > 0:
            logger.debug(f"Cleaned up {removed_count} expired cache entries")
        
        return removed_count
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._cache:
            return
        
        # OrderedDict maintains insertion order, oldest first
        key, entry = self._cache.popitem(last=False)
        self._stats.memory_bytes -= entry.size_bytes
        self._stats.evictions += 1
        
        # Call eviction callback
        if self.config.eviction_callback:
            try:
                self.config.eviction_callback(key, entry.value)
            except Exception as e:
                logger.error(f"Eviction callback error: {e}")
    
    def _check_memory_limit(self) -> None:
        """Check and enforce memory limits."""
        if self.config.memory_limit_mb is None:
            return
        
        memory_limit_bytes = self.config.memory_limit_mb * 1024 * 1024
        
        while self._stats.memory_bytes > memory_limit_bytes and self._cache:
            self._evict_lru()
    
    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """Get value from cache."""
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                if self.config.enable_stats:
                    self._stats.misses += 1
                return default
            
            # Check expiration
            if entry.is_expired():
                self._cache.pop(key)
                self._stats.memory_bytes -= entry.size_bytes
                self._stats.expirations += 1
                if self.config.enable_stats:
                    self._stats.misses += 1
                return default
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.touch()
            
            if self.config.enable_stats:
                self._stats.hits += 1
            
            return entry.value
    
    def put(
        self,
        key: K,
        value: V,
        ttl: Optional[float] = None
    ) -> None:
        """Put value in cache."""
        if ttl is None:
            ttl = self.config.default_ttl
        
        size_bytes = self._estimate_size(value)
        
        with self._lock:
            # Remove existing entry if present
            if key in self._cache:
                old_entry = self._cache.pop(key)
                self._stats.memory_bytes -= old_entry.size_bytes
            
            # Create new entry
            entry = CacheEntry(
                value=value,
                ttl=ttl,
                size_bytes=size_bytes
            )
            
            # Check size limit before adding
            while len(self._cache) >= self.config.max_size:
                self._evict_lru()
            
            # Add new entry
            self._cache[key] = entry
            self._stats.memory_bytes += size_bytes
            self._stats.total_size = len(self._cache)
            
            # Check memory limit
            self._check_memory_limit()
    
    def delete(self, key: K) -> bool:
        """Delete key from cache. Returns True if key existed."""
        with self._lock:
            entry = self._cache.pop(key, None)
            if entry:
                self._stats.memory_bytes -= entry.size_bytes
                self._stats.total_size = len(self._cache)
                return True
            return False
    
    def contains(self, key: K) -> bool:
        """Check if key exists and is not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            
            if entry.is_expired():
                self._cache.pop(key)
                self._stats.memory_bytes -= entry.size_bytes
                self._stats.expirations += 1
                return False
            
            return True
    
    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._cache.clear()
            self._stats.memory_bytes = 0
            self._stats.total_size = 0
    
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)
    
    def is_empty(self) -> bool:
        """Check if cache is empty."""
        return len(self._cache) == 0
    
    def keys(self) -> Iterator[K]:
        """Get all keys (snapshot)."""
        with self._lock:
            return iter(list(self._cache.keys()))
    
    def items(self) -> Iterator[tuple[K, V]]:
        """Get all key-value pairs (snapshot)."""
        with self._lock:
            items = []
            for key, entry in self._cache.items():
                if not entry.is_expired():
                    items.append((key, entry.value))
            return iter(items)
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            # Update current stats
            self._stats.total_size = len(self._cache)
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                expirations=self._stats.expirations,
                memory_bytes=self._stats.memory_bytes,
                total_size=self._stats.total_size
            )
    
    def cleanup(self) -> int:
        """Manual cleanup of expired entries."""
        return self._cleanup_expired()
    
    async def close(self) -> None:
        """Close cache and cleanup resources."""
        self._closed = True
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.clear()
    
    def __len__(self) -> int:
        """Get cache size."""
        return len(self._cache)
    
    def __contains__(self, key: K) -> bool:
        """Check if key is in cache."""
        return self.contains(key)
    
    def __getitem__(self, key: K) -> V:
        """Get item with [] operator."""
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value
    
    def __setitem__(self, key: K, value: V) -> None:
        """Set item with [] operator."""
        self.put(key, value)
    
    def __delitem__(self, key: K) -> None:
        """Delete item with del operator."""
        if not self.delete(key):
            raise KeyError(key)


class TTLDict(Dict[K, V]):
    """
    Dictionary with TTL support that mimics standard dict interface.
    Built on top of LRUCache for memory safety.
    """
    
    def __init__(
        self,
        default_ttl: Optional[float] = None,
        max_size: int = 1000,
        cleanup_interval: float = 60.0
    ):
        """Initialize TTL dictionary."""
        super().__init__()
        self._cache = LRUCache[K, V](CacheConfig(
            max_size=max_size,
            default_ttl=default_ttl,
            cleanup_interval=cleanup_interval
        ))
    
    def __getitem__(self, key: K) -> V:
        """Get item."""
        value = self._cache.get(key)
        if value is None:
            raise KeyError(key)
        return value
    
    def __setitem__(self, key: K, value: V) -> None:
        """Set item."""
        self._cache.put(key, value)
    
    def __delitem__(self, key: K) -> None:
        """Delete item."""
        if not self._cache.delete(key):
            raise KeyError(key)
    
    def __contains__(self, key: K) -> bool:
        """Check if key exists."""
        return self._cache.contains(key)
    
    def __len__(self) -> int:
        """Get size."""
        return len(self._cache)
    
    def __iter__(self) -> Iterator[K]:
        """Iterate over keys."""
        return self._cache.keys()
    
    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """Get with default."""
        return self._cache.get(key, default)
    
    def pop(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """Pop item."""
        value = self._cache.get(key, default)
        if value is not default:
            self._cache.delete(key)
        return value
    
    def clear(self) -> None:
        """Clear all items."""
        self._cache.clear()
    
    def keys(self) -> Iterator[K]:
        """Get keys."""
        return self._cache.keys()
    
    def items(self) -> Iterator[tuple[K, V]]:
        """Get items."""
        return self._cache.items()
    
    def put_with_ttl(self, key: K, value: V, ttl: float) -> None:
        """Put item with specific TTL."""
        self._cache.put(key, value, ttl)
    
    def cleanup(self) -> int:
        """Cleanup expired entries."""
        return self._cache.cleanup()
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        return self._cache.get_stats()
    
    async def close(self) -> None:
        """Close and cleanup."""
        await self._cache.close()


# Factory functions for convenience
def create_lru_cache(
    max_size: int = 1000,
    ttl: Optional[float] = None,
    cleanup_interval: float = 60.0,
    memory_limit_mb: Optional[float] = None
) -> LRUCache:
    """Create LRU cache with common settings."""
    config = CacheConfig(
        max_size=max_size,
        default_ttl=ttl,
        cleanup_interval=cleanup_interval,
        memory_limit_mb=memory_limit_mb,
        enable_stats=True
    )
    return LRUCache(config)


def create_ttl_dict(
    max_size: int = 1000,
    ttl: Optional[float] = None,
    cleanup_interval: float = 60.0
) -> TTLDict:
    """Create TTL dictionary with common settings."""
    return TTLDict(
        default_ttl=ttl,
        max_size=max_size,
        cleanup_interval=cleanup_interval
    )


# Alias for compatibility
TTLCache = LRUCache