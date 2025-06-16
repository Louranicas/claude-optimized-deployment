"""
MCP Performance Caching System
Agent 7: Advanced caching mechanisms for MCP server operations.

This module provides intelligent caching for MCP tool results, server metadata,
and connection pools to significantly improve performance and reduce resource usage.
"""

import asyncio
import time
import json
import hashlib
import pickle
from typing import Dict, Any, Optional, List, Union, Callable, TypeVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
import weakref
import logging
from contextlib import asynccontextmanager
from enum import Enum
import threading

from .lru_cache import create_ttl_dict
from .cleanup_scheduler import get_cleanup_scheduler

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheStrategy(Enum):
    """Cache strategies for different types of data."""
    NO_CACHE = "no_cache"
    TTL_CACHE = "ttl_cache"  # Time-to-live cache
    LRU_CACHE = "lru_cache"  # Least recently used
    WRITE_THROUGH = "write_through"  # Write to cache and storage
    WRITE_BACK = "write_back"  # Write to cache, flush later
    READ_THROUGH = "read_through"  # Read from cache, fallback to storage


@dataclass
class CacheConfig:
    """Configuration for caching behavior."""
    strategy: CacheStrategy = CacheStrategy.TTL_CACHE
    max_size: int = 1000
    ttl_seconds: float = 300.0  # 5 minutes
    compression: bool = True
    encryption: bool = False
    warmup_enabled: bool = True
    prefetch_enabled: bool = True
    cleanup_interval: float = 60.0  # 1 minute
    memory_limit_mb: int = 100
    eviction_threshold: float = 0.8  # 80% of max size


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int = 0
    size_bytes: int = 0
    ttl_seconds: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl_seconds is None:
            return False
        return (datetime.now() - self.created_at).total_seconds() > self.ttl_seconds
    
    def touch(self):
        """Update access timestamp and increment access count."""
        self.accessed_at = datetime.now()
        self.access_count += 1


@dataclass
class CacheStats:
    """Cache performance statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    memory_usage_bytes: int = 0
    avg_access_time_ms: float = 0.0
    hit_rate: float = 0.0
    last_cleanup: Optional[datetime] = None
    
    def update_hit_rate(self):
        """Update hit rate calculation."""
        total = self.hits + self.misses
        self.hit_rate = (self.hits / total) if total > 0 else 0.0


class MCPCache:
    """
    High-performance cache for MCP operations with multiple strategies.
    
    Features:
    - Multiple cache strategies (TTL, LRU, write-through, etc.)
    - Intelligent prefetching and warming
    - Memory management and compression
    - Thread-safe operations
    - Performance monitoring
    """
    
    def __init__(self, config: Optional[CacheConfig] = None):
        self.config = config or CacheConfig()
        self._entries: Dict[str, CacheEntry] = {}
        self._access_order = OrderedDict()  # For LRU tracking
        self._tags_index: Dict[str, set] = defaultdict(set)
        self._stats = CacheStats()
        self._lock = asyncio.Lock()
        self._memory_lock = threading.RLock()
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._prefetch_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        # Prefetch patterns
        self._access_patterns: Dict[str, List[datetime]] = defaultdict(list)
        self._prediction_cache: Dict[str, float] = {}
        
        # Register with cleanup scheduler
        try:
            cleanup_scheduler = get_cleanup_scheduler()
            cleanup_scheduler.register_task(
                name=f"mcp_cache_{id(self)}_cleanup",
                callback=self._cleanup_expired,
                interval_seconds=self.config.cleanup_interval,
                priority=cleanup_scheduler.TaskPriority.LOW
            )
        except Exception as e:
            logger.warning(f"Could not register with cleanup scheduler: {e}")
    
    async def initialize(self):
        """Initialize the cache system."""
        if self._is_running:
            return
        
        self._is_running = True
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        if self.config.prefetch_enabled:
            self._prefetch_task = asyncio.create_task(self._prefetch_loop())
        
        logger.info(f"MCP Cache initialized with strategy: {self.config.strategy.value}")
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        start_time = time.time()
        
        async with self._lock:
            entry = self._entries.get(key)
            
            # Cache miss
            if entry is None or entry.is_expired():
                self._stats.misses += 1
                self._record_access_time(time.time() - start_time)
                
                # Remove expired entry
                if entry is not None:
                    await self._remove_entry(key)
                
                return default
            
            # Cache hit
            self._stats.hits += 1
            entry.touch()
            
            # Update LRU order
            if self.config.strategy == CacheStrategy.LRU_CACHE:
                self._access_order.move_to_end(key)
            
            # Record access pattern for prefetching
            self._record_access_pattern(key)
            
            self._record_access_time(time.time() - start_time)
            self._stats.update_hit_rate()
            
            return entry.value
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[float] = None,
        tags: Optional[List[str]] = None
    ) -> bool:
        """Set value in cache."""
        if self.config.strategy == CacheStrategy.NO_CACHE:
            return False
        
        async with self._lock:
            # Check if we need to evict entries
            await self._ensure_capacity()
            
            # Calculate entry size
            size_bytes = self._calculate_size(value)
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                accessed_at=datetime.now(),
                size_bytes=size_bytes,
                ttl_seconds=ttl or self.config.ttl_seconds,
                tags=tags or []
            )
            
            # Add to cache
            self._entries[key] = entry
            
            # Update LRU order
            if self.config.strategy == CacheStrategy.LRU_CACHE:
                self._access_order[key] = None
            
            # Update tags index
            for tag in entry.tags:
                self._tags_index[tag].add(key)
            
            # Update statistics
            self._stats.size += 1
            self._stats.memory_usage_bytes += size_bytes
            
            logger.debug(f"Cached key '{key}' with size {size_bytes} bytes")
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        async with self._lock:
            if key in self._entries:
                await self._remove_entry(key)
                return True
            return False
    
    async def delete_by_tag(self, tag: str) -> int:
        """Delete all entries with a specific tag."""
        async with self._lock:
            keys = list(self._tags_index.get(tag, set()))
            count = 0
            
            for key in keys:
                if key in self._entries:
                    await self._remove_entry(key)
                    count += 1
            
            # Clean up tags index
            del self._tags_index[tag]
            
            logger.info(f"Deleted {count} entries with tag '{tag}'")
            return count
    
    async def clear(self):
        """Clear all cache entries."""
        async with self._lock:
            self._entries.clear()
            self._access_order.clear()
            self._tags_index.clear()
            self._stats = CacheStats()
            logger.info("Cache cleared")
    
    async def warm_up(self, warm_up_data: Dict[str, Any]):
        """Warm up cache with frequently accessed data."""
        if not self.config.warmup_enabled:
            return
        
        logger.info(f"Warming up cache with {len(warm_up_data)} entries")
        
        for key, value in warm_up_data.items():
            await self.set(key, value, tags=["warmup"])
    
    async def _ensure_capacity(self):
        """Ensure cache doesn't exceed memory limits."""
        # Check size-based eviction
        if self._stats.size >= self.config.max_size * self.config.eviction_threshold:
            await self._evict_entries(count=int(self.config.max_size * 0.1))
        
        # Check memory-based eviction
        memory_limit_bytes = self.config.memory_limit_mb * 1024 * 1024
        if self._stats.memory_usage_bytes >= memory_limit_bytes * self.config.eviction_threshold:
            await self._evict_entries_by_memory(target_reduction=0.2)
    
    async def _evict_entries(self, count: int):
        """Evict entries based on cache strategy."""
        if self.config.strategy == CacheStrategy.LRU_CACHE:
            # Evict least recently used
            keys_to_evict = list(self._access_order.keys())[:count]
        else:
            # Evict oldest entries
            entries_by_age = sorted(
                self._entries.items(),
                key=lambda x: x[1].created_at
            )
            keys_to_evict = [key for key, _ in entries_by_age[:count]]
        
        for key in keys_to_evict:
            await self._remove_entry(key)
            self._stats.evictions += 1
        
        logger.debug(f"Evicted {len(keys_to_evict)} entries")
    
    async def _evict_entries_by_memory(self, target_reduction: float):
        """Evict entries to reduce memory usage."""
        target_bytes = int(self._stats.memory_usage_bytes * target_reduction)
        freed_bytes = 0
        evicted_count = 0
        
        # Sort by size (largest first) for efficient memory reduction
        entries_by_size = sorted(
            self._entries.items(),
            key=lambda x: x[1].size_bytes,
            reverse=True
        )
        
        for key, entry in entries_by_size:
            if freed_bytes >= target_bytes:
                break
            
            freed_bytes += entry.size_bytes
            await self._remove_entry(key)
            evicted_count += 1
            self._stats.evictions += 1
        
        logger.debug(f"Evicted {evicted_count} entries, freed {freed_bytes} bytes")
    
    async def _remove_entry(self, key: str):
        """Remove entry and update all tracking structures."""
        entry = self._entries.get(key)
        if entry is None:
            return
        
        # Remove from main cache
        del self._entries[key]
        
        # Remove from LRU tracking
        self._access_order.pop(key, None)
        
        # Remove from tags index
        for tag in entry.tags:
            self._tags_index[tag].discard(key)
            if not self._tags_index[tag]:
                del self._tags_index[tag]
        
        # Update statistics
        self._stats.size -= 1
        self._stats.memory_usage_bytes -= entry.size_bytes
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of cached value."""
        try:
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (int, float, bool)):
                return 8  # Approximate
            elif isinstance(value, (list, tuple, dict)):
                return len(pickle.dumps(value))
            else:
                return len(str(value).encode('utf-8'))
        except Exception:
            return 1024  # Default fallback
    
    def _record_access_pattern(self, key: str):
        """Record access pattern for prefetching predictions."""
        now = datetime.now()
        patterns = self._access_patterns[key]
        patterns.append(now)
        
        # Keep only recent patterns (last hour)
        cutoff = now - timedelta(hours=1)
        self._access_patterns[key] = [t for t in patterns if t > cutoff]
    
    def _predict_next_access(self, key: str) -> Optional[datetime]:
        """Predict when a key might be accessed next."""
        patterns = self._access_patterns.get(key, [])
        if len(patterns) < 2:
            return None
        
        # Simple prediction based on average interval
        intervals = []
        for i in range(1, len(patterns)):
            interval = (patterns[i] - patterns[i-1]).total_seconds()
            intervals.append(interval)
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            return patterns[-1] + timedelta(seconds=avg_interval)
        
        return None
    
    def _record_access_time(self, duration: float):
        """Record access time for performance tracking."""
        duration_ms = duration * 1000
        
        # Simple moving average
        if self._stats.avg_access_time_ms == 0:
            self._stats.avg_access_time_ms = duration_ms
        else:
            # Weight recent measurements more heavily
            self._stats.avg_access_time_ms = (
                self._stats.avg_access_time_ms * 0.8 + 
                duration_ms * 0.2
            )
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._is_running:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
    
    async def _cleanup_expired(self) -> int:
        """Clean up expired entries."""
        async with self._lock:
            expired_keys = []
            now = datetime.now()
            
            for key, entry in self._entries.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                await self._remove_entry(key)
            
            self._stats.last_cleanup = now
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
            
            return len(expired_keys)
    
    async def _prefetch_loop(self):
        """Background prefetching loop."""
        while self._is_running:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._prefetch_predicted()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Prefetch error: {e}")
    
    async def _prefetch_predicted(self):
        """Prefetch data based on access patterns."""
        # This is a placeholder for intelligent prefetching
        # In a real implementation, this would analyze patterns
        # and prefetch likely-to-be-accessed data
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        return {
            "hits": self._stats.hits,
            "misses": self._stats.misses,
            "hit_rate": self._stats.hit_rate,
            "evictions": self._stats.evictions,
            "size": self._stats.size,
            "max_size": self.config.max_size,
            "memory_usage_mb": self._stats.memory_usage_bytes / 1024 / 1024,
            "memory_limit_mb": self.config.memory_limit_mb,
            "avg_access_time_ms": self._stats.avg_access_time_ms,
            "last_cleanup": self._stats.last_cleanup.isoformat() if self._stats.last_cleanup else None,
            "strategy": self.config.strategy.value
        }
    
    async def shutdown(self):
        """Shutdown cache and cleanup resources."""
        self._is_running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._prefetch_task:
            self._prefetch_task.cancel()
            try:
                await self._prefetch_task
            except asyncio.CancelledError:
                pass
        
        await self.clear()
        logger.info("MCP Cache shutdown complete")


class MCPToolCache:
    """
    Specialized cache for MCP tool results with intelligent invalidation.
    """
    
    def __init__(self, cache: MCPCache):
        self.cache = cache
        
        # Tool-specific cache configurations
        self.tool_configs = {
            # Fast, frequently accessed tools
            "brave_web_search": CacheConfig(ttl_seconds=300, max_size=100),
            "docker_ps": CacheConfig(ttl_seconds=30, max_size=50),
            "kubectl_get": CacheConfig(ttl_seconds=60, max_size=100),
            
            # Slow, expensive tools (cache longer)
            "security_scan": CacheConfig(ttl_seconds=3600, max_size=20),
            "npm_audit": CacheConfig(ttl_seconds=1800, max_size=30),
            "vulnerability_scan": CacheConfig(ttl_seconds=3600, max_size=20),
            
            # Dynamic tools (short cache)
            "system_stats": CacheConfig(ttl_seconds=10, max_size=10),
            "process_list": CacheConfig(ttl_seconds=5, max_size=5),
        }
    
    def _make_cache_key(self, server: str, tool: str, args: Dict[str, Any]) -> str:
        """Create cache key for tool call."""
        # Create deterministic hash of arguments
        args_str = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode()).hexdigest()[:16]
        return f"tool:{server}:{tool}:{args_hash}"
    
    async def get_tool_result(
        self, 
        server: str, 
        tool: str, 
        args: Dict[str, Any]
    ) -> Optional[Any]:
        """Get cached tool result."""
        cache_key = self._make_cache_key(server, tool, args)
        return await self.cache.get(cache_key)
    
    async def cache_tool_result(
        self, 
        server: str, 
        tool: str, 
        args: Dict[str, Any], 
        result: Any
    ) -> bool:
        """Cache tool result with appropriate TTL."""
        cache_key = self._make_cache_key(server, tool, args)
        
        # Get tool-specific configuration
        config = self.tool_configs.get(tool, CacheConfig())
        
        # Add tags for invalidation
        tags = [f"server:{server}", f"tool:{tool}"]
        
        return await self.cache.set(
            cache_key, 
            result, 
            ttl=config.ttl_seconds,
            tags=tags
        )
    
    async def invalidate_server(self, server: str):
        """Invalidate all cached results for a server."""
        return await self.cache.delete_by_tag(f"server:{server}")
    
    async def invalidate_tool(self, tool: str):
        """Invalidate all cached results for a tool."""
        return await self.cache.delete_by_tag(f"tool:{tool}")


# Global cache instances
_mcp_cache: Optional[MCPCache] = None
_tool_cache: Optional[MCPToolCache] = None


async def get_mcp_cache() -> MCPCache:
    """Get global MCP cache instance."""
    global _mcp_cache
    if _mcp_cache is None:
        _mcp_cache = MCPCache()
        await _mcp_cache.initialize()
    return _mcp_cache


async def get_tool_cache() -> MCPToolCache:
    """Get global tool cache instance."""
    global _tool_cache
    if _tool_cache is None:
        cache = await get_mcp_cache()
        _tool_cache = MCPToolCache(cache)
    return _tool_cache


# Decorator for caching tool results
def cache_tool_result(ttl: Optional[float] = None, tags: Optional[List[str]] = None):
    """Decorator to cache MCP tool results."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get cache
            tool_cache = await get_tool_cache()
            
            # Try to get from cache first
            # Note: This is simplified - in practice you'd need to extract
            # server, tool, and args from the function parameters
            
            # Execute function if not in cache
            result = await func(*args, **kwargs)
            
            # Cache the result
            # Note: Implementation would depend on function signature
            
            return result
        
        return wrapper
    return decorator


__all__ = [
    "CacheStrategy",
    "CacheConfig", 
    "CacheEntry",
    "CacheStats",
    "MCPCache",
    "MCPToolCache",
    "get_mcp_cache",
    "get_tool_cache",
    "cache_tool_result"
]