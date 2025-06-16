"""
High-performance caching for Academic MCP
LRU cache with async support and persistence
"""

import asyncio
from typing import Dict, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass
import time
import pickle
import aiofiles
from pathlib import Path
import hashlib
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheEntry(Generic[T]):
    """Cache entry with metadata"""
    value: T
    timestamp: float
    ttl: float
    access_count: int = 0
    size_bytes: int = 0


class AsyncLRUCache(Generic[T]):
    """
    Async-aware LRU cache with persistence
    Optimized for academic search results
    """
    
    def __init__(
        self,
        max_size: int = 1000,
        ttl: float = 3600,
        persist_path: Optional[Path] = None
    ):
        self.max_size = max_size
        self.default_ttl = ttl
        self.persist_path = persist_path
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }
        
        # Load persisted cache if available
        if persist_path:
            asyncio.create_task(self._load_cache())
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = f"{args}:{sorted(kwargs.items())}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    async def get(self, key: str) -> Optional[T]:
        """Get value from cache"""
        async with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None
            
            entry = self._cache[key]
            
            # Check TTL
            if time.time() - entry.timestamp > entry.ttl:
                del self._cache[key]
                self._stats["misses"] += 1
                return None
            
            # Update LRU order
            self._cache.move_to_end(key)
            entry.access_count += 1
            
            self._stats["hits"] += 1
            return entry.value
    
    async def set(
        self,
        key: str,
        value: T,
        ttl: Optional[float] = None
    ) -> None:
        """Set value in cache"""
        async with self._lock:
            # Calculate size
            try:
                size_bytes = len(pickle.dumps(value))
            except:
                size_bytes = 0
            
            # Create entry
            entry = CacheEntry(
                value=value,
                timestamp=time.time(),
                ttl=ttl or self.default_ttl,
                size_bytes=size_bytes
            )
            
            # Add to cache
            self._cache[key] = entry
            self._cache.move_to_end(key)
            
            # Evict if necessary
            while len(self._cache) > self.max_size:
                evicted_key = next(iter(self._cache))
                del self._cache[evicted_key]
                self._stats["evictions"] += 1
            
            # Persist if configured
            if self.persist_path:
                asyncio.create_task(self._persist_cache())
    
    async def _load_cache(self) -> None:
        """Load cache from disk"""
        if not self.persist_path or not self.persist_path.exists():
            return
        
        try:
            async with aiofiles.open(self.persist_path, 'rb') as f:
                data = await f.read()
                self._cache = pickle.loads(data)
                logger.info(f"Loaded {len(self._cache)} cache entries")
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
    
    async def _persist_cache(self) -> None:
        """Persist cache to disk"""
        if not self.persist_path:
            return
        
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(self.persist_path, 'wb') as f:
                data = pickle.dumps(self._cache)
                await f.write(data)
        except Exception as e:
            logger.error(f"Failed to persist cache: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total_requests if total_requests > 0 else 0
        
        return {
            **self._stats,
            "size": len(self._cache),
            "hit_rate": hit_rate,
            "total_requests": total_requests
        }


def cached(
    cache: AsyncLRUCache,
    ttl: Optional[float] = None,
    key_func: Optional[Callable] = None
):
    """Decorator for caching async function results"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = cache._generate_key(*args, **kwargs)
            
            # Check cache
            result = await cache.get(cache_key)
            if result is not None:
                return result
            
            # Call function
            result = await func(*args, **kwargs)
            
            # Store in cache
            await cache.set(cache_key, result, ttl)
            
            return result
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


class SearchResultCache:
    """Specialized cache for search results"""
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Different caches for different types
        self.search_cache = AsyncLRUCache(
            max_size=500,
            ttl=3600,  # 1 hour
            persist_path=cache_dir / "search.cache"
        )
        
        self.paper_cache = AsyncLRUCache(
            max_size=2000,
            ttl=86400,  # 24 hours
            persist_path=cache_dir / "papers.cache"
        )
        
        self.citation_cache = AsyncLRUCache(
            max_size=1000,
            ttl=604800,  # 1 week
            persist_path=cache_dir / "citations.cache"
        )
    
    async def get_search_results(self, query: str, filters: Dict) -> Optional[Any]:
        """Get cached search results"""
        key = f"search:{query}:{sorted(filters.items())}"
        return await self.search_cache.get(key)
    
    async def cache_search_results(
        self,
        query: str,
        filters: Dict,
        results: Any
    ) -> None:
        """Cache search results"""
        key = f"search:{query}:{sorted(filters.items())}"
        await self.search_cache.set(key, results)
    
    async def get_paper(self, paper_id: str) -> Optional[Any]:
        """Get cached paper"""
        return await self.paper_cache.get(f"paper:{paper_id}")
    
    async def cache_paper(self, paper_id: str, paper: Any) -> None:
        """Cache paper"""
        await self.paper_cache.set(f"paper:{paper_id}", paper)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "search": self.search_cache.get_stats(),
            "papers": self.paper_cache.get_stats(),
            "citations": self.citation_cache.get_stats()
        }
