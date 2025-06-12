"""
Object Pool Implementation for Memory Optimization

This module provides object pooling utilities to reduce allocation pressure
and improve garbage collection performance by reusing objects.
"""

import threading
import weakref
from abc import ABC, abstractmethod
from collections import deque
from typing import Generic, TypeVar, Optional, Dict, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class PoolStatistics:
    """Statistics for object pool performance"""
    pool_name: str
    created_count: int = 0
    reused_count: int = 0
    destroyed_count: int = 0
    current_size: int = 0
    max_size: int = 0
    hit_rate: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    
    def update_hit_rate(self):
        """Update the cache hit rate"""
        total_requests = self.created_count + self.reused_count
        if total_requests > 0:
            self.hit_rate = self.reused_count / total_requests
        self.last_updated = datetime.now()


class Poolable(ABC):
    """Abstract base class for poolable objects"""
    
    @abstractmethod
    def reset(self):
        """Reset object state for reuse"""
        pass
        
    @abstractmethod
    def is_valid(self) -> bool:
        """Check if object is still valid for reuse"""
        return True


class ObjectPool(Generic[T]):
    """
    Generic object pool for memory optimization.
    
    Provides thread-safe object pooling with automatic cleanup,
    size limits, and performance monitoring.
    """
    
    def __init__(
        self,
        factory: Callable[[], T],
        max_size: int = 100,
        cleanup_interval: int = 300,  # 5 minutes
        max_idle_time: int = 600,     # 10 minutes
        name: str = "default"
    ):
        self.factory = factory
        self.max_size = max_size
        self.cleanup_interval = cleanup_interval
        self.max_idle_time = max_idle_time
        self.name = name
        
        self._pool: deque = deque()
        self._lock = threading.RLock()
        self._timestamps: Dict[int, datetime] = {}
        self._statistics = PoolStatistics(pool_name=name, max_size=max_size)
        self._last_cleanup = datetime.now()
        
    def acquire(self) -> T:
        """
        Acquire an object from the pool.
        
        Returns:
            Object from pool or newly created object
        """
        with self._lock:
            # Try to get from pool
            while self._pool:
                obj = self._pool.popleft()
                obj_id = id(obj)
                
                # Remove timestamp
                self._timestamps.pop(obj_id, None)
                
                # Check if object is still valid
                if hasattr(obj, 'is_valid') and callable(obj.is_valid):
                    if not obj.is_valid():
                        self._statistics.destroyed_count += 1
                        continue
                        
                # Reset object state
                if hasattr(obj, 'reset') and callable(obj.reset):
                    try:
                        obj.reset()
                    except Exception as e:
                        logger.warning(f"Failed to reset pooled object: {e}")
                        self._statistics.destroyed_count += 1
                        continue
                        
                self._statistics.reused_count += 1
                self._statistics.current_size = len(self._pool)
                self._statistics.update_hit_rate()
                
                logger.debug(f"Reused object from pool {self.name}")
                return obj
                
            # No valid objects in pool, create new one
            try:
                obj = self.factory()
                self._statistics.created_count += 1
                self._statistics.update_hit_rate()
                
                logger.debug(f"Created new object for pool {self.name}")
                return obj
            except Exception as e:
                logger.error(f"Failed to create object for pool {self.name}: {e}")
                raise
                
    def release(self, obj: T):
        """
        Release an object back to the pool.
        
        Args:
            obj: Object to return to pool
        """
        if obj is None:
            return
            
        with self._lock:
            # Check pool size limit
            if len(self._pool) >= self.max_size:
                self._statistics.destroyed_count += 1
                logger.debug(f"Pool {self.name} at capacity, discarding object")
                return
                
            # Add to pool with timestamp
            self._pool.append(obj)
            self._timestamps[id(obj)] = datetime.now()
            self._statistics.current_size = len(self._pool)
            
            logger.debug(f"Returned object to pool {self.name}")
            
            # Periodic cleanup
            if self._should_cleanup():
                self._cleanup_expired()
                
    def _should_cleanup(self) -> bool:
        """Check if cleanup should be performed"""
        return (datetime.now() - self._last_cleanup).total_seconds() > self.cleanup_interval
        
    def _cleanup_expired(self):
        """Remove expired objects from pool"""
        with self._lock:
            current_time = datetime.now()
            expired_ids = []
            
            # Find expired objects
            for obj_id, timestamp in self._timestamps.items():
                if (current_time - timestamp).total_seconds() > self.max_idle_time:
                    expired_ids.append(obj_id)
                    
            # Remove expired objects
            if expired_ids:
                new_pool = deque()
                for obj in self._pool:
                    if id(obj) not in expired_ids:
                        new_pool.append(obj)
                    else:
                        self._statistics.destroyed_count += 1
                        
                self._pool = new_pool
                
                # Clean up timestamps
                for obj_id in expired_ids:
                    self._timestamps.pop(obj_id, None)
                    
                self._statistics.current_size = len(self._pool)
                self._last_cleanup = current_time
                
                logger.info(f"Cleaned up {len(expired_ids)} expired objects from pool {self.name}")
                
    def clear(self):
        """Clear all objects from the pool"""
        with self._lock:
            destroyed_count = len(self._pool)
            self._pool.clear()
            self._timestamps.clear()
            self._statistics.destroyed_count += destroyed_count
            self._statistics.current_size = 0
            
            logger.info(f"Cleared pool {self.name}, destroyed {destroyed_count} objects")
            
    def get_statistics(self) -> PoolStatistics:
        """Get pool performance statistics"""
        with self._lock:
            self._statistics.current_size = len(self._pool)
            self._statistics.update_hit_rate()
            return self._statistics
            
    def resize(self, new_max_size: int):
        """Resize the pool maximum capacity"""
        with self._lock:
            old_size = self.max_size
            self.max_size = new_max_size
            self._statistics.max_size = new_max_size
            
            # If shrinking, remove excess objects
            if new_max_size < len(self._pool):
                excess = len(self._pool) - new_max_size
                for _ in range(excess):
                    obj = self._pool.pop()
                    self._timestamps.pop(id(obj), None)
                    self._statistics.destroyed_count += 1
                    
                self._statistics.current_size = len(self._pool)
                
            logger.info(f"Resized pool {self.name} from {old_size} to {new_max_size}")


class PooledObject:
    """
    Base class for objects that can be pooled.
    
    Provides automatic reset functionality and validation.
    """
    
    def __init__(self):
        self._created_at = datetime.now()
        self._reset_count = 0
        
    def reset(self):
        """Reset object state for reuse"""
        self._reset_count += 1
        # Override in subclasses for specific reset logic
        
    def is_valid(self) -> bool:
        """Check if object is valid for reuse"""
        # Basic validation - object not too old or reset too many times
        age = (datetime.now() - self._created_at).total_seconds()
        return age < 3600 and self._reset_count < 100  # 1 hour max age, 100 reuses max


# Common object pools
class StringBuilderPool:
    """Pool for string building operations"""
    
    class StringBuilder(PooledObject):
        def __init__(self):
            super().__init__()
            self.parts = []
            
        def append(self, text: str):
            self.parts.append(text)
            return self
            
        def build(self) -> str:
            return ''.join(self.parts)
            
        def reset(self):
            super().reset()
            self.parts.clear()
            
    _pool = ObjectPool(factory=lambda: StringBuilderPool.StringBuilder(), max_size=50, name="StringBuilder")
    
    @classmethod
    def acquire(cls) -> 'StringBuilderPool.StringBuilder':
        return cls._pool.acquire()
        
    @classmethod
    def release(cls, obj: 'StringBuilderPool.StringBuilder'):
        cls._pool.release(obj)
        
    @classmethod
    def get_statistics(cls) -> PoolStatistics:
        return cls._pool.get_statistics()


class DictPool:
    """Pool for dictionary objects"""
    
    class PooledDict(dict, PooledObject):
        def __init__(self):
            dict.__init__(self)
            PooledObject.__init__(self)
            
        def reset(self):
            super().reset()
            self.clear()
            
    _pool = ObjectPool(factory=lambda: DictPool.PooledDict(), max_size=100, name="Dict")
    
    @classmethod
    def acquire(cls) -> 'DictPool.PooledDict':
        return cls._pool.acquire()
        
    @classmethod
    def release(cls, obj: 'DictPool.PooledDict'):
        cls._pool.release(obj)
        
    @classmethod
    def get_statistics(cls) -> PoolStatistics:
        return cls._pool.get_statistics()


class ListPool:
    """Pool for list objects"""
    
    class PooledList(list, PooledObject):
        def __init__(self):
            list.__init__(self)
            PooledObject.__init__(self)
            
        def reset(self):
            super().reset()
            self.clear()
            
    _pool = ObjectPool(factory=lambda: ListPool.PooledList(), max_size=100, name="List")
    
    @classmethod
    def acquire(cls) -> 'ListPool.PooledList':
        return cls._pool.acquire()
        
    @classmethod
    def release(cls, obj: 'ListPool.PooledList'):
        cls._pool.release(obj)
        
    @classmethod
    def get_statistics(cls) -> PoolStatistics:
        return cls._pool.get_statistics()


# Pool manager for centralized control
class PoolManager:
    """Centralized manager for all object pools"""
    
    _pools: Dict[str, ObjectPool] = {}
    _lock = threading.Lock()
    
    @classmethod
    def register_pool(cls, name: str, pool: ObjectPool):
        """Register a pool with the manager"""
        with cls._lock:
            cls._pools[name] = pool
            logger.info(f"Registered pool: {name}")
            
    @classmethod
    def get_pool(cls, name: str) -> Optional[ObjectPool]:
        """Get a pool by name"""
        with cls._lock:
            return cls._pools.get(name)
            
    @classmethod
    def get_all_statistics(cls) -> Dict[str, PoolStatistics]:
        """Get statistics for all registered pools"""
        with cls._lock:
            stats = {}
            for name, pool in cls._pools.items():
                stats[name] = pool.get_statistics()
            return stats
            
    @classmethod
    def cleanup_all_pools(cls):
        """Trigger cleanup for all pools"""
        with cls._lock:
            for pool in cls._pools.values():
                pool._cleanup_expired()
                
    @classmethod
    def clear_all_pools(cls):
        """Clear all pools"""
        with cls._lock:
            for pool in cls._pools.values():
                pool.clear()
                
    @classmethod
    def get_total_memory_impact(cls) -> Dict[str, int]:
        """Get estimated memory impact of all pools"""
        with cls._lock:
            impact = {
                "total_objects": 0,
                "estimated_memory_mb": 0
            }
            
            for pool in cls._pools.values():
                stats = pool.get_statistics()
                impact["total_objects"] += stats.current_size
                # Rough estimate: 1KB per object
                impact["estimated_memory_mb"] += stats.current_size * 0.001
                
            return impact


# Register common pools
PoolManager.register_pool("StringBuilder", StringBuilderPool._pool)
PoolManager.register_pool("Dict", DictPool._pool)
PoolManager.register_pool("List", ListPool._pool)


# Context manager for automatic object pooling
class pooled:
    """Context manager for automatic object acquisition and release"""
    
    def __init__(self, pool_class):
        self.pool_class = pool_class
        self.obj = None
        
    def __enter__(self):
        self.obj = self.pool_class.acquire()
        return self.obj
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.obj is not None:
            self.pool_class.release(self.obj)