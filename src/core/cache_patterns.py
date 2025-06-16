"""
Advanced cache patterns and strategies implementation.

This module provides sophisticated caching patterns including:
- Write patterns (write-through, write-behind, write-around)
- Read patterns (cache-aside, refresh-ahead)
- Consistency patterns (read-through, eventual consistency)
- Invalidation patterns (time-based, event-based, dependency-based)
- Partitioning strategies
"""

import asyncio
import time
import weakref
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    Any, Dict, List, Optional, Set, Callable, Generic, TypeVar,
    Awaitable, Union, Tuple
)
from enum import Enum
import structlog

from .distributed_cache import CacheManager, CacheConfig

__all__ = [
    "CachePattern",
    "ConsistencyLevel", 
    "InvalidationStrategy",
    "PartitionStrategy",
    "CachePatternConfig",
    "PatternManager",
    "WritePatternManager",
    "ReadPatternManager",
    "ConsistencyManager",
    "InvalidationManager",
    "PartitionManager"
]

T = TypeVar('T')
logger = structlog.get_logger(__name__)


class CachePattern(Enum):
    """Cache access patterns."""
    CACHE_ASIDE = "cache_aside"
    READ_THROUGH = "read_through"
    WRITE_THROUGH = "write_through"
    WRITE_BEHIND = "write_behind"
    WRITE_AROUND = "write_around"
    REFRESH_AHEAD = "refresh_ahead"


class ConsistencyLevel(Enum):
    """Cache consistency levels."""
    EVENTUAL = "eventual"
    STRONG = "strong"
    WEAK = "weak"
    SESSION = "session"


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""
    TTL_BASED = "ttl_based"
    EVENT_BASED = "event_based"
    DEPENDENCY_BASED = "dependency_based"
    MANUAL = "manual"
    LRU = "lru"
    LFU = "lfu"


class PartitionStrategy(Enum):
    """Cache partitioning strategies."""
    HASH_BASED = "hash_based"
    RANGE_BASED = "range_based"
    DIRECTORY_BASED = "directory_based"
    CONSISTENT_HASH = "consistent_hash"


@dataclass
class CachePatternConfig:
    """Configuration for cache patterns."""
    # Write pattern settings
    write_pattern: CachePattern = CachePattern.CACHE_ASIDE
    write_batch_size: int = 100
    write_batch_timeout: float = 5.0
    write_retry_attempts: int = 3
    write_retry_delay: float = 1.0
    
    # Read pattern settings
    read_pattern: CachePattern = CachePattern.CACHE_ASIDE
    read_timeout: float = 5.0
    prefetch_factor: float = 0.1  # Prefetch when 10% TTL remaining
    refresh_ahead_threshold: float = 0.8  # Refresh when 80% TTL passed
    
    # Consistency settings
    consistency_level: ConsistencyLevel = ConsistencyLevel.EVENTUAL
    consistency_timeout: float = 10.0
    
    # Invalidation settings
    invalidation_strategy: InvalidationStrategy = InvalidationStrategy.TTL_BASED
    dependency_tracking: bool = False
    event_driven_invalidation: bool = False
    
    # Partitioning settings
    partition_strategy: PartitionStrategy = PartitionStrategy.HASH_BASED
    num_partitions: int = 16
    partition_size_limit: int = 10000
    
    # Performance settings
    async_writes: bool = True
    batch_operations: bool = True
    compression_enabled: bool = True
    
    # Monitoring settings
    pattern_metrics_enabled: bool = True
    performance_tracking: bool = True


class DataLoader(ABC, Generic[T]):
    """Abstract data loader for cache patterns."""
    
    @abstractmethod
    async def load(self, key: str) -> Optional[T]:
        """Load data for given key."""
        pass
    
    @abstractmethod
    async def load_batch(self, keys: List[str]) -> Dict[str, T]:
        """Load data for multiple keys."""
        pass


class DataWriter(ABC, Generic[T]):
    """Abstract data writer for cache patterns."""
    
    @abstractmethod
    async def write(self, key: str, value: T) -> bool:
        """Write data for given key."""
        pass
    
    @abstractmethod
    async def write_batch(self, items: Dict[str, T]) -> Dict[str, bool]:
        """Write data for multiple keys."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete data for given key."""
        pass


class WritePatternManager:
    """Manages write patterns for cache operations."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        self._write_queue: Dict[str, Any] = {}
        self._write_task: Optional[asyncio.Task] = None
        self._write_lock = asyncio.Lock()
        
        if config.write_pattern == CachePattern.WRITE_BEHIND:
            self._start_write_behind_processor()
    
    def _start_write_behind_processor(self) -> None:
        """Start background processor for write-behind pattern."""
        if not self._write_task:
            self._write_task = asyncio.create_task(self._process_write_behind_queue())
    
    async def _process_write_behind_queue(self) -> None:
        """Process write-behind queue in background."""
        while True:
            try:
                await asyncio.sleep(self.config.write_batch_timeout)
                
                async with self._write_lock:
                    if not self._write_queue:
                        continue
                    
                    # Process queued writes in batches
                    items_to_write = dict(self._write_queue)
                    self._write_queue.clear()
                
                # Write to underlying storage
                if hasattr(self, '_data_writer') and self._data_writer:
                    await self._data_writer.write_batch(items_to_write)
                
                logger.debug(
                    "Write-behind batch processed",
                    batch_size=len(items_to_write)
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Write-behind processing error", error=str(e))
    
    async def write_through(self, key: str, value: Any, data_writer: DataWriter) -> bool:
        """Write-through pattern: write to cache and storage simultaneously."""
        try:
            # Write to both cache and storage
            cache_result = await self.cache_manager.cache.set(key, value)
            storage_result = await data_writer.write(key, value)
            
            success = cache_result and storage_result
            
            if not success:
                # Rollback cache if storage write failed
                if cache_result and not storage_result:
                    await self.cache_manager.cache.delete(key)
                
                logger.warning(
                    "Write-through operation failed",
                    key=key,
                    cache_success=cache_result,
                    storage_success=storage_result
                )
            
            return success
            
        except Exception as e:
            logger.error("Write-through error", key=key, error=str(e))
            return False
    
    async def write_behind(self, key: str, value: Any) -> bool:
        """Write-behind pattern: write to cache immediately, storage later."""
        try:
            # Write to cache immediately
            cache_result = await self.cache_manager.cache.set(key, value)
            
            if cache_result:
                # Queue for background write to storage
                async with self._write_lock:
                    self._write_queue[key] = value
            
            return cache_result
            
        except Exception as e:
            logger.error("Write-behind error", key=key, error=str(e))
            return False
    
    async def write_around(self, key: str, value: Any, data_writer: DataWriter) -> bool:
        """Write-around pattern: write to storage only, bypass cache."""
        try:
            # Write only to storage, skip cache
            result = await data_writer.write(key, value)
            
            # Optionally invalidate cache entry if it exists
            if result:
                await self.cache_manager.cache.delete(key)
            
            return result
            
        except Exception as e:
            logger.error("Write-around error", key=key, error=str(e))
            return False
    
    async def close(self) -> None:
        """Close write pattern manager."""
        if self._write_task:
            self._write_task.cancel()
            try:
                await self._write_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining writes
        if self._write_queue and hasattr(self, '_data_writer'):
            await self._data_writer.write_batch(dict(self._write_queue))


class ReadPatternManager:
    """Manages read patterns for cache operations."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        self._prefetch_tasks: Dict[str, asyncio.Task] = {}
        self._access_tracking: Dict[str, float] = {}
    
    async def cache_aside(self, key: str, data_loader: DataLoader) -> Any:
        """Cache-aside pattern: check cache first, load from storage if miss."""
        try:
            # Try cache first
            value = await self.cache_manager.cache.get(key)
            if value is not None:
                self._track_access(key)
                return value
            
            # Cache miss - load from storage
            value = await data_loader.load(key)
            if value is not None:
                # Store in cache for future requests
                await self.cache_manager.cache.set(key, value)
            
            return value
            
        except Exception as e:
            logger.error("Cache-aside error", key=key, error=str(e))
            # Fallback to storage if cache fails
            return await data_loader.load(key)
    
    async def read_through(self, key: str, data_loader: DataLoader) -> Any:
        """Read-through pattern: cache handles loading from storage automatically."""
        try:
            # This pattern requires the cache to automatically load from storage
            # We simulate this by combining cache check and loading
            value = await self.cache_manager.cache.get(key)
            
            if value is None:
                # Load from storage and cache it
                value = await data_loader.load(key)
                if value is not None:
                    await self.cache_manager.cache.set(key, value)
            
            return value
            
        except Exception as e:
            logger.error("Read-through error", key=key, error=str(e))
            return None
    
    async def refresh_ahead(self, key: str, data_loader: DataLoader) -> Any:
        """Refresh-ahead pattern: refresh cache before expiration."""
        try:
            value = await self.cache_manager.cache.get(key)
            
            if value is not None:
                # Check if refresh is needed
                ttl = await self.cache_manager.cache.ttl(key)
                original_ttl = self.cache_manager.cache.config.default_ttl
                
                if ttl > 0 and (ttl / original_ttl) < self.config.refresh_ahead_threshold:
                    # Schedule background refresh
                    if key not in self._prefetch_tasks:
                        self._prefetch_tasks[key] = asyncio.create_task(
                            self._background_refresh(key, data_loader)
                        )
                
                return value
            else:
                # Cache miss - load immediately
                value = await data_loader.load(key)
                if value is not None:
                    await self.cache_manager.cache.set(key, value)
                return value
                
        except Exception as e:
            logger.error("Refresh-ahead error", key=key, error=str(e))
            return await data_loader.load(key)
    
    async def _background_refresh(self, key: str, data_loader: DataLoader) -> None:
        """Background refresh for refresh-ahead pattern."""
        try:
            value = await data_loader.load(key)
            if value is not None:
                await self.cache_manager.cache.set(key, value)
            
            logger.debug("Background refresh completed", key=key)
            
        except Exception as e:
            logger.warning("Background refresh failed", key=key, error=str(e))
        finally:
            # Clean up task
            if key in self._prefetch_tasks:
                del self._prefetch_tasks[key]
    
    def _track_access(self, key: str) -> None:
        """Track key access for pattern optimization."""
        if self.config.performance_tracking:
            self._access_tracking[key] = time.time()
    
    async def get_hot_keys(self, threshold: float = 0.8) -> List[str]:
        """Get frequently accessed keys for preloading."""
        if not self.config.performance_tracking:
            return []
        
        current_time = time.time()
        recent_threshold = current_time - 3600  # Last hour
        
        hot_keys = [
            key for key, last_access in self._access_tracking.items()
            if last_access > recent_threshold
        ]
        
        return hot_keys


class ConsistencyManager:
    """Manages cache consistency across multiple levels and nodes."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        self._version_vector: Dict[str, int] = {}
        self._consistency_callbacks: List[Callable] = []
    
    async def ensure_consistency(
        self,
        key: str,
        value: Any,
        consistency_level: Optional[ConsistencyLevel] = None
    ) -> bool:
        """Ensure cache consistency based on configured level."""
        level = consistency_level or self.config.consistency_level
        
        if level == ConsistencyLevel.STRONG:
            return await self._strong_consistency(key, value)
        elif level == ConsistencyLevel.EVENTUAL:
            return await self._eventual_consistency(key, value)
        elif level == ConsistencyLevel.WEAK:
            return await self._weak_consistency(key, value)
        elif level == ConsistencyLevel.SESSION:
            return await self._session_consistency(key, value)
        
        return False
    
    async def _strong_consistency(self, key: str, value: Any) -> bool:
        """Strong consistency: all replicas must be updated synchronously."""
        try:
            # In a real implementation, this would coordinate with all replicas
            # For now, we ensure local cache is updated
            success = await self.cache_manager.cache.set(key, value)
            
            if success:
                # Update version vector
                self._version_vector[key] = self._version_vector.get(key, 0) + 1
                
                # Notify consistency callbacks
                for callback in self._consistency_callbacks:
                    try:
                        await callback(key, value, "strong")
                    except Exception as e:
                        logger.warning("Consistency callback failed", error=str(e))
            
            return success
            
        except Exception as e:
            logger.error("Strong consistency error", key=key, error=str(e))
            return False
    
    async def _eventual_consistency(self, key: str, value: Any) -> bool:
        """Eventual consistency: updates propagated asynchronously."""
        try:
            # Update local cache immediately
            success = await self.cache_manager.cache.set(key, value)
            
            if success:
                # Schedule asynchronous propagation
                asyncio.create_task(self._propagate_update(key, value))
            
            return success
            
        except Exception as e:
            logger.error("Eventual consistency error", key=key, error=str(e))
            return False
    
    async def _weak_consistency(self, key: str, value: Any) -> bool:
        """Weak consistency: minimal consistency guarantees."""
        try:
            # Simple local update with no coordination
            return await self.cache_manager.cache.set(key, value)
            
        except Exception as e:
            logger.error("Weak consistency error", key=key, error=str(e))
            return False
    
    async def _session_consistency(self, key: str, value: Any) -> bool:
        """Session consistency: consistent within user session."""
        try:
            # For session consistency, we need to track session-specific state
            # This is a simplified implementation
            success = await self.cache_manager.cache.set(key, value)
            
            if success:
                # Tag with session information
                session_key = f"session:{key}"
                await self.cache_manager.cache.set(session_key, value)
            
            return success
            
        except Exception as e:
            logger.error("Session consistency error", key=key, error=str(e))
            return False
    
    async def _propagate_update(self, key: str, value: Any) -> None:
        """Propagate update to other cache nodes/replicas."""
        try:
            # In a real implementation, this would propagate to other nodes
            # For now, we just log the propagation
            logger.debug("Propagating update", key=key)
            
            # Simulate propagation delay
            await asyncio.sleep(0.1)
            
        except Exception as e:
            logger.warning("Update propagation failed", key=key, error=str(e))
    
    def add_consistency_callback(self, callback: Callable) -> None:
        """Add callback for consistency events."""
        self._consistency_callbacks.append(callback)
    
    def get_version(self, key: str) -> int:
        """Get version number for key."""
        return self._version_vector.get(key, 0)


class InvalidationManager:
    """Manages cache invalidation strategies."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        self._dependencies: Dict[str, Set[str]] = {}  # key -> dependent keys
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._invalidation_stats: Dict[str, int] = {}
    
    async def invalidate_key(
        self,
        key: str,
        strategy: Optional[InvalidationStrategy] = None
    ) -> bool:
        """Invalidate cache key using specified strategy."""
        strategy = strategy or self.config.invalidation_strategy
        
        try:
            if strategy == InvalidationStrategy.MANUAL:
                return await self._manual_invalidation(key)
            elif strategy == InvalidationStrategy.EVENT_BASED:
                return await self._event_based_invalidation(key)
            elif strategy == InvalidationStrategy.DEPENDENCY_BASED:
                return await self._dependency_based_invalidation(key)
            elif strategy == InvalidationStrategy.TTL_BASED:
                return await self._ttl_based_invalidation(key)
            
            return False
            
        except Exception as e:
            logger.error("Invalidation error", key=key, strategy=strategy.value, error=str(e))
            return False
    
    async def _manual_invalidation(self, key: str) -> bool:
        """Manual invalidation: explicitly delete key."""
        success = await self.cache_manager.cache.delete(key)
        self._update_stats("manual", success)
        return success
    
    async def _event_based_invalidation(self, key: str) -> bool:
        """Event-based invalidation: invalidate based on events."""
        # Trigger event handlers
        if key in self._event_handlers:
            for handler in self._event_handlers[key]:
                try:
                    await handler(key)
                except Exception as e:
                    logger.warning("Event handler failed", key=key, error=str(e))
        
        success = await self.cache_manager.cache.delete(key)
        self._update_stats("event_based", success)
        return success
    
    async def _dependency_based_invalidation(self, key: str) -> bool:
        """Dependency-based invalidation: invalidate dependent keys too."""
        keys_to_invalidate = {key}
        
        # Add dependent keys
        if key in self._dependencies:
            keys_to_invalidate.update(self._dependencies[key])
        
        # Find keys that depend on this key
        for dep_key, deps in self._dependencies.items():
            if key in deps:
                keys_to_invalidate.add(dep_key)
        
        success_count = 0
        for k in keys_to_invalidate:
            if await self.cache_manager.cache.delete(k):
                success_count += 1
        
        success = success_count > 0
        self._update_stats("dependency_based", success)
        return success
    
    async def _ttl_based_invalidation(self, key: str) -> bool:
        """TTL-based invalidation: set short TTL for gradual expiration."""
        # Instead of immediate deletion, set very short TTL
        success = await self.cache_manager.cache.expire(key, 1)  # 1 second TTL
        self._update_stats("ttl_based", success)
        return success
    
    def add_dependency(self, key: str, dependent_key: str) -> None:
        """Add dependency relationship between keys."""
        if key not in self._dependencies:
            self._dependencies[key] = set()
        self._dependencies[key].add(dependent_key)
        
        logger.debug("Dependency added", key=key, dependent=dependent_key)
    
    def remove_dependency(self, key: str, dependent_key: str) -> None:
        """Remove dependency relationship."""
        if key in self._dependencies:
            self._dependencies[key].discard(dependent_key)
            if not self._dependencies[key]:
                del self._dependencies[key]
    
    def add_event_handler(self, key: str, handler: Callable) -> None:
        """Add event handler for key invalidation."""
        if key not in self._event_handlers:
            self._event_handlers[key] = []
        self._event_handlers[key].append(handler)
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern."""
        try:
            count = await self.cache_manager.cache.delete_pattern(pattern)
            self._update_stats("pattern", count > 0)
            return count
            
        except Exception as e:
            logger.error("Pattern invalidation error", pattern=pattern, error=str(e))
            return 0
    
    def _update_stats(self, strategy: str, success: bool) -> None:
        """Update invalidation statistics."""
        if self.config.pattern_metrics_enabled:
            stat_key = f"{strategy}_{'success' if success else 'failure'}"
            self._invalidation_stats[stat_key] = self._invalidation_stats.get(stat_key, 0) + 1
    
    def get_stats(self) -> Dict[str, int]:
        """Get invalidation statistics."""
        return self._invalidation_stats.copy()


class PartitionManager:
    """Manages cache partitioning strategies."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        self._partition_map: Dict[str, int] = {}
        self._partition_sizes: Dict[int, int] = {}
    
    def get_partition(self, key: str) -> int:
        """Get partition number for key."""
        if self.config.partition_strategy == PartitionStrategy.HASH_BASED:
            return self._hash_partition(key)
        elif self.config.partition_strategy == PartitionStrategy.RANGE_BASED:
            return self._range_partition(key)
        elif self.config.partition_strategy == PartitionStrategy.DIRECTORY_BASED:
            return self._directory_partition(key)
        elif self.config.partition_strategy == PartitionStrategy.CONSISTENT_HASH:
            return self._consistent_hash_partition(key)
        
        return 0
    
    def _hash_partition(self, key: str) -> int:
        """Simple hash-based partitioning."""
        return hash(key) % self.config.num_partitions
    
    def _range_partition(self, key: str) -> int:
        """Range-based partitioning using key prefixes."""
        # Extract prefix for range-based partitioning
        if ':' in key:
            prefix = key.split(':', 1)[0]
            return hash(prefix) % self.config.num_partitions
        return self._hash_partition(key)
    
    def _directory_partition(self, key: str) -> int:
        """Directory-based partitioning using explicit mapping."""
        if key in self._partition_map:
            return self._partition_map[key]
        
        # Assign to least loaded partition
        min_partition = min(
            range(self.config.num_partitions),
            key=lambda p: self._partition_sizes.get(p, 0)
        )
        
        self._partition_map[key] = min_partition
        self._partition_sizes[min_partition] = self._partition_sizes.get(min_partition, 0) + 1
        
        return min_partition
    
    def _consistent_hash_partition(self, key: str) -> int:
        """Consistent hash-based partitioning."""
        # Use secure SHA-256 instead of MD5 for cryptographic security
        import hashlib
        key_hash = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        return key_hash % self.config.num_partitions
    
    async def rebalance_partitions(self) -> Dict[str, int]:
        """Rebalance partitions when they become uneven."""
        if self.config.partition_strategy != PartitionStrategy.DIRECTORY_BASED:
            return {}
        
        # Check if rebalancing is needed
        sizes = list(self._partition_sizes.values())
        if not sizes:
            return {}
        
        avg_size = sum(sizes) / len(sizes)
        max_size = max(sizes)
        
        if max_size > avg_size * 1.5:  # 50% above average
            logger.info("Starting partition rebalancing")
            
            # Find overloaded partitions
            moves = {}
            for key, partition in list(self._partition_map.items()):
                if self._partition_sizes.get(partition, 0) > avg_size * 1.2:
                    # Move to least loaded partition
                    new_partition = min(
                        range(self.config.num_partitions),
                        key=lambda p: self._partition_sizes.get(p, 0)
                    )
                    
                    if new_partition != partition:
                        moves[key] = new_partition
                        
                        # Update tracking
                        self._partition_map[key] = new_partition
                        self._partition_sizes[partition] -= 1
                        self._partition_sizes[new_partition] = self._partition_sizes.get(new_partition, 0) + 1
            
            logger.info("Partition rebalancing completed", moves_count=len(moves))
            return moves
        
        return {}
    
    def get_partition_stats(self) -> Dict[str, Any]:
        """Get partition statistics."""
        return {
            "strategy": self.config.partition_strategy.value,
            "num_partitions": self.config.num_partitions,
            "partition_sizes": dict(self._partition_sizes),
            "total_keys": sum(self._partition_sizes.values()),
            "avg_partition_size": sum(self._partition_sizes.values()) / max(1, len(self._partition_sizes))
        }


class PatternManager:
    """Main manager coordinating all cache patterns."""
    
    def __init__(self, cache_manager: CacheManager, config: CachePatternConfig):
        self.cache_manager = cache_manager
        self.config = config
        
        self.write_manager = WritePatternManager(cache_manager, config)
        self.read_manager = ReadPatternManager(cache_manager, config)
        self.consistency_manager = ConsistencyManager(cache_manager, config)
        self.invalidation_manager = InvalidationManager(cache_manager, config)
        self.partition_manager = PartitionManager(cache_manager, config)
    
    async def get_or_set(
        self,
        key: str,
        data_loader: DataLoader,
        pattern: Optional[CachePattern] = None
    ) -> Any:
        """Get value using specified read pattern."""
        pattern = pattern or self.config.read_pattern
        
        if pattern == CachePattern.CACHE_ASIDE:
            return await self.read_manager.cache_aside(key, data_loader)
        elif pattern == CachePattern.READ_THROUGH:
            return await self.read_manager.read_through(key, data_loader)
        elif pattern == CachePattern.REFRESH_AHEAD:
            return await self.read_manager.refresh_ahead(key, data_loader)
        else:
            return await self.read_manager.cache_aside(key, data_loader)
    
    async def set_with_pattern(
        self,
        key: str,
        value: Any,
        data_writer: Optional[DataWriter] = None,
        pattern: Optional[CachePattern] = None
    ) -> bool:
        """Set value using specified write pattern."""
        pattern = pattern or self.config.write_pattern
        
        if pattern == CachePattern.WRITE_THROUGH and data_writer:
            return await self.write_manager.write_through(key, value, data_writer)
        elif pattern == CachePattern.WRITE_BEHIND:
            return await self.write_manager.write_behind(key, value)
        elif pattern == CachePattern.WRITE_AROUND and data_writer:
            return await self.write_manager.write_around(key, value, data_writer)
        else:
            # Default to cache-aside (just set in cache)
            return await self.cache_manager.cache.set(key, value)
    
    async def invalidate(
        self,
        key: str,
        strategy: Optional[InvalidationStrategy] = None
    ) -> bool:
        """Invalidate key using specified strategy."""
        return await self.invalidation_manager.invalidate_key(key, strategy)
    
    async def ensure_consistency(
        self,
        key: str,
        value: Any,
        level: Optional[ConsistencyLevel] = None
    ) -> bool:
        """Ensure consistency using specified level."""
        return await self.consistency_manager.ensure_consistency(key, value, level)
    
    def get_partition(self, key: str) -> int:
        """Get partition for key."""
        return self.partition_manager.get_partition(key)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive pattern statistics."""
        return {
            "config": {
                "read_pattern": self.config.read_pattern.value,
                "write_pattern": self.config.write_pattern.value,
                "consistency_level": self.config.consistency_level.value,
                "invalidation_strategy": self.config.invalidation_strategy.value,
            },
            "invalidation_stats": self.invalidation_manager.get_stats(),
            "partition_stats": self.partition_manager.get_partition_stats(),
            "hot_keys": await self.read_manager.get_hot_keys(),
        }
    
    async def close(self) -> None:
        """Close pattern manager and cleanup resources."""
        await self.write_manager.close()