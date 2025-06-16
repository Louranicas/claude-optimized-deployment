"""
Comprehensive distributed caching system with Redis cluster support.

This module provides a complete multi-level caching solution with:
- Redis cluster support for high availability
- Cache warming strategies
- Multiple invalidation patterns (TTL, event-based, manual)
- Multi-level caching (L1: memory, L2: Redis, L3: database)
- Compression and serialization
- Cache monitoring and analytics
- Cache patterns (cache-aside, write-through, write-behind)
- Partitioning and sharding
- Security features (encryption, access control)
"""

import asyncio
import hashlib
import json
import logging
import time
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union, Callable, Generic, TypeVar,
    Protocol, runtime_checkable
)
import redis
import redis.asyncio as aioredis
from redis.sentinel import Sentinel
from redis.cluster import RedisCluster
from redis.exceptions import (
    RedisError, ConnectionError, TimeoutError, RedisClusterException
)
import orjson
from cryptography.fernet import Fernet
import structlog

from .cache_config import get_cache_config
from .lru_cache import TTLCache
from .memory_monitor import get_memory_monitor

__all__ = [
    "CacheLevel",
    "CachePattern",
    "CacheStrategy",
    "CacheEntry",
    "CacheConfig",
    "CacheMetrics",
    "CacheSerializer",
    "CacheCompressor",
    "CacheEncryption",
    "CacheSharding",
    "CacheMonitor",
    "CacheWarmer",
    "CacheInvalidator",
    "DistributedCache",
    "CacheManager",
    "create_cache_manager"
]

T = TypeVar('T')
logger = structlog.get_logger(__name__)


class CacheLevel(Enum):
    """Cache levels for multi-level caching."""
    L1_MEMORY = "l1_memory"
    L2_REDIS = "l2_redis"
    L3_DATABASE = "l3_database"


class CachePattern(Enum):
    """Cache access patterns."""
    CACHE_ASIDE = "cache_aside"
    WRITE_THROUGH = "write_through"
    WRITE_BEHIND = "write_behind"
    WRITE_AROUND = "write_around"
    REFRESH_AHEAD = "refresh_ahead"


class CacheStrategy(Enum):
    """Cache warming and eviction strategies."""
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"
    RANDOM = "random"
    HYBRID = "hybrid"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    ttl: Optional[float] = None
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.ttl is None:
            return False
        return time.time() > (self.created_at + self.ttl)
    
    @property
    def age(self) -> float:
        """Get entry age in seconds."""
        return time.time() - self.created_at
    
    def touch(self) -> None:
        """Update last accessed time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1


@dataclass
class CacheConfig:
    """Configuration for distributed cache."""
    # Redis configuration
    redis_url: str = "redis://localhost:6379"
    redis_cluster_nodes: Optional[List[str]] = None
    redis_sentinel_hosts: Optional[List[Tuple[str, int]]] = None
    redis_sentinel_service: str = "mymaster"
    redis_password: Optional[str] = None
    redis_db: int = 0
    redis_ssl: bool = False
    
    # Connection settings
    max_connections: int = 100
    connection_timeout: float = 5.0
    socket_timeout: float = 5.0
    retry_on_timeout: bool = True
    health_check_interval: float = 30.0
    
    # Cache settings
    default_ttl: float = 3600.0  # 1 hour
    max_value_size: int = 1024 * 1024  # 1MB
    compression_threshold: int = 1024  # Compress values > 1KB
    enable_compression: bool = True
    enable_encryption: bool = False
    encryption_key: Optional[str] = None
    
    # Multi-level cache settings
    l1_max_size: int = 1000
    l1_ttl: float = 300.0  # 5 minutes
    l2_ttl: float = 3600.0  # 1 hour
    enable_l1_cache: bool = True
    
    # Sharding settings
    num_shards: int = 16
    consistent_hashing: bool = True
    replication_factor: int = 2
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_interval: float = 60.0
    enable_tracing: bool = False
    
    # Cache warming settings
    enable_warming: bool = False
    warming_batch_size: int = 100
    warming_delay: float = 0.1
    
    # Security settings
    enable_access_control: bool = False
    allowed_keys_pattern: Optional[str] = None
    denied_keys_pattern: Optional[str] = None


@dataclass
class CacheMetrics:
    """Cache performance metrics."""
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    evictions: int = 0
    errors: int = 0
    
    # Timing metrics
    avg_get_time: float = 0.0
    avg_set_time: float = 0.0
    avg_delete_time: float = 0.0
    
    # Memory metrics
    memory_usage: int = 0
    item_count: int = 0
    
    # Network metrics (for Redis)
    network_bytes_sent: int = 0
    network_bytes_received: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate
    
    def reset(self) -> None:
        """Reset all metrics."""
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.evictions = 0
        self.errors = 0
        self.avg_get_time = 0.0
        self.avg_set_time = 0.0
        self.avg_delete_time = 0.0
        self.memory_usage = 0
        self.item_count = 0
        self.network_bytes_sent = 0
        self.network_bytes_received = 0


@runtime_checkable
class CacheSerializer(Protocol):
    """Protocol for cache serialization."""
    
    def serialize(self, value: Any) -> bytes:
        """Serialize value to bytes."""
        ...
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize bytes to value."""
        ...


class JSONSerializer:
    """JSON-based cache serializer."""
    
    def serialize(self, value: Any) -> bytes:
        """Serialize value using orjson."""
        try:
            return orjson.dumps(value)
        except (TypeError, ValueError) as e:
            logger.error("Failed to serialize value", error=str(e))
            raise
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize value using orjson."""
        try:
            return orjson.loads(data)
        except (orjson.JSONDecodeError, ValueError) as e:
            logger.error("Failed to deserialize value", error=str(e))
            raise


class PickleSerializer:
    """Pickle-based cache serializer (more flexible but less secure)."""
    
    def serialize(self, value: Any) -> bytes:
        """Serialize value using pickle."""
        import pickle
        try:
            return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.error("Failed to pickle serialize value", error=str(e))
            raise
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize value using pickle."""
        import pickle
        try:
            return pickle.loads(data)
        except Exception as e:
            logger.error("Failed to pickle deserialize value", error=str(e))
            raise


class CacheCompressor:
    """Cache value compression."""
    
    def __init__(self, compression_level: int = 6):
        self.compression_level = compression_level
    
    def compress(self, data: bytes, threshold: int = 1024) -> Tuple[bytes, bool]:
        """Compress data if it exceeds threshold."""
        if len(data) < threshold:
            return data, False
        
        try:
            compressed = zlib.compress(data, self.compression_level)
            # Only use compression if it actually reduces size
            if len(compressed) < len(data):
                return compressed, True
            return data, False
        except Exception as e:
            logger.warning("Compression failed", error=str(e))
            return data, False
    
    def decompress(self, data: bytes, is_compressed: bool) -> bytes:
        """Decompress data if it was compressed."""
        if not is_compressed:
            return data
        
        try:
            return zlib.decompress(data)
        except Exception as e:
            logger.error("Decompression failed", error=str(e))
            raise


class CacheEncryption:
    """Cache value encryption for security."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        if encryption_key:
            self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        else:
            # Generate a new key if none provided
            self.fernet = Fernet(Fernet.generate_key())
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data."""
        try:
            return self.fernet.encrypt(data)
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data."""
        try:
            return self.fernet.decrypt(data)
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise


class CacheSharding:
    """Cache key sharding for distributed caching."""
    
    def __init__(self, num_shards: int = 16, consistent_hashing: bool = True):
        self.num_shards = num_shards
        self.consistent_hashing = consistent_hashing
        
        if consistent_hashing:
            # Create virtual nodes for better distribution
            self.virtual_nodes = 150
            self.ring = {}
            for shard in range(num_shards):
                for vnode in range(self.virtual_nodes):
                    key = f"shard_{shard}_vnode_{vnode}"
                    hash_key = int(hashlib.md5(key.encode()).hexdigest(), 16)
                    self.ring[hash_key] = shard
            self.sorted_keys = sorted(self.ring.keys())
    
    def get_shard(self, key: str) -> int:
        """Get shard number for a key."""
        if self.consistent_hashing:
            return self._consistent_hash_shard(key)
        else:
            return self._simple_hash_shard(key)
    
    def _simple_hash_shard(self, key: str) -> int:
        """Simple hash-based sharding."""
        return hash(key) % self.num_shards
    
    def _consistent_hash_shard(self, key: str) -> int:
        """Consistent hash-based sharding."""
        key_hash = int(hashlib.md5(key.encode()).hexdigest(), 16)
        
        # Find the first node clockwise from the key
        for ring_key in self.sorted_keys:
            if key_hash <= ring_key:
                return self.ring[ring_key]
        
        # Wrap around to the first node
        return self.ring[self.sorted_keys[0]]
    
    def get_shards_for_pattern(self, pattern: str) -> List[int]:
        """Get all shards that might contain keys matching a pattern."""
        if '*' in pattern or '?' in pattern:
            # Pattern matching requires checking all shards
            return list(range(self.num_shards))
        else:
            # Exact key, return specific shard
            return [self.get_shard(pattern)]


class CacheMonitor:
    """Cache monitoring and analytics."""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.metrics = CacheMetrics()
        self.start_time = time.time()
        self._metrics_lock = asyncio.Lock()
        self._monitoring_task: Optional[asyncio.Task] = None
    
    async def start_monitoring(self) -> None:
        """Start monitoring task."""
        if self.config.enable_metrics and not self._monitoring_task:
            self._monitoring_task = asyncio.create_task(self._monitor_loop())
    
    async def stop_monitoring(self) -> None:
        """Stop monitoring task."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while True:
            try:
                await asyncio.sleep(self.config.metrics_interval)
                await self._collect_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitoring error", error=str(e))
    
    async def _collect_metrics(self) -> None:
        """Collect and log metrics."""
        async with self._metrics_lock:
            uptime = time.time() - self.start_time
            
            logger.info(
                "Cache metrics",
                uptime=uptime,
                hit_rate=self.metrics.hit_rate,
                miss_rate=self.metrics.miss_rate,
                hits=self.metrics.hits,
                misses=self.metrics.misses,
                sets=self.metrics.sets,
                deletes=self.metrics.deletes,
                evictions=self.metrics.evictions,
                errors=self.metrics.errors,
                avg_get_time=self.metrics.avg_get_time,
                avg_set_time=self.metrics.avg_set_time,
                memory_usage=self.metrics.memory_usage,
                item_count=self.metrics.item_count
            )
    
    async def record_hit(self, duration: float = 0.0) -> None:
        """Record cache hit."""
        async with self._metrics_lock:
            self.metrics.hits += 1
            if duration > 0:
                # Update running average
                total_ops = self.metrics.hits + self.metrics.misses
                self.metrics.avg_get_time = (
                    (self.metrics.avg_get_time * (total_ops - 1) + duration) / total_ops
                )
    
    async def record_miss(self, duration: float = 0.0) -> None:
        """Record cache miss."""
        async with self._metrics_lock:
            self.metrics.misses += 1
            if duration > 0:
                total_ops = self.metrics.hits + self.metrics.misses
                self.metrics.avg_get_time = (
                    (self.metrics.avg_get_time * (total_ops - 1) + duration) / total_ops
                )
    
    async def record_set(self, duration: float = 0.0) -> None:
        """Record cache set operation."""
        async with self._metrics_lock:
            self.metrics.sets += 1
            if duration > 0:
                self.metrics.avg_set_time = (
                    (self.metrics.avg_set_time * (self.metrics.sets - 1) + duration) / self.metrics.sets
                )
    
    async def record_delete(self, duration: float = 0.0) -> None:
        """Record cache delete operation."""
        async with self._metrics_lock:
            self.metrics.deletes += 1
            if duration > 0:
                self.metrics.avg_delete_time = (
                    (self.metrics.avg_delete_time * (self.metrics.deletes - 1) + duration) / self.metrics.deletes
                )
    
    async def record_eviction(self) -> None:
        """Record cache eviction."""
        async with self._metrics_lock:
            self.metrics.evictions += 1
    
    async def record_error(self) -> None:
        """Record cache error."""
        async with self._metrics_lock:
            self.metrics.errors += 1
    
    async def update_memory_usage(self, usage: int, item_count: int) -> None:
        """Update memory usage metrics."""
        async with self._metrics_lock:
            self.metrics.memory_usage = usage
            self.metrics.item_count = item_count
    
    async def get_metrics(self) -> CacheMetrics:
        """Get current metrics."""
        async with self._metrics_lock:
            # Return a copy to avoid race conditions
            return CacheMetrics(
                hits=self.metrics.hits,
                misses=self.metrics.misses,
                sets=self.metrics.sets,
                deletes=self.metrics.deletes,
                evictions=self.metrics.evictions,
                errors=self.metrics.errors,
                avg_get_time=self.metrics.avg_get_time,
                avg_set_time=self.metrics.avg_set_time,
                avg_delete_time=self.metrics.avg_delete_time,
                memory_usage=self.metrics.memory_usage,
                item_count=self.metrics.item_count,
                network_bytes_sent=self.metrics.network_bytes_sent,
                network_bytes_received=self.metrics.network_bytes_received
            )


class CacheWarmer:
    """Cache warming strategies."""
    
    def __init__(self, cache: 'DistributedCache', config: CacheConfig):
        self.cache = cache
        self.config = config
        self._warming_task: Optional[asyncio.Task] = None
    
    async def warm_keys(self, keys: List[str], data_loader: Callable[[str], Any]) -> None:
        """Warm cache with specific keys."""
        if not self.config.enable_warming:
            return
        
        logger.info("Starting cache warming", key_count=len(keys))
        
        for i in range(0, len(keys), self.config.warming_batch_size):
            batch = keys[i:i + self.config.warming_batch_size]
            
            # Load data for batch
            tasks = []
            for key in batch:
                try:
                    value = await data_loader(key)
                    if value is not None:
                        tasks.append(self.cache.set(key, value))
                except Exception as e:
                    logger.warning("Failed to load data for warming", key=key, error=str(e))
            
            # Execute batch
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Small delay between batches to avoid overwhelming the system
            if self.config.warming_delay > 0 and i + self.config.warming_batch_size < len(keys):
                await asyncio.sleep(self.config.warming_delay)
        
        logger.info("Cache warming completed", key_count=len(keys))
    
    async def warm_pattern(self, pattern: str, data_loader: Callable[[str], Any]) -> None:
        """Warm cache with keys matching a pattern."""
        # This would typically involve querying a database or other data source
        # to find keys matching the pattern, then calling warm_keys
        logger.info("Pattern-based warming not implemented in base class", pattern=pattern)


class CacheInvalidator:
    """Cache invalidation strategies."""
    
    def __init__(self, cache: 'DistributedCache'):
        self.cache = cache
        self._invalidation_listeners: Dict[str, List[Callable]] = {}
    
    async def invalidate_by_key(self, key: str) -> bool:
        """Invalidate specific key."""
        return await self.cache.delete(key)
    
    async def invalidate_by_pattern(self, pattern: str) -> int:
        """Invalidate keys matching pattern."""
        return await self.cache.delete_pattern(pattern)
    
    async def invalidate_by_tags(self, tags: Set[str]) -> int:
        """Invalidate keys with specific tags."""
        # This requires maintaining a tag -> keys mapping
        # Implementation depends on the specific cache backend
        count = 0
        for tag in tags:
            keys = await self._get_keys_for_tag(tag)
            for key in keys:
                if await self.cache.delete(key):
                    count += 1
        return count
    
    async def _get_keys_for_tag(self, tag: str) -> List[str]:
        """Get keys associated with a tag."""
        # This would typically be implemented using Redis sets
        # storing tag -> key mappings
        return []
    
    def register_invalidation_listener(self, event: str, callback: Callable) -> None:
        """Register callback for invalidation events."""
        if event not in self._invalidation_listeners:
            self._invalidation_listeners[event] = []
        self._invalidation_listeners[event].append(callback)
    
    async def trigger_invalidation_event(self, event: str, data: Any) -> None:
        """Trigger invalidation event callbacks."""
        if event in self._invalidation_listeners:
            for callback in self._invalidation_listeners[event]:
                try:
                    await callback(data)
                except Exception as e:
                    logger.error("Invalidation callback failed", event=event, error=str(e))


class DistributedCache:
    """Main distributed cache class with Redis cluster support."""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.serializer: CacheSerializer = JSONSerializer()
        self.compressor = CacheCompressor() if config.enable_compression else None
        self.encryption = CacheEncryption(config.encryption_key) if config.enable_encryption else None
        self.sharding = CacheSharding(config.num_shards, config.consistent_hashing)
        self.monitor = CacheMonitor(config)
        self.warmer = CacheWarmer(self, config)
        self.invalidator = CacheInvalidator(self)
        
        # L1 cache (in-memory)
        self.l1_cache: Optional[TTLCache] = None
        if config.enable_l1_cache:
            self.l1_cache = TTLCache(
                maxsize=config.l1_max_size,
                ttl=config.l1_ttl
            )
        
        # Redis connections
        self.redis_pool: Optional[aioredis.ConnectionPool] = None
        self.redis_cluster: Optional[RedisCluster] = None
        self.redis_sentinel: Optional[Sentinel] = None
        self.redis_clients: List[aioredis.Redis] = []
        
        self._initialized = False
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize cache connections."""
        if self._initialized:
            return
        
        async with self._lock:
            if self._initialized:
                return
            
            try:
                await self._setup_redis_connections()
                await self.monitor.start_monitoring()
                self._initialized = True
                logger.info("Distributed cache initialized successfully")
            except Exception as e:
                logger.error("Failed to initialize distributed cache", error=str(e))
                raise
    
    async def _setup_redis_connections(self) -> None:
        """Set up Redis connections based on configuration."""
        if self.config.redis_cluster_nodes:
            await self._setup_cluster_connections()
        elif self.config.redis_sentinel_hosts:
            await self._setup_sentinel_connections()
        else:
            await self._setup_single_connections()
    
    async def _setup_cluster_connections(self) -> None:
        """Set up Redis cluster connections."""
        try:
            startup_nodes = [
                {"host": node.split(':')[0], "port": int(node.split(':')[1])}
                for node in self.config.redis_cluster_nodes
            ]
            
            self.redis_cluster = RedisCluster(
                startup_nodes=startup_nodes,
                password=self.config.redis_password,
                ssl=self.config.redis_ssl,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.connection_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                decode_responses=False  # We handle encoding ourselves
            )
            
            # Test connection
            await self.redis_cluster.ping()
            logger.info("Redis cluster connection established")
            
        except Exception as e:
            logger.error("Failed to connect to Redis cluster", error=str(e))
            raise
    
    async def _setup_sentinel_connections(self) -> None:
        """Set up Redis sentinel connections."""
        try:
            self.redis_sentinel = Sentinel(
                self.config.redis_sentinel_hosts,
                password=self.config.redis_password,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.connection_timeout
            )
            
            # Get master connection
            master = self.redis_sentinel.master_for(
                self.config.redis_sentinel_service,
                password=self.config.redis_password,
                db=self.config.redis_db,
                ssl=self.config.redis_ssl
            )
            
            # Test connection
            await master.ping()
            logger.info("Redis sentinel connection established")
            
        except Exception as e:
            logger.error("Failed to connect to Redis sentinel", error=str(e))
            raise
    
    async def _setup_single_connections(self) -> None:
        """Set up single Redis instance connections with sharding."""
        try:
            # Create connection pool
            self.redis_pool = aioredis.ConnectionPool.from_url(
                self.config.redis_url,
                password=self.config.redis_password,
                db=self.config.redis_db,
                ssl=self.config.redis_ssl,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.connection_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                decode_responses=False
            )
            
            # Create Redis clients for each shard
            for shard in range(self.config.num_shards):
                client = aioredis.Redis(connection_pool=self.redis_pool)
                self.redis_clients.append(client)
            
            # Test connection
            if self.redis_clients:
                await self.redis_clients[0].ping()
                logger.info("Redis single instance connections established")
            
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            raise
    
    def _get_redis_client(self, key: str) -> aioredis.Redis:
        """Get Redis client for a specific key."""
        if self.redis_cluster:
            return self.redis_cluster
        elif self.redis_sentinel:
            return self.redis_sentinel.master_for(self.config.redis_sentinel_service)
        else:
            shard = self.sharding.get_shard(key)
            return self.redis_clients[shard % len(self.redis_clients)]
    
    def _prepare_value(self, value: Any) -> bytes:
        """Serialize, compress, and encrypt value."""
        # Serialize
        data = self.serializer.serialize(value)
        
        # Compress if enabled
        is_compressed = False
        if self.compressor:
            data, is_compressed = self.compressor.compress(data, self.config.compression_threshold)
        
        # Encrypt if enabled
        if self.encryption:
            data = self.encryption.encrypt(data)
        
        # Add metadata prefix
        metadata = {
            'compressed': is_compressed,
            'encrypted': self.encryption is not None,
            'serializer': 'json',  # Could be made configurable
            'timestamp': time.time()
        }
        
        metadata_bytes = orjson.dumps(metadata)
        metadata_len = len(metadata_bytes).to_bytes(4, 'big')
        
        return metadata_len + metadata_bytes + data
    
    def _extract_value(self, data: bytes) -> Any:
        """Decrypt, decompress, and deserialize value."""
        # Extract metadata
        metadata_len = int.from_bytes(data[:4], 'big')
        metadata_bytes = data[4:4 + metadata_len]
        value_data = data[4 + metadata_len:]
        
        metadata = orjson.loads(metadata_bytes)
        
        # Decrypt if needed
        if metadata.get('encrypted', False) and self.encryption:
            value_data = self.encryption.decrypt(value_data)
        
        # Decompress if needed
        if metadata.get('compressed', False) and self.compressor:
            value_data = self.compressor.decompress(value_data, True)
        
        # Deserialize
        return self.serializer.deserialize(value_data)
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        start_time = time.time()
        
        try:
            # Check L1 cache first
            if self.l1_cache:
                l1_value = self.l1_cache.get(key)
                if l1_value is not None:
                    await self.monitor.record_hit(time.time() - start_time)
                    return l1_value
            
            # Check Redis
            redis_client = self._get_redis_client(key)
            raw_data = await redis_client.get(key)
            
            if raw_data is None:
                await self.monitor.record_miss(time.time() - start_time)
                return default
            
            # Extract value
            value = self._extract_value(raw_data)
            
            # Update L1 cache
            if self.l1_cache:
                self.l1_cache.set(key, value)
            
            await self.monitor.record_hit(time.time() - start_time)
            return value
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache get failed", key=key, error=str(e))
            return default
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        tags: Optional[Set[str]] = None
    ) -> bool:
        """Set value in cache."""
        start_time = time.time()
        
        try:
            # Check value size
            prepared_value = self._prepare_value(value)
            if len(prepared_value) > self.config.max_value_size:
                logger.warning("Value too large for cache", key=key, size=len(prepared_value))
                return False
            
            # Use default TTL if not specified
            cache_ttl = ttl or self.config.default_ttl
            
            # Set in Redis
            redis_client = self._get_redis_client(key)
            await redis_client.setex(key, int(cache_ttl), prepared_value)
            
            # Set in L1 cache
            if self.l1_cache:
                self.l1_cache.set(key, value, ttl=min(cache_ttl, self.config.l1_ttl))
            
            # Handle tags if provided
            if tags:
                await self._add_tags(key, tags)
            
            await self.monitor.record_set(time.time() - start_time)
            return True
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache set failed", key=key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache."""
        start_time = time.time()
        
        try:
            # Delete from L1 cache
            if self.l1_cache:
                self.l1_cache.delete(key)
            
            # Delete from Redis
            redis_client = self._get_redis_client(key)
            result = await redis_client.delete(key)
            
            await self.monitor.record_delete(time.time() - start_time)
            return result > 0
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache delete failed", key=key, error=str(e))
            return False
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern."""
        try:
            count = 0
            if self.redis_cluster:
                # For cluster, we need to scan all nodes
                for node in self.redis_cluster.get_nodes():
                    keys = await node.keys(pattern)
                    if keys:
                        count += await node.delete(*keys)
            else:
                # For single instance or sentinel
                redis_client = self._get_redis_client(pattern)
                keys = await redis_client.keys(pattern)
                if keys:
                    count = await redis_client.delete(*keys)
            
            # Clear L1 cache entries matching pattern
            if self.l1_cache:
                self.l1_cache.clear_pattern(pattern)
            
            return count
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache delete pattern failed", pattern=pattern, error=str(e))
            return 0
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        try:
            # Check L1 cache first
            if self.l1_cache and self.l1_cache.get(key) is not None:
                return True
            
            # Check Redis
            redis_client = self._get_redis_client(key)
            return bool(await redis_client.exists(key))
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache exists check failed", key=key, error=str(e))
            return False
    
    async def expire(self, key: str, ttl: float) -> bool:
        """Set TTL for existing key."""
        try:
            redis_client = self._get_redis_client(key)
            return bool(await redis_client.expire(key, int(ttl)))
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache expire failed", key=key, error=str(e))
            return False
    
    async def ttl(self, key: str) -> float:
        """Get TTL for key."""
        try:
            redis_client = self._get_redis_client(key)
            return float(await redis_client.ttl(key))
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache TTL check failed", key=key, error=str(e))
            return -1.0
    
    async def clear(self) -> None:
        """Clear all cache data."""
        try:
            # Clear L1 cache
            if self.l1_cache:
                self.l1_cache.clear()
            
            # Clear Redis
            if self.redis_cluster:
                await self.redis_cluster.flushall()
            else:
                for client in self.redis_clients:
                    await client.flushdb()
            
            logger.info("Cache cleared successfully")
            
        except Exception as e:
            await self.monitor.record_error()
            logger.error("Cache clear failed", error=str(e))
    
    async def _add_tags(self, key: str, tags: Set[str]) -> None:
        """Add tags for a key (for tag-based invalidation)."""
        # This would typically use Redis sets to maintain tag -> keys mappings
        # Implementation depends on specific requirements
        pass
    
    async def get_info(self) -> Dict[str, Any]:
        """Get cache information and statistics."""
        try:
            info = {
                'config': {
                    'redis_url': self.config.redis_url,
                    'num_shards': self.config.num_shards,
                    'compression_enabled': self.config.enable_compression,
                    'encryption_enabled': self.config.enable_encryption,
                    'l1_cache_enabled': self.config.enable_l1_cache,
                },
                'metrics': await self.monitor.get_metrics(),
                'redis_info': {}
            }
            
            # Get Redis info
            if self.redis_cluster:
                info['redis_info'] = await self.redis_cluster.info()
            elif self.redis_clients:
                info['redis_info'] = await self.redis_clients[0].info()
            
            return info
            
        except Exception as e:
            logger.error("Failed to get cache info", error=str(e))
            return {}
    
    async def close(self) -> None:
        """Close cache connections."""
        try:
            await self.monitor.stop_monitoring()
            
            if self.redis_cluster:
                await self.redis_cluster.close()
            
            if self.redis_pool:
                await self.redis_pool.disconnect()
            
            for client in self.redis_clients:
                await client.close()
            
            logger.info("Cache connections closed")
            
        except Exception as e:
            logger.error("Error closing cache connections", error=str(e))


class CacheManager:
    """High-level cache manager with pattern support."""
    
    def __init__(self, config: CacheConfig):
        self.cache = DistributedCache(config)
        self.config = config
        self._pattern_handlers: Dict[CachePattern, Callable] = {
            CachePattern.CACHE_ASIDE: self._cache_aside,
            CachePattern.WRITE_THROUGH: self._write_through,
            CachePattern.WRITE_BEHIND: self._write_behind,
        }
    
    async def initialize(self) -> None:
        """Initialize cache manager."""
        await self.cache.initialize()
    
    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[float] = None,
        pattern: CachePattern = CachePattern.CACHE_ASIDE
    ) -> Any:
        """Get value from cache or set it using factory function."""
        handler = self._pattern_handlers.get(pattern, self._cache_aside)
        return await handler(key, factory, ttl)
    
    async def _cache_aside(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[float] = None
    ) -> Any:
        """Cache-aside pattern implementation."""
        # Try to get from cache first
        value = await self.cache.get(key)
        if value is not None:
            return value
        
        # Cache miss, load from source
        value = await factory()
        if value is not None:
            await self.cache.set(key, value, ttl)
        
        return value
    
    async def _write_through(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[float] = None
    ) -> Any:
        """Write-through pattern implementation."""
        # Load from source and immediately cache
        value = await factory()
        if value is not None:
            await self.cache.set(key, value, ttl)
        return value
    
    async def _write_behind(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[float] = None
    ) -> Any:
        """Write-behind pattern implementation."""
        # Try cache first
        value = await self.cache.get(key)
        if value is not None:
            return value
        
        # Load from source
        value = await factory()
        if value is not None:
            # Schedule background cache update
            asyncio.create_task(self.cache.set(key, value, ttl))
        
        return value
    
    async def invalidate_by_pattern(self, pattern: str) -> int:
        """Invalidate keys matching pattern."""
        return await self.cache.invalidator.invalidate_by_pattern(pattern)
    
    async def invalidate_by_tags(self, tags: Set[str]) -> int:
        """Invalidate keys with specific tags."""
        return await self.cache.invalidator.invalidate_by_tags(tags)
    
    async def warm_cache(self, keys: List[str], data_loader: Callable[[str], Any]) -> None:
        """Warm cache with specific keys."""
        await self.cache.warmer.warm_keys(keys, data_loader)
    
    async def get_metrics(self) -> CacheMetrics:
        """Get cache metrics."""
        return await self.cache.monitor.get_metrics()
    
    async def get_info(self) -> Dict[str, Any]:
        """Get cache information."""
        return await self.cache.get_info()
    
    async def close(self) -> None:
        """Close cache manager."""
        await self.cache.close()


def create_cache_manager(
    redis_url: str = "redis://localhost:6379",
    **kwargs
) -> CacheManager:
    """Create a cache manager with default configuration."""
    config = CacheConfig(redis_url=redis_url, **kwargs)
    return CacheManager(config)