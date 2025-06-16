"""
Performance Optimizer for Python MCP Servers
Optimized for AMD Ryzen 7 7800X3D (16 threads) with 32GB RAM
"""

import asyncio
import multiprocessing
import concurrent.futures
import threading
import time
import gc
import os
import psutil
import redis
import logging
from typing import Any, Dict, List, Optional, Callable, Union, TypeVar, Generic
from dataclasses import dataclass, field
from functools import wraps, lru_cache
from collections import OrderedDict
from weakref import WeakValueDictionary
import json
import pickle
from datetime import datetime, timedelta

# CPU Configuration for AMD Ryzen 7 7800X3D
CPU_CORES = 16
THREAD_POOL_SIZE = CPU_CORES
PROCESS_POOL_SIZE = min(8, CPU_CORES - 2)  # Reserve 2 cores for main process

T = TypeVar('T')

@dataclass
class PerformanceConfig:
    """Performance optimization configuration"""
    # CPU Optimization
    enable_async_processing: bool = True
    thread_pool_size: int = THREAD_POOL_SIZE
    process_pool_size: int = PROCESS_POOL_SIZE
    enable_async_batching: bool = True
    
    # Memory Configuration (32GB RAM optimization)
    max_memory_usage_mb: int = 28 * 1024  # 28GB, leaving 4GB for system
    gc_threshold: int = 75  # percentage
    enable_memory_profiling: bool = True
    
    # Cache Configuration
    lru_cache_size: int = 10000
    cache_ttl: int = 3600  # seconds
    enable_redis_cache: bool = True
    redis_url: str = "redis://localhost:6379"
    
    # Connection Pooling
    db_connection_pool_size: int = 32
    http_connection_pool_size: int = 64
    keep_alive_timeout: int = 30000
    
    # Performance Monitoring
    enable_metrics: bool = True
    metrics_interval: int = 1
    alert_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'cpu_usage': 85.0,
        'memory_usage': 90.0,
        'response_time': 5000.0
    })

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    cpu: Dict[str, float]
    memory: Dict[str, float]
    cache: Dict[str, float]
    requests: Dict[str, float]
    connections: Dict[str, int]

class AsyncLRUCache(Generic[T]):
    """Async-friendly LRU Cache implementation"""
    
    def __init__(self, maxsize: int = 1000, ttl: int = 3600):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: OrderedDict[str, tuple[T, datetime]] = OrderedDict()
        self.lock = asyncio.Lock()
        
    async def get(self, key: str) -> Optional[T]:
        async with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                # Check TTL
                if datetime.now() - timestamp < timedelta(seconds=self.ttl):
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Expired, remove from cache
                    del self.cache[key]
            return None
    
    async def set(self, key: str, value: T) -> None:
        async with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.maxsize:
                    # Remove least recently used
                    self.cache.popitem(last=False)
            self.cache[key] = (value, datetime.now())
    
    async def delete(self, key: str) -> bool:
        async with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False
    
    async def clear(self) -> None:
        async with self.lock:
            self.cache.clear()
    
    async def size(self) -> int:
        async with self.lock:
            return len(self.cache)

class AsyncQueue:
    """High-performance async queue with concurrency control"""
    
    def __init__(self, max_concurrency: int = CPU_CORES):
        self.max_concurrency = max_concurrency
        self.queue = asyncio.Queue()
        self.active_tasks = set()
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.processing = False
    
    async def add(self, coro: Callable[[], Any]) -> Any:
        """Add a coroutine to the queue"""
        future = asyncio.Future()
        await self.queue.put((coro, future))
        
        if not self.processing:
            asyncio.create_task(self._process_queue())
        
        return await future
    
    async def _process_queue(self):
        """Process items in the queue with concurrency control"""
        if self.processing:
            return
            
        self.processing = True
        
        try:
            while not self.queue.empty() or self.active_tasks:
                # Wait for available slot
                await self.semaphore.acquire()
                
                try:
                    # Get next item from queue
                    coro, future = await asyncio.wait_for(
                        self.queue.get(), timeout=0.1
                    )
                    
                    # Process the item
                    task = asyncio.create_task(self._process_item(coro, future))
                    self.active_tasks.add(task)
                    
                except asyncio.TimeoutError:
                    self.semaphore.release()
                    if not self.active_tasks:
                        break
                    
                    # Wait for at least one task to complete
                    if self.active_tasks:
                        done, pending = await asyncio.wait(
                            self.active_tasks, 
                            return_when=asyncio.FIRST_COMPLETED
                        )
                        for task in done:
                            self.active_tasks.remove(task)
        finally:
            self.processing = False
    
    async def _process_item(self, coro: Callable, future: asyncio.Future):
        """Process a single item"""
        try:
            result = await coro()
            future.set_result(result)
        except Exception as e:
            future.set_exception(e)
        finally:
            self.semaphore.release()

class BatchProcessor:
    """Batch processor for efficient bulk operations"""
    
    def __init__(self, processor: Callable[[List[Any]], List[Any]], 
                 batch_size: int = 100, delay: float = 0.05):
        self.processor = processor
        self.batch_size = batch_size
        self.delay = delay
        self.batch: List[tuple[Any, asyncio.Future]] = []
        self.timer: Optional[asyncio.Handle] = None
        self.lock = asyncio.Lock()
    
    async def add(self, item: Any) -> Any:
        """Add an item for batch processing"""
        future = asyncio.Future()
        
        async with self.lock:
            self.batch.append((item, future))
            
            if len(self.batch) >= self.batch_size:
                await self._process_batch()
            else:
                if self.timer:
                    self.timer.cancel()
                self.timer = asyncio.get_event_loop().call_later(
                    self.delay, lambda: asyncio.create_task(self._process_batch())
                )
        
        return await future
    
    async def _process_batch(self):
        """Process the current batch"""
        async with self.lock:
            if not self.batch:
                return
            
            current_batch = self.batch.copy()
            self.batch.clear()
            
            if self.timer:
                self.timer.cancel()
                self.timer = None
        
        try:
            items = [item for item, _ in current_batch]
            results = await asyncio.get_event_loop().run_in_executor(
                None, self.processor, items
            )
            
            for (_, future), result in zip(current_batch, results):
                if not future.done():
                    future.set_result(result)
                    
        except Exception as e:
            for _, future in current_batch:
                if not future.done():
                    future.set_exception(e)

class PerformanceOptimizer:
    """Main performance optimizer class"""
    
    def __init__(self, config: PerformanceConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Initialize components
        self.lru_cache = AsyncLRUCache(config.lru_cache_size, config.cache_ttl)
        self.redis_client: Optional[redis.Redis] = None
        self.async_queue = AsyncQueue(config.thread_pool_size)
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=config.thread_pool_size
        )
        self.process_pool = concurrent.futures.ProcessPoolExecutor(
            max_workers=config.process_pool_size
        )
        
        # Metrics tracking
        self.request_count = 0
        self.error_count = 0
        self.response_times: List[float] = []
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Initialize Redis if enabled
        if config.enable_redis_cache:
            self._init_redis()
        
        # Start monitoring
        if config.enable_metrics:
            self._start_monitoring()
        
        # Optimize Python runtime
        self._optimize_runtime()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(
                self.config.redis_url,
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30
            )
            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis cache initialized successfully")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Redis: {e}")
            self.redis_client = None
    
    def _start_monitoring(self):
        """Start performance monitoring"""
        asyncio.create_task(self._monitor_performance())
    
    def _optimize_runtime(self):
        """Optimize Python runtime for performance"""
        # Set garbage collection thresholds for better performance
        gc.set_threshold(700, 10, 10)
        
        # Enable garbage collection debugging if memory profiling is enabled
        if self.config.enable_memory_profiling:
            # Monitor memory usage periodically
            asyncio.create_task(self._monitor_memory())
    
    async def _monitor_performance(self):
        """Monitor performance metrics"""
        while True:
            try:
                metrics = await self._collect_metrics()
                await self._check_alerts(metrics)
                await asyncio.sleep(self.config.metrics_interval)
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_memory(self):
        """Monitor memory usage and trigger GC if needed"""
        while True:
            try:
                process = psutil.Process()
                memory_percent = process.memory_percent()
                
                if memory_percent > self.config.gc_threshold:
                    # Force garbage collection
                    gc.collect()
                    self.logger.info(f"Forced garbage collection at {memory_percent:.1f}% memory usage")
                
                await asyncio.sleep(10)
            except Exception as e:
                self.logger.error(f"Error in memory monitoring: {e}")
                await asyncio.sleep(30)
    
    async def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        process = psutil.Process()
        
        # CPU metrics
        cpu_percent = process.cpu_percent()
        cpu_times = process.cpu_times()
        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        
        # Memory metrics
        memory_info = process.memory_info()
        memory_percent = process.memory_percent()
        
        # Cache metrics
        cache_hit_rate = 0
        if self.cache_hits + self.cache_misses > 0:
            cache_hit_rate = (self.cache_hits / (self.cache_hits + self.cache_misses)) * 100
        
        # Request metrics
        avg_response_time = 0
        if self.response_times:
            avg_response_time = sum(self.response_times) / len(self.response_times)
            # Keep only recent response times
            if len(self.response_times) > 1000:
                self.response_times = self.response_times[-1000:]
        
        error_rate = 0
        if self.request_count > 0:
            error_rate = (self.error_count / self.request_count) * 100
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu={
                'usage': cpu_percent,
                'load_average': load_avg[0],
                'cores': psutil.cpu_count()
            },
            memory={
                'used': memory_info.rss,
                'total': psutil.virtual_memory().total,
                'percentage': memory_percent
            },
            cache={
                'hit_rate': cache_hit_rate,
                'miss_rate': 100 - cache_hit_rate,
                'size': await self.lru_cache.size()
            },
            requests={
                'total': self.request_count,
                'error_rate': error_rate,
                'average_response_time': avg_response_time
            },
            connections={
                'active': threading.active_count()
            }
        )
    
    async def _check_alerts(self, metrics: PerformanceMetrics):
        """Check for alert conditions"""
        thresholds = self.config.alert_thresholds
        
        if metrics.cpu['usage'] > thresholds['cpu_usage']:
            self.logger.warning(
                f"High CPU usage: {metrics.cpu['usage']:.1f}% "
                f"(threshold: {thresholds['cpu_usage']}%)"
            )
        
        if metrics.memory['percentage'] > thresholds['memory_usage']:
            self.logger.warning(
                f"High memory usage: {metrics.memory['percentage']:.1f}% "
                f"(threshold: {thresholds['memory_usage']}%)"
            )
        
        if metrics.requests['average_response_time'] > thresholds['response_time']:
            self.logger.warning(
                f"High response time: {metrics.requests['average_response_time']:.1f}ms "
                f"(threshold: {thresholds['response_time']}ms)"
            )
    
    # Cache operations
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            # Try LRU cache first
            value = await self.lru_cache.get(key)
            if value is not None:
                self.cache_hits += 1
                return value
            
            # Try Redis cache
            if self.redis_client:
                redis_value = self.redis_client.get(key)
                if redis_value:
                    # Deserialize and populate LRU cache
                    try:
                        value = json.loads(redis_value)
                        await self.lru_cache.set(key, value)
                        self.cache_hits += 1
                        return value
                    except json.JSONDecodeError:
                        # Try pickle if JSON fails
                        try:
                            value = pickle.loads(redis_value.encode())
                            await self.lru_cache.set(key, value)
                            self.cache_hits += 1
                            return value
                        except:
                            pass
            
            self.cache_misses += 1
            return None
            
        except Exception as e:
            self.logger.error(f"Cache get error for key {key}: {e}")
            self.cache_misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        try:
            # Set in LRU cache
            await self.lru_cache.set(key, value)
            
            # Set in Redis cache
            if self.redis_client:
                try:
                    serialized = json.dumps(value)
                except (TypeError, ValueError):
                    # Fall back to pickle for non-JSON serializable objects
                    serialized = pickle.dumps(value)
                
                cache_ttl = ttl or self.config.cache_ttl
                self.redis_client.setex(key, cache_ttl, serialized)
                
        except Exception as e:
            self.logger.error(f"Cache set error for key {key}: {e}")
    
    async def delete(self, key: str) -> None:
        """Delete value from cache"""
        try:
            await self.lru_cache.delete(key)
            if self.redis_client:
                self.redis_client.delete(key)
        except Exception as e:
            self.logger.error(f"Cache delete error for key {key}: {e}")
    
    async def clear(self) -> None:
        """Clear all cached values"""
        try:
            await self.lru_cache.clear()
            if self.redis_client:
                self.redis_client.flushdb()
        except Exception as e:
            self.logger.error(f"Cache clear error: {e}")
    
    # Async processing
    async def process_async(self, coro: Callable[[], Any]) -> Any:
        """Process coroutine asynchronously with queue management"""
        return await self.async_queue.add(coro)
    
    async def process_in_thread(self, func: Callable, *args, **kwargs) -> Any:
        """Process function in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, func, *args, **kwargs)
    
    async def process_in_process(self, func: Callable, *args, **kwargs) -> Any:
        """Process function in process pool for CPU-intensive tasks"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.process_pool, func, *args, **kwargs)
    
    # Request tracking
    def track_request(self):
        """Track a new request"""
        self.request_count += 1
    
    def track_error(self):
        """Track an error"""
        self.error_count += 1
    
    def track_response_time(self, response_time: float):
        """Track response time"""
        self.response_times.append(response_time)
    
    # Performance metrics
    async def get_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics"""
        return await self._collect_metrics()
    
    # Cleanup
    async def cleanup(self):
        """Cleanup resources"""
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)
        
        if self.redis_client:
            self.redis_client.close()
        
        await self.lru_cache.clear()
        
        self.logger.info("Performance optimizer cleaned up")

# Decorator utilities
def memoize_async(maxsize: int = 128, ttl: int = 3600):
    """Async memoization decorator"""
    def decorator(func):
        cache = AsyncLRUCache(maxsize, ttl)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Create cache key
            key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try cache first
            result = await cache.get(key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(key, result)
            return result
        
        wrapper.cache = cache
        return wrapper
    return decorator

def rate_limit(calls_per_second: float):
    """Rate limiting decorator"""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                await asyncio.sleep(left_to_wait)
            ret = await func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator

def retry_async(max_retries: int = 3, delay: float = 1.0, exponential_backoff: bool = True):
    """Async retry decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        wait_time = delay * (2 ** attempt if exponential_backoff else 1)
                        await asyncio.sleep(wait_time)
                    else:
                        raise last_exception
            
            raise last_exception
        return wrapper
    return decorator

# Batch processing utilities
def create_batch_processor(processor_func: Callable[[List[Any]], List[Any]], 
                          batch_size: int = 100, 
                          delay: float = 0.05) -> BatchProcessor:
    """Create a batch processor instance"""
    return BatchProcessor(processor_func, batch_size, delay)

# Performance monitoring utilities
async def benchmark_function(func: Callable, *args, **kwargs) -> tuple[Any, float]:
    """Benchmark a function and return result with execution time"""
    start_time = time.time()
    try:
        if asyncio.iscoroutinefunction(func):
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
        return result, time.time() - start_time
    except Exception as e:
        return e, time.time() - start_time