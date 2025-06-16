"""
Distributed Rate Limiting System with Redis

This module provides a comprehensive rate limiting solution with multiple algorithms:
- Token Bucket: Smooth rate limiting with burst capacity
- Sliding Window: Precise rate limiting over time windows
- Fixed Window: Simple rate limiting with reset intervals

Features:
- Redis-backed distributed rate limiting
- Per-user, per-IP, and global rate limiting
- Multiple algorithm support
- High-throughput optimization
- Monitoring and metrics
- Configurable rate limits per endpoint
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import redis.asyncio as aioredis
    from redis.asyncio import Redis
    from redis.exceptions import RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    # Create dummy classes for type hints
    class Redis:
        pass
    class RedisError(Exception):
        pass

logger = logging.getLogger(__name__)


class RateLimitAlgorithm(Enum):
    """Available rate limiting algorithms."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


class RateLimitScope(Enum):
    """Rate limiting scopes."""
    GLOBAL = "global"
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting rules."""
    requests: int  # Number of requests allowed
    window: int    # Time window in seconds
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    scope: RateLimitScope = RateLimitScope.PER_IP
    burst: Optional[int] = None  # For token bucket algorithm
    redis_key_prefix: str = "rate_limit"
    redis_ttl: int = 86400  # 24 hours default TTL


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None
    limit: int = 0
    scope: str = ""
    algorithm: str = ""


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, result: RateLimitResult):
        self.result = result
        super().__init__(f"Rate limit exceeded. Retry after {result.retry_after}s")


class BaseRateLimiter(ABC):
    """Base class for rate limiting algorithms."""
    
    def __init__(self, redis: Redis, config: RateLimitConfig):
        self.redis = redis
        self.config = config
        self.metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'redis_errors': 0
        }
    
    @abstractmethod
    async def check_rate_limit(self, key: str, identifier: str) -> RateLimitResult:
        """Check if request is within rate limit."""
        pass
    
    def _generate_key(self, key: str, identifier: str) -> str:
        """Generate Redis key for rate limiting."""
        return f"{self.config.redis_key_prefix}:{self.config.algorithm.value}:{key}:{identifier}"
    
    async def _redis_execute(self, pipeline_func):
        """Execute Redis pipeline with error handling."""
        try:
            async with self.redis.pipeline() as pipe:
                return await pipeline_func(pipe)
        except RedisError as e:
            self.metrics['redis_errors'] += 1
            logger.error(f"Redis error in rate limiter: {e}")
            # Return permissive result on Redis failure
            return RateLimitResult(
                allowed=True,
                remaining=self.config.requests,
                reset_time=time.time() + self.config.window,
                limit=self.config.requests,
                scope=self.config.scope.value,
                algorithm=self.config.algorithm.value
            )


class TokenBucketRateLimiter(BaseRateLimiter):
    """Token bucket rate limiting algorithm.
    
    Allows bursts up to bucket size, then maintains steady rate.
    Uses Redis to store bucket state (tokens, last_refill).
    """
    
    async def check_rate_limit(self, key: str, identifier: str) -> RateLimitResult:
        """Check rate limit using token bucket algorithm."""
        self.metrics['total_requests'] += 1
        
        redis_key = self._generate_key(key, identifier)
        current_time = time.time()
        
        # Token bucket parameters
        capacity = self.config.burst or self.config.requests
        refill_rate = self.config.requests / self.config.window
        
        async def _pipeline_func(pipe):
            # Get current bucket state
            await pipe.multi()
            bucket_data = await pipe.hmget(redis_key, 'tokens', 'last_refill')
            
            if bucket_data[0] is None:
                # Initialize bucket
                tokens = float(capacity)
                last_refill = current_time
            else:
                tokens = float(bucket_data[0])
                last_refill = float(bucket_data[1])
            
            # Calculate tokens to add based on time elapsed
            time_elapsed = current_time - last_refill
            tokens_to_add = time_elapsed * refill_rate
            tokens = min(capacity, tokens + tokens_to_add)
            
            if tokens >= 1.0:
                # Allow request
                tokens -= 1.0
                allowed = True
                
                # Update bucket state
                await pipe.hmset(redis_key, {
                    'tokens': str(tokens),
                    'last_refill': str(current_time)
                })
                await pipe.expire(redis_key, self.config.redis_ttl)
                await pipe.execute()
                
                self.metrics['allowed_requests'] += 1
                return RateLimitResult(
                    allowed=True,
                    remaining=int(tokens),
                    reset_time=current_time + ((capacity - tokens) / refill_rate),
                    limit=capacity,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
            else:
                # Deny request
                self.metrics['denied_requests'] += 1
                retry_after = int((1.0 - tokens) / refill_rate) + 1
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=current_time + retry_after,
                    retry_after=retry_after,
                    limit=capacity,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
        
        return await self._redis_execute(_pipeline_func)


class SlidingWindowRateLimiter(BaseRateLimiter):
    """Sliding window rate limiting algorithm.
    
    Maintains precise rate limiting over a sliding time window.
    Uses Redis sorted sets to track request timestamps.
    """
    
    async def check_rate_limit(self, key: str, identifier: str) -> RateLimitResult:
        """Check rate limit using sliding window algorithm."""
        self.metrics['total_requests'] += 1
        
        redis_key = self._generate_key(key, identifier)
        current_time = time.time()
        window_start = current_time - self.config.window
        
        async def _pipeline_func(pipe):
            # Remove expired entries and count current requests
            await pipe.multi()
            await pipe.zremrangebyscore(redis_key, 0, window_start)
            current_count = await pipe.zcard(redis_key)
            
            if current_count < self.config.requests:
                # Allow request
                await pipe.zadd(redis_key, {str(current_time): current_time})
                await pipe.expire(redis_key, self.config.redis_ttl)
                await pipe.execute()
                
                self.metrics['allowed_requests'] += 1
                return RateLimitResult(
                    allowed=True,
                    remaining=self.config.requests - current_count - 1,
                    reset_time=current_time + self.config.window,
                    limit=self.config.requests,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
            else:
                # Deny request - get oldest request time for retry calculation
                oldest_requests = await pipe.zrange(redis_key, 0, 0, withscores=True)
                
                if oldest_requests:
                    oldest_time = oldest_requests[0][1]
                    retry_after = int(oldest_time + self.config.window - current_time) + 1
                else:
                    retry_after = self.config.window
                
                self.metrics['denied_requests'] += 1
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=current_time + retry_after,
                    retry_after=retry_after,
                    limit=self.config.requests,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
        
        return await self._redis_execute(_pipeline_func)


class FixedWindowRateLimiter(BaseRateLimiter):
    """Fixed window rate limiting algorithm.
    
    Simple rate limiting with fixed time windows that reset at intervals.
    Uses Redis counters with expiration.
    """
    
    async def check_rate_limit(self, key: str, identifier: str) -> RateLimitResult:
        """Check rate limit using fixed window algorithm."""
        self.metrics['total_requests'] += 1
        
        current_time = time.time()
        window_id = int(current_time // self.config.window)
        redis_key = f"{self._generate_key(key, identifier)}:{window_id}"
        
        async def _pipeline_func(pipe):
            await pipe.multi()
            current_count = await pipe.get(redis_key)
            current_count = int(current_count) if current_count else 0
            
            if current_count < self.config.requests:
                # Allow request
                await pipe.incr(redis_key)
                await pipe.expire(redis_key, self.config.window * 2)  # Buffer for clock skew
                await pipe.execute()
                
                self.metrics['allowed_requests'] += 1
                window_reset = (window_id + 1) * self.config.window
                
                return RateLimitResult(
                    allowed=True,
                    remaining=self.config.requests - current_count - 1,
                    reset_time=window_reset,
                    limit=self.config.requests,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
            else:
                # Deny request
                self.metrics['denied_requests'] += 1
                window_reset = (window_id + 1) * self.config.window
                retry_after = int(window_reset - current_time) + 1
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=window_reset,
                    retry_after=retry_after,
                    limit=self.config.requests,
                    scope=self.config.scope.value,
                    algorithm=self.config.algorithm.value
                )
        
        return await self._redis_execute(_pipeline_func)


class DistributedRateLimiter:
    """Main distributed rate limiter with multiple algorithms and scopes."""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        redis_pool_size: int = 20,
        default_config: Optional[RateLimitConfig] = None
    ):
        self.redis_url = redis_url
        self.redis_pool_size = redis_pool_size
        self.redis: Optional[Redis] = None
        
        # Default configuration
        self.default_config = default_config or RateLimitConfig(
            requests=100,
            window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        
        # Store rate limiters for different algorithms
        self._limiters: Dict[RateLimitAlgorithm, BaseRateLimiter] = {}
        
        # Rate limit rules per endpoint
        self.endpoint_configs: Dict[str, List[RateLimitConfig]] = {}
        
        # Global metrics
        self.global_metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'redis_errors': 0,
            'algorithm_usage': {alg.value: 0 for alg in RateLimitAlgorithm}
        }
    
    async def initialize(self):
        """Initialize Redis connection and rate limiters."""
        try:
            self.redis = aioredis.from_url(
                self.redis_url,
                max_connections=self.redis_pool_size,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={
                    1: 1,  # TCP_KEEPIDLE
                    2: 3,  # TCP_KEEPINTVL
                    3: 5   # TCP_KEEPCNT
                }
            )
            
            # Test connection
            await self.redis.ping()
            logger.info("Rate limiter Redis connection established")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis for rate limiter: {e}")
            raise
    
    async def close(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
    
    def _get_limiter(self, config: RateLimitConfig) -> BaseRateLimiter:
        """Get or create rate limiter for algorithm."""
        if config.algorithm not in self._limiters:
            if config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                self._limiters[config.algorithm] = TokenBucketRateLimiter(self.redis, config)
            elif config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                self._limiters[config.algorithm] = SlidingWindowRateLimiter(self.redis, config)
            elif config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                self._limiters[config.algorithm] = FixedWindowRateLimiter(self.redis, config)
            else:
                raise ValueError(f"Unsupported algorithm: {config.algorithm}")
        
        return self._limiters[config.algorithm]
    
    def configure_endpoint(
        self,
        endpoint: str,
        configs: List[RateLimitConfig]
    ):
        """Configure rate limiting rules for an endpoint."""
        self.endpoint_configs[endpoint] = configs
        logger.info(f"Configured rate limiting for endpoint {endpoint} with {len(configs)} rules")
    
    def _generate_identifier(
        self,
        scope: RateLimitScope,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None
    ) -> str:
        """Generate identifier based on scope."""
        if scope == RateLimitScope.GLOBAL:
            return "global"
        elif scope == RateLimitScope.PER_IP:
            return ip_address or "unknown_ip"
        elif scope == RateLimitScope.PER_USER:
            return user_id or "anonymous"
        elif scope == RateLimitScope.PER_ENDPOINT:
            return endpoint or "unknown_endpoint"
        else:
            raise ValueError(f"Unsupported scope: {scope}")
    
    async def check_rate_limit(
        self,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None,
        raise_on_limit: bool = False
    ) -> List[RateLimitResult]:
        """Check rate limits for an endpoint with all configured rules."""
        if not self.redis:
            await self.initialize()
        
        # Get configurations for this endpoint, fall back to default
        configs = self.endpoint_configs.get(endpoint, [self.default_config])
        
        results = []
        
        for config in configs:
            self.global_metrics['total_requests'] += 1
            self.global_metrics['algorithm_usage'][config.algorithm.value] += 1
            
            # Generate identifier based on scope
            identifier = self._generate_identifier(
                config.scope, ip_address, user_id, endpoint
            )
            
            # Get appropriate rate limiter
            limiter = self._get_limiter(config)
            
            # Check rate limit
            result = await limiter.check_rate_limit(endpoint, identifier)
            results.append(result)
            
            # Update global metrics
            if result.allowed:
                self.global_metrics['allowed_requests'] += 1
            else:
                self.global_metrics['denied_requests'] += 1
                
                if raise_on_limit:
                    raise RateLimitExceeded(result)
        
        return results
    
    async def is_rate_limited(
        self,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> bool:
        """Check if any rate limit is exceeded for the endpoint."""
        results = await self.check_rate_limit(endpoint, ip_address, user_id)
        return any(not result.allowed for result in results)
    
    async def get_rate_limit_headers(
        self,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, str]:
        """Get rate limit headers for HTTP responses."""
        results = await self.check_rate_limit(endpoint, ip_address, user_id)
        
        if not results:
            return {}
        
        # Use the most restrictive result for headers
        most_restrictive = min(results, key=lambda r: r.remaining if r.allowed else -1)
        
        headers = {
            'X-RateLimit-Limit': str(most_restrictive.limit),
            'X-RateLimit-Remaining': str(most_restrictive.remaining),
            'X-RateLimit-Reset': str(int(most_restrictive.reset_time)),
            'X-RateLimit-Scope': most_restrictive.scope,
            'X-RateLimit-Algorithm': most_restrictive.algorithm
        }
        
        if not most_restrictive.allowed and most_restrictive.retry_after:
            headers['Retry-After'] = str(most_restrictive.retry_after)
        
        return headers
    
    async def reset_rate_limit(
        self,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None,
        scope: Optional[RateLimitScope] = None
    ):
        """Reset rate limit for specific identifier."""
        if not self.redis:
            await self.initialize()
        
        configs = self.endpoint_configs.get(endpoint, [self.default_config])
        
        for config in configs:
            if scope and config.scope != scope:
                continue
            
            identifier = self._generate_identifier(
                config.scope, ip_address, user_id, endpoint
            )
            
            redis_key_pattern = f"{config.redis_key_prefix}:{config.algorithm.value}:{endpoint}:{identifier}*"
            
            # Delete all matching keys
            keys = await self.redis.keys(redis_key_pattern)
            if keys:
                await self.redis.delete(*keys)
                logger.info(f"Reset rate limit for {redis_key_pattern}")
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive rate limiting metrics."""
        limiter_metrics = {}
        for algorithm, limiter in self._limiters.items():
            limiter_metrics[algorithm.value] = limiter.metrics
        
        return {
            'global_metrics': self.global_metrics,
            'limiter_metrics': limiter_metrics,
            'endpoint_configs': {
                endpoint: [
                    {
                        'requests': config.requests,
                        'window': config.window,
                        'algorithm': config.algorithm.value,
                        'scope': config.scope.value
                    }
                    for config in configs
                ]
                for endpoint, configs in self.endpoint_configs.items()
            },
            'redis_info': {
                'connected': self.redis is not None and await self._check_redis_health(),
                'url': self.redis_url
            }
        }
    
    async def _check_redis_health(self) -> bool:
        """Check if Redis is healthy."""
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False


# Global rate limiter instance
_global_rate_limiter: Optional[DistributedRateLimiter] = None


def get_rate_limiter() -> DistributedRateLimiter:
    """Get global rate limiter instance."""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = DistributedRateLimiter()
    return _global_rate_limiter


async def initialize_rate_limiter(redis_url: str = "redis://localhost:6379/0"):
    """Initialize global rate limiter."""
    global _global_rate_limiter
    _global_rate_limiter = DistributedRateLimiter(redis_url=redis_url)
    await _global_rate_limiter.initialize()


async def close_rate_limiter():
    """Close global rate limiter."""
    global _global_rate_limiter
    if _global_rate_limiter:
        await _global_rate_limiter.close()
        _global_rate_limiter = None