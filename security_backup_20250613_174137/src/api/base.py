"""Base API client implementation with common patterns."""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Type, TypeVar

import aiohttp
from aiohttp import ClientError, ClientTimeout

from src.core.circuit_breaker import CircuitBreaker
from src.core.exceptions import APIError, RateLimitError
from src.core.lru_cache import LRUCache
from src.core.retry import RetryConfig, retry_with_backoff

logger = logging.getLogger(__name__)

T = TypeVar('T', bound='BaseAPIClient')


class RateLimiter:
    """Rate limiter implementation with sliding window."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    async def acquire(self, key: str = "default") -> None:
        """Acquire rate limit permission."""
        now = time.time()
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < self.window_seconds
        ]
        
        if len(self.requests[key]) >= self.max_requests:
            sleep_time = self.window_seconds - (now - self.requests[key][0])
            if sleep_time > 0:
                logger.warning(f"Rate limit reached for {key}, sleeping {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
                return await self.acquire(key)
        
        self.requests[key].append(now)


class BaseAPIClient(ABC):
    """Base API client with common functionality."""
    
    def __init__(
        self,
        api_key: str,
        base_url: str,
        max_retries: int = 3,
        timeout: int = 30,
        cache_ttl: int = 300,
        rate_limit: Optional[tuple[int, int]] = None,
        circuit_breaker_enabled: bool = True
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.max_retries = max_retries
        self.timeout = ClientTimeout(total=timeout)
        
        # Cache configuration
        self.cache = LRUCache(capacity=1000)
        self.cache_ttl = cache_ttl
        
        # Rate limiting
        if rate_limit:
            self.rate_limiter = RateLimiter(*rate_limit)
        else:
            self.rate_limiter = None
        
        # Circuit breaker
        if circuit_breaker_enabled:
            self.circuit_breaker = CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60,
                expected_exception=APIError
            )
        else:
            self.circuit_breaker = None
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._headers = self._build_headers()
        
        # Metrics
        self.metrics = {
            'requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'rate_limits': 0
        }
    
    @abstractmethod
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        pass
    
    @abstractmethod
    async def _process_response(self, response: Dict[str, Any]) -> Any:
        """Process API response into desired format."""
        pass
    
    @property
    async def session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=self._headers
            )
        return self._session
    
    def _cache_key(self, method: str, url: str, **kwargs) -> str:
        """Generate cache key for request."""
        # Create a stable hash of the request parameters
        params = {
            'method': method,
            'url': url,
            'params': kwargs.get('params', {}),
            'json': kwargs.get('json', {})
        }
        key_str = json.dumps(params, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        use_cache: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """Make HTTP request with retries and caching."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        cache_key = self._cache_key(method, url, **kwargs)
        
        # Check cache first
        if use_cache and method.upper() == 'GET':
            cached = self.cache.get(cache_key)
            if cached is not None:
                self.metrics['cache_hits'] += 1
                logger.debug(f"Cache hit for {url}")
                return cached
            self.metrics['cache_misses'] += 1
        
        # Apply rate limiting
        if self.rate_limiter:
            await self.rate_limiter.acquire(self.api_key[:8])
        
        # Retry configuration
        retry_config = RetryConfig(
            max_retries=self.max_retries,
            backoff_factor=2.0,
            exceptions=(ClientError, asyncio.TimeoutError)
        )
        
        @retry_with_backoff(retry_config)
        async def _request():
            self.metrics['requests'] += 1
            
            try:
                session = await self.session
                
                # Use circuit breaker if enabled
                if self.circuit_breaker:
                    async with self.circuit_breaker:
                        async with session.request(method, url, **kwargs) as response:
                            return await self._handle_response(response)
                else:
                    async with session.request(method, url, **kwargs) as response:
                        return await self._handle_response(response)
                        
            except Exception as e:
                self.metrics['errors'] += 1
                logger.error(f"Request failed: {url} - {str(e)}")
                raise
        
        result = await _request()
        
        # Cache successful GET requests
        if use_cache and method.upper() == 'GET':
            self.cache.put(cache_key, result, ttl=self.cache_ttl)
        
        return result
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        """Handle API response and errors."""
        try:
            data = await response.json()
        except Exception:
            data = {'text': await response.text()}
        
        if response.status == 429:
            self.metrics['rate_limits'] += 1
            retry_after = response.headers.get('Retry-After', '60')
            raise RateLimitError(f"Rate limit exceeded. Retry after {retry_after}s")
        
        if response.status >= 400:
            error_msg = data.get('error', data.get('message', str(data)))
            raise APIError(f"API error ({response.status}): {error_msg}")
        
        return data
    
    async def health_check(self) -> Dict[str, Any]:
        """Check API health and return metrics."""
        return {
            'status': 'healthy',
            'metrics': self.metrics,
            'cache_size': len(self.cache.cache),
            'circuit_breaker': {
                'state': self.circuit_breaker.state if self.circuit_breaker else 'disabled',
                'failure_count': self.circuit_breaker.failure_count if self.circuit_breaker else 0
            }
        }
    
    async def close(self):
        """Close session and cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self: T) -> T:
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


class APIKeyRotator:
    """Manage multiple API keys with rotation."""
    
    def __init__(self, api_keys: list[str]):
        self.api_keys = api_keys
        self.current_index = 0
        self.key_metrics = defaultdict(lambda: {'requests': 0, 'errors': 0})
    
    def get_current_key(self) -> str:
        """Get current API key."""
        return self.api_keys[self.current_index]
    
    def rotate(self) -> str:
        """Rotate to next API key."""
        self.current_index = (self.current_index + 1) % len(self.api_keys)
        return self.get_current_key()
    
    def mark_error(self, key: str):
        """Mark error for a key."""
        self.key_metrics[key]['errors'] += 1
    
    def mark_success(self, key: str):
        """Mark successful request for a key."""
        self.key_metrics[key]['requests'] += 1