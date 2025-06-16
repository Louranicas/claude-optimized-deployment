"""
Comprehensive retry patterns for preventing thundering herd and cascading failures.

This module provides advanced retry strategies with:
- Multiple retry patterns (exponential backoff, linear, fixed, adaptive)
- Jitter and rate limiting to prevent thundering herd
- Retry budgets to prevent cascading failures
- Idempotency key management
- Service-specific retry policies
- Circuit breaker integration
- Retry monitoring and metrics
- Graceful degradation patterns
- Configuration management
- Testing and validation framework
"""

import asyncio
import functools
import hashlib
import json
import logging
import math
import random
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union, 
    Protocol, runtime_checkable
)
from weakref import WeakValueDictionary

try:
    from src.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, get_circuit_breaker
    CIRCUIT_BREAKER_AVAILABLE = True
except ImportError:
    CIRCUIT_BREAKER_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class RetryStrategy(Enum):
    """Comprehensive retry strategies."""
    EXPONENTIAL = "exponential"
    EXPONENTIAL_JITTER = "exponential_jitter"
    LINEAR = "linear"
    FIXED = "fixed"
    ADAPTIVE = "adaptive"
    FIBONACCI = "fibonacci"
    DECORRELATED_JITTER = "decorrelated_jitter"
    CONSTANT_JITTER = "constant_jitter"


class ServiceType(Enum):
    """Service types for specialized retry policies."""
    AI_CLAUDE = "ai_claude"
    AI_OPENAI = "ai_openai"
    AI_GOOGLE = "ai_google"
    AI_DEEPSEEK = "ai_deepseek"
    AI_GROQ = "ai_groq"
    AI_OLLAMA = "ai_ollama"
    AI_HUGGINGFACE = "ai_huggingface"
    DATABASE = "database"
    CACHE = "cache"
    STORAGE = "storage"
    MESSAGE_QUEUE = "message_queue"
    HTTP_API = "http_api"
    MICROSERVICE = "microservice"
    THIRD_PARTY_API = "third_party_api"
    MCP_SERVER = "mcp_server"
    UNKNOWN = "unknown"


class RetryBudgetType(Enum):
    """Types of retry budgets."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    ADAPTIVE = "adaptive"


@runtime_checkable
class IdempotencyProvider(Protocol):
    """Protocol for idempotency key providers."""
    
    def generate_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate idempotency key for operation."""
        ...
    
    async def check_previous_result(self, key: str) -> Optional[Any]:
        """Check for previous result with this key."""
        ...
    
    async def store_result(self, key: str, result: Any, ttl: int = 3600) -> None:
        """Store operation result."""
        ...


@dataclass
class RetryBudgetConfig:
    """Configuration for retry budgets."""
    budget_type: RetryBudgetType = RetryBudgetType.TOKEN_BUCKET
    max_retries_per_minute: int = 60
    max_retries_per_hour: int = 1000
    burst_capacity: int = 10
    refill_rate: float = 1.0  # tokens per second
    adaptive_threshold: float = 0.8  # success rate threshold for adaptation
    enable_global_budget: bool = True
    enable_per_service_budget: bool = True


@dataclass
class RetryMetrics:
    """Metrics for retry operations."""
    total_attempts: int = 0
    successful_retries: int = 0
    failed_retries: int = 0
    abandoned_retries: int = 0
    circuit_breaker_rejections: int = 0
    budget_rejections: int = 0
    idempotency_hits: int = 0
    total_wait_time: float = 0.0
    average_wait_time: float = 0.0
    max_wait_time: float = 0.0
    retry_reasons: Dict[str, int] = field(default_factory=dict)
    success_by_attempt: Dict[int, int] = field(default_factory=dict)
    failure_by_attempt: Dict[int, int] = field(default_factory=dict)
    last_retry_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_attempts": self.total_attempts,
            "successful_retries": self.successful_retries,
            "failed_retries": self.failed_retries,
            "abandoned_retries": self.abandoned_retries,
            "circuit_breaker_rejections": self.circuit_breaker_rejections,
            "budget_rejections": self.budget_rejections,
            "idempotency_hits": self.idempotency_hits,
            "total_wait_time": self.total_wait_time,
            "average_wait_time": self.average_wait_time,
            "max_wait_time": self.max_wait_time,
            "retry_reasons": dict(self.retry_reasons),
            "success_by_attempt": dict(self.success_by_attempt),
            "failure_by_attempt": dict(self.failure_by_attempt),
            "last_retry_time": self.last_retry_time.isoformat() if self.last_retry_time else None,
            "success_rate": self.get_success_rate(),
            "average_attempts_to_success": self.get_average_attempts_to_success()
        }
    
    def get_success_rate(self) -> float:
        """Calculate overall success rate."""
        total = self.successful_retries + self.failed_retries
        return self.successful_retries / total if total > 0 else 0.0
    
    def get_average_attempts_to_success(self) -> float:
        """Calculate average attempts until success."""
        if not self.success_by_attempt:
            return 0.0
        
        total_attempts = sum(attempt * count for attempt, count in self.success_by_attempt.items())
        total_successes = sum(self.success_by_attempt.values())
        return total_attempts / total_successes if total_successes > 0 else 0.0


@dataclass
class RetryPolicyConfig:
    """Comprehensive retry policy configuration."""
    # Basic retry parameters
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    timeout: float = 300.0
    
    # Strategy configuration
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_JITTER
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1
    
    # Exception handling
    retryable_exceptions: Set[Type[Exception]] = field(default_factory=set)
    non_retryable_exceptions: Set[Type[Exception]] = field(default_factory=set)
    retryable_status_codes: Set[int] = field(default_factory=set)
    
    # Advanced features
    enable_circuit_breaker: bool = True
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    enable_retry_budget: bool = True
    retry_budget_config: Optional[RetryBudgetConfig] = None
    enable_idempotency: bool = True
    idempotency_provider: Optional[IdempotencyProvider] = None
    
    # Service-specific settings
    service_type: ServiceType = ServiceType.UNKNOWN
    service_name: str = "unknown"
    
    # Monitoring and logging
    enable_metrics: bool = True
    log_retries: bool = True
    log_level: str = "WARNING"
    
    # Rate limiting and throttling
    enable_rate_limiting: bool = True
    max_concurrent_retries: int = 10
    enable_adaptive_backoff: bool = True
    
    def __post_init__(self):
        """Initialize default configurations."""
        if not self.retryable_exceptions:
            self.retryable_exceptions = {
                ConnectionError,
                TimeoutError,
                OSError,
                IOError,
            }
        
        if not self.non_retryable_exceptions:
            self.non_retryable_exceptions = {
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                ImportError,
                SyntaxError,
            }
        
        if not self.retryable_status_codes:
            self.retryable_status_codes = {408, 429, 500, 502, 503, 504}
        
        if self.circuit_breaker_config is None and self.enable_circuit_breaker:
            self.circuit_breaker_config = CircuitBreakerConfig(
                name=f"{self.service_name}_circuit_breaker",
                failure_threshold=5,
                timeout=60.0
            )
        
        if self.retry_budget_config is None and self.enable_retry_budget:
            self.retry_budget_config = RetryBudgetConfig()


class TokenBucket:
    """Token bucket implementation for retry rate limiting."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """Initialize token bucket."""
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from bucket."""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            
            # Refill tokens
            tokens_to_add = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = now
            
            # Try to consume
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    async def get_tokens(self) -> float:
        """Get current token count."""
        async with self._lock:
            return self.tokens


class RetryBudget:
    """Retry budget implementation to prevent cascading failures."""
    
    def __init__(self, config: RetryBudgetConfig):
        """Initialize retry budget."""
        self.config = config
        self._token_bucket = TokenBucket(
            capacity=config.burst_capacity,
            refill_rate=config.refill_rate
        )
        self._sliding_window = deque(maxlen=60)  # Track last 60 seconds
        self._hourly_window = deque(maxlen=3600)  # Track last hour
        self._lock = asyncio.Lock()
    
    async def can_retry(self) -> bool:
        """Check if retry is allowed under current budget."""
        if self.config.budget_type == RetryBudgetType.TOKEN_BUCKET:
            return await self._token_bucket.consume(1)
        
        elif self.config.budget_type == RetryBudgetType.SLIDING_WINDOW:
            return await self._check_sliding_window()
        
        elif self.config.budget_type == RetryBudgetType.FIXED_WINDOW:
            return await self._check_fixed_window()
        
        return True  # Default allow
    
    async def _check_sliding_window(self) -> bool:
        """Check sliding window budget."""
        async with self._lock:
            now = time.time()
            
            # Clean old entries
            while self._sliding_window and now - self._sliding_window[0] > 60:
                self._sliding_window.popleft()
            
            while self._hourly_window and now - self._hourly_window[0] > 3600:
                self._hourly_window.popleft()
            
            # Check limits
            if len(self._sliding_window) >= self.config.max_retries_per_minute:
                return False
            
            if len(self._hourly_window) >= self.config.max_retries_per_hour:
                return False
            
            # Record retry
            self._sliding_window.append(now)
            self._hourly_window.append(now)
            return True
    
    async def _check_fixed_window(self) -> bool:
        """Check fixed window budget."""
        # Simplified implementation
        return await self._check_sliding_window()


class DefaultIdempotencyProvider:
    """Default implementation of idempotency provider."""
    
    def __init__(self):
        """Initialize with in-memory cache."""
        self._cache: Dict[str, tuple] = {}  # key -> (result, timestamp)
        self._lock = asyncio.Lock()
    
    def generate_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate idempotency key."""
        # Create a stable hash of function name and parameters
        content = {
            'function': func_name,
            'args': str(args),
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.md5(content_str.encode()).hexdigest()
    
    async def check_previous_result(self, key: str) -> Optional[Any]:
        """Check for cached result."""
        async with self._lock:
            if key in self._cache:
                result, timestamp = self._cache[key]
                # Check if not expired (default 1 hour)
                if time.time() - timestamp < 3600:
                    return result
                else:
                    del self._cache[key]
            return None
    
    async def store_result(self, key: str, result: Any, ttl: int = 3600) -> None:
        """Store result in cache."""
        async with self._lock:
            self._cache[key] = (result, time.time())


class RedisIdempotencyProvider:
    """Redis-based idempotency provider."""
    
    def __init__(self, redis_client):
        """Initialize with Redis client."""
        self.redis = redis_client
    
    def generate_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate idempotency key."""
        content = {
            'function': func_name,
            'args': str(args),
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        
        content_str = json.dumps(content, sort_keys=True)
        hash_key = hashlib.md5(content_str.encode()).hexdigest()
        return f"idempotency:{hash_key}"
    
    async def check_previous_result(self, key: str) -> Optional[Any]:
        """Check Redis for cached result."""
        try:
            result_data = await self.redis.get(key)
            if result_data:
                return json.loads(result_data)
        except Exception as e:
            logger.warning(f"Failed to check idempotency key {key}: {e}")
        return None
    
    async def store_result(self, key: str, result: Any, ttl: int = 3600) -> None:
        """Store result in Redis."""
        try:
            result_data = json.dumps(result, default=str)
            await self.redis.setex(key, ttl, result_data)
        except Exception as e:
            logger.warning(f"Failed to store idempotency result for {key}: {e}")


class RetryDelayCalculator:
    """Calculate retry delays with various strategies."""
    
    @staticmethod
    def calculate_delay(
        attempt: int,
        config: RetryPolicyConfig,
        previous_delay: Optional[float] = None
    ) -> float:
        """Calculate delay for given attempt."""
        if config.strategy == RetryStrategy.FIXED:
            delay = config.base_delay
        
        elif config.strategy == RetryStrategy.LINEAR:
            delay = config.base_delay * attempt
        
        elif config.strategy == RetryStrategy.EXPONENTIAL:
            delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
        
        elif config.strategy == RetryStrategy.EXPONENTIAL_JITTER:
            base_delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
            jitter = base_delay * config.jitter_factor * random.random()
            delay = base_delay + jitter
        
        elif config.strategy == RetryStrategy.FIBONACCI:
            delay = RetryDelayCalculator._fibonacci_delay(attempt, config.base_delay)
        
        elif config.strategy == RetryStrategy.DECORRELATED_JITTER:
            if previous_delay is None:
                previous_delay = config.base_delay
            delay = random.uniform(config.base_delay, previous_delay * 3)
        
        elif config.strategy == RetryStrategy.CONSTANT_JITTER:
            jitter = config.base_delay * config.jitter_factor * random.random()
            delay = config.base_delay + jitter
        
        elif config.strategy == RetryStrategy.ADAPTIVE:
            delay = RetryDelayCalculator._adaptive_delay(attempt, config)
        
        else:
            delay = config.base_delay
        
        # Apply max delay limit
        return min(delay, config.max_delay)
    
    @staticmethod
    def _fibonacci_delay(attempt: int, base_delay: float) -> float:
        """Calculate Fibonacci-based delay."""
        def fib(n):
            if n <= 1:
                return n
            a, b = 0, 1
            for _ in range(2, n + 1):
                a, b = b, a + b
            return b
        
        return base_delay * fib(attempt)
    
    @staticmethod
    def _adaptive_delay(attempt: int, config: RetryPolicyConfig) -> float:
        """Calculate adaptive delay based on system load."""
        # Simple adaptive strategy - can be enhanced with system metrics
        base_delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
        
        # Add system load factor (simplified)
        load_factor = 1.0  # Could be based on CPU, memory, etc.
        
        return base_delay * load_factor


class RetryPolicyManager:
    """Manager for service-specific retry policies."""
    
    def __init__(self):
        """Initialize policy manager."""
        self._policies: Dict[str, RetryPolicyConfig] = {}
        self._default_policies: Dict[ServiceType, RetryPolicyConfig] = {}
        self._lock = asyncio.Lock()
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default policies for different service types."""
        # AI Service policies
        ai_policy = RetryPolicyConfig(
            max_attempts=5,
            base_delay=2.0,
            max_delay=60.0,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            retryable_status_codes={408, 429, 500, 502, 503, 504},
            enable_circuit_breaker=True,
            enable_retry_budget=True
        )
        
        self._default_policies[ServiceType.AI_CLAUDE] = ai_policy
        self._default_policies[ServiceType.AI_OPENAI] = ai_policy
        self._default_policies[ServiceType.AI_GOOGLE] = ai_policy
        
        # Database policy
        self._default_policies[ServiceType.DATABASE] = RetryPolicyConfig(
            max_attempts=3,
            base_delay=0.5,
            max_delay=5.0,
            strategy=RetryStrategy.LINEAR,
            enable_circuit_breaker=True,
            enable_retry_budget=True
        )
        
        # Cache policy
        self._default_policies[ServiceType.CACHE] = RetryPolicyConfig(
            max_attempts=2,
            base_delay=0.1,
            max_delay=1.0,
            strategy=RetryStrategy.FIXED,
            enable_circuit_breaker=False,
            enable_retry_budget=True
        )
        
        # HTTP API policy
        self._default_policies[ServiceType.HTTP_API] = RetryPolicyConfig(
            max_attempts=4,
            base_delay=1.0,
            max_delay=30.0,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            retryable_status_codes={408, 429, 500, 502, 503, 504},
            enable_circuit_breaker=True,
            enable_retry_budget=True
        )
    
    async def get_policy(
        self, 
        service_name: str, 
        service_type: ServiceType = ServiceType.UNKNOWN
    ) -> RetryPolicyConfig:
        """Get retry policy for service."""
        async with self._lock:
            if service_name in self._policies:
                return self._policies[service_name]
            
            if service_type in self._default_policies:
                policy = self._default_policies[service_type]
                policy.service_name = service_name
                policy.service_type = service_type
                return policy
            
            # Return basic default policy
            return RetryPolicyConfig(service_name=service_name, service_type=service_type)
    
    async def register_policy(self, service_name: str, policy: RetryPolicyConfig):
        """Register custom policy for service."""
        async with self._lock:
            self._policies[service_name] = policy
            logger.info(f"Registered retry policy for service: {service_name}")


class ComprehensiveRetryHandler:
    """Comprehensive retry handler with all advanced features."""
    
    def __init__(self, config: RetryPolicyConfig):
        """Initialize retry handler."""
        self.config = config
        self.metrics = RetryMetrics()
        self._circuit_breaker: Optional[CircuitBreaker] = None
        self._retry_budget: Optional[RetryBudget] = None
        self._idempotency_provider: Optional[IdempotencyProvider] = None
        self._active_retries = 0
        self._lock = asyncio.Lock()
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize retry components."""
        # Initialize circuit breaker
        if self.config.enable_circuit_breaker and CIRCUIT_BREAKER_AVAILABLE:
            self._circuit_breaker = get_circuit_breaker(
                self.config.service_name,
                self.config.circuit_breaker_config
            )
        
        # Initialize retry budget
        if self.config.enable_retry_budget:
            self._retry_budget = RetryBudget(self.config.retry_budget_config)
        
        # Initialize idempotency provider
        if self.config.enable_idempotency:
            if self.config.idempotency_provider:
                self._idempotency_provider = self.config.idempotency_provider
            else:
                self._idempotency_provider = DefaultIdempotencyProvider()
    
    async def execute(
        self,
        func: Callable[..., T],
        *args,
        **kwargs
    ) -> T:
        """Execute function with comprehensive retry logic."""
        # Check rate limiting
        if self.config.enable_rate_limiting:
            async with self._lock:
                if self._active_retries >= self.config.max_concurrent_retries:
                    self.metrics.budget_rejections += 1
                    raise Exception(f"Too many concurrent retries for {self.config.service_name}")
                self._active_retries += 1
        
        try:
            return await self._execute_with_retry(func, *args, **kwargs)
        finally:
            if self.config.enable_rate_limiting:
                async with self._lock:
                    self._active_retries -= 1
    
    async def _execute_with_retry(
        self,
        func: Callable[..., T],
        *args,
        **kwargs
    ) -> T:
        """Internal retry execution logic."""
        # Generate idempotency key
        idempotency_key = None
        if self._idempotency_provider:
            idempotency_key = self._idempotency_provider.generate_key(
                func.__name__, args, kwargs
            )
            
            # Check for previous result
            previous_result = await self._idempotency_provider.check_previous_result(
                idempotency_key
            )
            if previous_result is not None:
                self.metrics.idempotency_hits += 1
                logger.debug(f"Idempotency hit for {func.__name__}")
                return previous_result
        
        start_time = time.time()
        last_exception = None
        previous_delay = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > self.config.timeout:
                self.metrics.abandoned_retries += 1
                raise TimeoutError(f"Retry timeout exceeded after {elapsed:.2f}s")
            
            # Check retry budget
            if self._retry_budget and attempt > 1:
                if not await self._retry_budget.can_retry():
                    self.metrics.budget_rejections += 1
                    logger.warning(f"Retry budget exhausted for {func.__name__}")
                    if last_exception:
                        raise last_exception
                    raise Exception("Retry budget exhausted")
            
            try:
                # Execute with circuit breaker if available
                if self._circuit_breaker:
                    result = await self._circuit_breaker.call(func, *args, **kwargs)
                else:
                    result = await self._execute_function(func, *args, **kwargs)
                
                # Store result for idempotency
                if self._idempotency_provider and idempotency_key:
                    await self._idempotency_provider.store_result(idempotency_key, result)
                
                # Record success metrics
                self.metrics.total_attempts += 1
                if attempt > 1:
                    self.metrics.successful_retries += 1
                self.metrics.success_by_attempt[attempt] = (
                    self.metrics.success_by_attempt.get(attempt, 0) + 1
                )
                
                return result
                
            except Exception as e:
                last_exception = e
                self.metrics.total_attempts += 1
                self.metrics.failure_by_attempt[attempt] = (
                    self.metrics.failure_by_attempt.get(attempt, 0) + 1
                )
                
                # Track failure reason
                error_type = type(e).__name__
                self.metrics.retry_reasons[error_type] = (
                    self.metrics.retry_reasons.get(error_type, 0) + 1
                )
                
                # Check if exception is retryable
                if not self._is_retryable_exception(e):
                    logger.error(f"Non-retryable exception in {func.__name__}: {e}")
                    self.metrics.failed_retries += 1
                    raise
                
                # Check if this was the last attempt
                if attempt >= self.config.max_attempts:
                    self.metrics.failed_retries += 1
                    logger.error(
                        f"Max retries ({self.config.max_attempts}) exceeded for {func.__name__}: {e}"
                    )
                    raise
                
                # Calculate and apply delay
                delay = RetryDelayCalculator.calculate_delay(
                    attempt, self.config, previous_delay
                )
                previous_delay = delay
                
                self.metrics.total_wait_time += delay
                self.metrics.average_wait_time = (
                    self.metrics.total_wait_time / max(1, self.metrics.total_attempts - 1)
                )
                self.metrics.max_wait_time = max(self.metrics.max_wait_time, delay)
                self.metrics.last_retry_time = datetime.now()
                
                if self.config.log_retries:
                    getattr(logger, self.config.log_level.lower())(
                        f"Retry attempt {attempt}/{self.config.max_attempts} for {func.__name__}: {e}, "
                        f"waiting {delay:.2f}s before retry"
                    )
                
                await asyncio.sleep(delay)
        
        # Should not reach here
        if last_exception:
            raise last_exception
        raise Exception(f"Unexpected retry loop exit in {func.__name__}")
    
    async def _execute_function(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function (async or sync)."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args, **kwargs)
    
    def _is_retryable_exception(self, exc: Exception) -> bool:
        """Check if exception is retryable."""
        # Check non-retryable exceptions first
        for non_retryable in self.config.non_retryable_exceptions:
            if isinstance(exc, non_retryable):
                return False
        
        # Check retryable exceptions
        for retryable in self.config.retryable_exceptions:
            if isinstance(exc, retryable):
                return True
        
        # Check HTTP status codes
        if hasattr(exc, 'status') or hasattr(exc, 'status_code'):
            status = getattr(exc, 'status', None) or getattr(exc, 'status_code', None)
            if status and status in self.config.retryable_status_codes:
                return True
        
        return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get retry metrics."""
        return {
            "service_name": self.config.service_name,
            "service_type": self.config.service_type.value,
            "config": {
                "max_attempts": self.config.max_attempts,
                "strategy": self.config.strategy.value,
                "base_delay": self.config.base_delay,
                "max_delay": self.config.max_delay,
            },
            "metrics": self.metrics.to_dict(),
            "circuit_breaker_metrics": (
                self._circuit_breaker.get_metrics() if self._circuit_breaker else None
            )
        }


# Global instances
_policy_manager = RetryPolicyManager()
_retry_handlers: Dict[str, ComprehensiveRetryHandler] = {}
_handlers_lock = asyncio.Lock()


async def get_retry_handler(
    service_name: str,
    service_type: ServiceType = ServiceType.UNKNOWN,
    custom_config: Optional[RetryPolicyConfig] = None
) -> ComprehensiveRetryHandler:
    """Get or create retry handler for service."""
    async with _handlers_lock:
        if service_name not in _retry_handlers:
            if custom_config:
                config = custom_config
            else:
                config = await _policy_manager.get_policy(service_name, service_type)
            
            _retry_handlers[service_name] = ComprehensiveRetryHandler(config)
            logger.info(f"Created retry handler for service: {service_name}")
        
        return _retry_handlers[service_name]


def comprehensive_retry(
    service_name: str,
    service_type: ServiceType = ServiceType.UNKNOWN,
    custom_config: Optional[RetryPolicyConfig] = None
) -> Callable[[F], F]:
    """
    Decorator for comprehensive retry functionality.
    
    Args:
        service_name: Name of the service
        service_type: Type of service for default policy
        custom_config: Custom retry configuration
    
    Example:
        ```python
        @comprehensive_retry("openai_api", ServiceType.AI_OPENAI)
        async def call_openai():
            return await openai_client.chat.completions.create(...)
        ```
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            handler = await get_retry_handler(service_name, service_type, custom_config)
            return await handler.execute(func, *args, **kwargs)
        
        # Attach handler for inspection
        wrapper._retry_handler = None  # Will be set on first call
        wrapper._service_name = service_name
        wrapper._service_type = service_type
        
        return wrapper
    
    return decorator


# Convenience decorators for specific service types
def retry_ai_service(
    service_name: str,
    max_attempts: int = 5,
    base_delay: float = 2.0
) -> Callable[[F], F]:
    """Retry decorator for AI services."""
    config = RetryPolicyConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        service_type=ServiceType.AI_CLAUDE,
        service_name=service_name
    )
    return comprehensive_retry(service_name, ServiceType.AI_CLAUDE, config)


def retry_database(
    service_name: str,
    max_attempts: int = 3,
    base_delay: float = 0.5
) -> Callable[[F], F]:
    """Retry decorator for database operations."""
    config = RetryPolicyConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        strategy=RetryStrategy.LINEAR,
        service_type=ServiceType.DATABASE,
        service_name=service_name
    )
    return comprehensive_retry(service_name, ServiceType.DATABASE, config)


def retry_api_call(
    service_name: str,
    max_attempts: int = 4,
    base_delay: float = 1.0
) -> Callable[[F], F]:
    """Retry decorator for HTTP API calls."""
    config = RetryPolicyConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        service_type=ServiceType.HTTP_API,
        service_name=service_name
    )
    return comprehensive_retry(service_name, ServiceType.HTTP_API, config)


async def get_all_retry_metrics() -> Dict[str, Any]:
    """Get metrics for all retry handlers."""
    metrics = {}
    async with _handlers_lock:
        for name, handler in _retry_handlers.items():
            metrics[name] = handler.get_metrics()
    
    return {
        "handlers": metrics,
        "summary": {
            "total_handlers": len(_retry_handlers),
            "total_attempts": sum(
                h.metrics.total_attempts for h in _retry_handlers.values()
            ),
            "total_successes": sum(
                h.metrics.successful_retries for h in _retry_handlers.values()
            ),
            "total_failures": sum(
                h.metrics.failed_retries for h in _retry_handlers.values()
            )
        }
    }


async def export_retry_metrics(filepath: str):
    """Export retry metrics to JSON file."""
    metrics = await get_all_retry_metrics()
    metrics["timestamp"] = datetime.now().isoformat()
    
    with open(filepath, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    logger.info(f"Exported retry metrics to {filepath}")


# Export public API
__all__ = [
    'RetryStrategy',
    'ServiceType',
    'RetryBudgetType',
    'RetryPolicyConfig',
    'RetryBudgetConfig',
    'RetryMetrics',
    'ComprehensiveRetryHandler',
    'RetryPolicyManager',
    'IdempotencyProvider',
    'DefaultIdempotencyProvider',
    'RedisIdempotencyProvider',
    'comprehensive_retry',
    'retry_ai_service',
    'retry_database',
    'retry_api_call',
    'get_retry_handler',
    'get_all_retry_metrics',
    'export_retry_metrics',
]