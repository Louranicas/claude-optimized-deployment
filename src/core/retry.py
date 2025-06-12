"""
Comprehensive retry utilities for network operations.

This module provides production-grade retry logic with exponential backoff,
circuit breaker pattern, and configurable strategies for different error types.
"""

import asyncio
import functools
import logging
import os
import random
import time
import gc
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from weakref import WeakValueDictionary

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential,
    wait_random_exponential,
    retry_if_exception_type,
    retry_if_result,
    before_sleep_log,
    after_log,
    RetryError
)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Type variables
T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# Environment variable configuration
DEFAULT_MAX_RETRIES = int(os.getenv('RETRY_MAX_ATTEMPTS', '3'))
DEFAULT_MIN_WAIT = float(os.getenv('RETRY_MIN_WAIT_SECONDS', '1'))
DEFAULT_MAX_WAIT = float(os.getenv('RETRY_MAX_WAIT_SECONDS', '60'))
DEFAULT_TIMEOUT = float(os.getenv('RETRY_TIMEOUT_SECONDS', '300'))
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', '5'))
CIRCUIT_BREAKER_TIMEOUT = int(os.getenv('CIRCUIT_BREAKER_TIMEOUT_SECONDS', '60'))


class RetryStrategy(Enum):
    """Enum for different retry strategies."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    RANDOM_EXPONENTIAL = "random_exponential"
    FIXED = "fixed"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = DEFAULT_MAX_RETRIES
    min_wait_seconds: float = DEFAULT_MIN_WAIT
    max_wait_seconds: float = DEFAULT_MAX_WAIT
    timeout_seconds: float = DEFAULT_TIMEOUT
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True
    retryable_exceptions: Optional[Set[Type[Exception]]] = None
    non_retryable_exceptions: Optional[Set[Type[Exception]]] = None
    retryable_status_codes: Optional[Set[int]] = None
    log_retries: bool = True
    memory_limit_mb: float = 100.0  # Memory limit per retry operation
    cleanup_between_retries: bool = True
    max_payload_size_mb: float = 50.0  # Maximum payload size in MB

    def __post_init__(self):
        """Set default retryable exceptions and status codes."""
        if self.retryable_exceptions is None:
            self.retryable_exceptions = {
                ConnectionError,
                TimeoutError,
                asyncio.TimeoutError,
                httpx.NetworkError,
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.RemoteProtocolError,
                OSError,
                IOError,
            }
        
        if self.non_retryable_exceptions is None:
            self.non_retryable_exceptions = {
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                ImportError,
                SyntaxError,
            }
        
        if self.retryable_status_codes is None:
            self.retryable_status_codes = {
                408,  # Request Timeout
                429,  # Too Many Requests
                500,  # Internal Server Error
                502,  # Bad Gateway
                503,  # Service Unavailable
                504,  # Gateway Timeout
            }
        
        # State tracking for memory management
        self._retry_state_cache: WeakValueDictionary = WeakValueDictionary()
        self._payload_cache: Dict[str, Any] = {}


class CircuitBreaker:
    """
    Circuit breaker implementation to prevent cascading failures.
    
    The circuit breaker has three states:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failure threshold exceeded, requests fail immediately
    - HALF_OPEN: Testing if the service has recovered
    """
    
    def __init__(
        self,
        failure_threshold: int = CIRCUIT_BREAKER_THRESHOLD,
        recovery_timeout: int = CIRCUIT_BREAKER_TIMEOUT,
        expected_exception: Type[Exception] = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = "CLOSED"
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            if self.state == "OPEN":
                if self._should_attempt_reset():
                    self.state = "HALF_OPEN"
                else:
                    raise Exception(f"Circuit breaker is OPEN for {func.__name__}")
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            async with self._lock:
                self._on_success()
            return result
        except self.expected_exception as e:
            async with self._lock:
                self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return False
        return datetime.now() - self.last_failure_time >= timedelta(seconds=self.recovery_timeout)
    
    def _on_success(self):
        """Handle successful call."""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")


def is_retryable_exception(exc: Exception, config: RetryConfig) -> bool:
    """Determine if an exception is retryable based on configuration."""
    # Check non-retryable exceptions first
    if config.non_retryable_exceptions:
        for non_retryable in config.non_retryable_exceptions:
            if isinstance(exc, non_retryable):
                return False
    
    # Check retryable exceptions
    if config.retryable_exceptions:
        for retryable in config.retryable_exceptions:
            if isinstance(exc, retryable):
                return True
    
    # Check HTTP status codes for HTTP-related exceptions
    if hasattr(exc, 'status') or hasattr(exc, 'status_code'):
        status = getattr(exc, 'status', None) or getattr(exc, 'status_code', None)
        if status and config.retryable_status_codes:
            return status in config.retryable_status_codes
    
    return False


def is_retryable_response(response: Any, config: RetryConfig) -> bool:
    """Determine if a response should trigger a retry."""
    if hasattr(response, 'status') or hasattr(response, 'status_code'):
        status = getattr(response, 'status', None) or getattr(response, 'status_code', None)
        if status and config.retryable_status_codes:
            return status in config.retryable_status_codes
    return False


def check_memory_pressure() -> bool:
    """Check if system is under memory pressure."""
    if not PSUTIL_AVAILABLE:
        return False
    
    try:
        memory = psutil.virtual_memory()
        return memory.percent > 85  # 85% threshold
    except Exception:
        return False


def get_current_memory_mb() -> float:
    """Get current memory usage in MB."""
    if not PSUTIL_AVAILABLE:
        return 0.0
    
    try:
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except Exception:
        return 0.0


def cleanup_retry_state(func_name: str, attempt: int) -> None:
    """Clean up state between retry attempts."""
    try:
        # Force garbage collection
        gc.collect()
        
        # Clear any cached data for this function/attempt
        cache_key = f"{func_name}_{attempt}"
        
        # Log memory usage if available
        if PSUTIL_AVAILABLE:
            memory_mb = get_current_memory_mb()
            logger.debug(f"Memory usage after cleanup for {func_name}: {memory_mb:.1f}MB")
        
    except Exception as e:
        logger.debug(f"State cleanup failed for {func_name}: {e}")


def check_payload_size(payload: Any, max_size_mb: float) -> bool:
    """Check if payload size exceeds limit."""
    try:
        payload_size = sys.getsizeof(payload) / 1024 / 1024  # Convert to MB
        if payload_size > max_size_mb:
            logger.warning(f"Payload size {payload_size:.2f}MB exceeds limit {max_size_mb}MB")
            return False
        return True
    except Exception:
        return True  # If we can't measure, allow it


def get_wait_time(attempt: int, config: RetryConfig) -> float:
    """Calculate wait time based on retry strategy."""
    if config.strategy == RetryStrategy.EXPONENTIAL:
        wait_time = min(config.min_wait_seconds * (2 ** (attempt - 1)), config.max_wait_seconds)
    elif config.strategy == RetryStrategy.LINEAR:
        wait_time = min(config.min_wait_seconds * attempt, config.max_wait_seconds)
    elif config.strategy == RetryStrategy.FIXED:
        wait_time = config.min_wait_seconds
    else:  # RANDOM_EXPONENTIAL
        base_wait = config.min_wait_seconds * (2 ** (attempt - 1))
        wait_time = min(base_wait, config.max_wait_seconds)
    
    if config.jitter:
        # Add random jitter to prevent thundering herd
        jitter = random.uniform(0, wait_time * 0.1)
        wait_time += jitter
    
    return wait_time


def retry_async(config: Optional[RetryConfig] = None) -> Callable[[F], F]:
    """
    Async retry decorator with configurable retry logic.
    
    Args:
        config: RetryConfig instance with retry configuration
    
    Returns:
        Decorated function with retry logic
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            start_time = time.time()
            initial_memory = get_current_memory_mb()
            
            for attempt in range(1, config.max_attempts + 1):
                try:
                    # Check timeout
                    elapsed = time.time() - start_time
                    if elapsed > config.timeout_seconds:
                        raise TimeoutError(f"Retry timeout exceeded after {elapsed:.2f} seconds")
                    
                    # Check memory pressure before retry
                    if check_memory_pressure():
                        logger.warning(f"Skipping retry {attempt} for {func.__name__} due to memory pressure")
                        raise Exception("Retry skipped due to memory pressure")
                    
                    # Check payload size if we can estimate it
                    if args and not check_payload_size(args, config.max_payload_size_mb):
                        raise ValueError(f"Payload size exceeds limit for {func.__name__}")
                    
                    # Log attempt if configured
                    if config.log_retries and attempt > 1:
                        logger.info(f"Retry attempt {attempt}/{config.max_attempts} for {func.__name__}")
                    
                    # Execute function
                    result = await func(*args, **kwargs)
                    
                    # Check if response should trigger retry
                    if is_retryable_response(result, config):
                        if attempt < config.max_attempts:
                            # Clean up before retry
                            if config.cleanup_between_retries:
                                cleanup_retry_state(func.__name__, attempt)
                            
                            wait_time = get_wait_time(attempt, config)
                            logger.warning(
                                f"Retryable response from {func.__name__}, "
                                f"waiting {wait_time:.2f}s before retry"
                            )
                            await asyncio.sleep(wait_time)
                            continue
                    
                    # Check memory usage after successful execution
                    final_memory = get_current_memory_mb()
                    memory_used = final_memory - initial_memory
                    if memory_used > config.memory_limit_mb:
                        logger.warning(f"Function {func.__name__} used {memory_used:.1f}MB (limit: {config.memory_limit_mb}MB)")
                    
                    return result
                    
                except Exception as e:
                    last_exception = e
                    
                    # Check if exception is retryable
                    if not is_retryable_exception(e, config):
                        logger.error(f"Non-retryable exception in {func.__name__}: {e}")
                        raise
                    
                    # Check if we have more attempts
                    if attempt < config.max_attempts:
                        # Clean up state before retry
                        if config.cleanup_between_retries:
                            cleanup_retry_state(func.__name__, attempt)
                        
                        wait_time = get_wait_time(attempt, config)
                        logger.warning(
                            f"Retryable exception in {func.__name__}: {e}, "
                            f"waiting {wait_time:.2f}s before retry"
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            f"Max retries ({config.max_attempts}) exceeded for {func.__name__}: {e}"
                        )
                        raise
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
            raise Exception(f"Unexpected retry loop exit in {func.__name__}")
        
        return async_wrapper
    
    return decorator


def retry_sync(config: Optional[RetryConfig] = None) -> Callable[[F], F]:
    """
    Synchronous retry decorator with configurable retry logic.
    
    Args:
        config: RetryConfig instance with retry configuration
    
    Returns:
        Decorated function with retry logic
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            start_time = time.time()
            initial_memory = get_current_memory_mb()
            
            for attempt in range(1, config.max_attempts + 1):
                try:
                    # Check timeout
                    elapsed = time.time() - start_time
                    if elapsed > config.timeout_seconds:
                        raise TimeoutError(f"Retry timeout exceeded after {elapsed:.2f} seconds")
                    
                    # Check memory pressure before retry
                    if check_memory_pressure():
                        logger.warning(f"Skipping retry {attempt} for {func.__name__} due to memory pressure")
                        raise Exception("Retry skipped due to memory pressure")
                    
                    # Check payload size if we can estimate it
                    if args and not check_payload_size(args, config.max_payload_size_mb):
                        raise ValueError(f"Payload size exceeds limit for {func.__name__}")
                    
                    # Log attempt if configured
                    if config.log_retries and attempt > 1:
                        logger.info(f"Retry attempt {attempt}/{config.max_attempts} for {func.__name__}")
                    
                    # Execute function
                    result = func(*args, **kwargs)
                    
                    # Check if response should trigger retry
                    if is_retryable_response(result, config):
                        if attempt < config.max_attempts:
                            # Clean up before retry
                            if config.cleanup_between_retries:
                                cleanup_retry_state(func.__name__, attempt)
                            
                            wait_time = get_wait_time(attempt, config)
                            logger.warning(
                                f"Retryable response from {func.__name__}, "
                                f"waiting {wait_time:.2f}s before retry"
                            )
                            time.sleep(wait_time)
                            continue
                    
                    # Check memory usage after successful execution
                    final_memory = get_current_memory_mb()
                    memory_used = final_memory - initial_memory
                    if memory_used > config.memory_limit_mb:
                        logger.warning(f"Function {func.__name__} used {memory_used:.1f}MB (limit: {config.memory_limit_mb}MB)")
                    
                    return result
                    
                except Exception as e:
                    last_exception = e
                    
                    # Check if exception is retryable
                    if not is_retryable_exception(e, config):
                        logger.error(f"Non-retryable exception in {func.__name__}: {e}")
                        raise
                    
                    # Check if we have more attempts
                    if attempt < config.max_attempts:
                        # Clean up state before retry
                        if config.cleanup_between_retries:
                            cleanup_retry_state(func.__name__, attempt)
                        
                        wait_time = get_wait_time(attempt, config)
                        logger.warning(
                            f"Retryable exception in {func.__name__}: {e}, "
                            f"waiting {wait_time:.2f}s before retry"
                        )
                        time.sleep(wait_time)
                    else:
                        logger.error(
                            f"Max retries ({config.max_attempts}) exceeded for {func.__name__}: {e}"
                        )
                        raise
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
            raise Exception(f"Unexpected retry loop exit in {func.__name__}")
        
        return sync_wrapper
    
    return decorator


# Convenience decorators with preset configurations
def retry_network(max_attempts: int = 3, timeout: float = 60) -> Callable[[F], F]:
    """Retry decorator specifically for network operations."""
    config = RetryConfig(
        max_attempts=max_attempts,
        timeout_seconds=timeout,
        strategy=RetryStrategy.EXPONENTIAL,
        min_wait_seconds=1,
        max_wait_seconds=30,
    )
    return retry_async(config)


def retry_api_call(max_attempts: int = 5, timeout: float = 120) -> Callable[[F], F]:
    """Retry decorator specifically for API calls with rate limiting."""
    config = RetryConfig(
        max_attempts=max_attempts,
        timeout_seconds=timeout,
        strategy=RetryStrategy.RANDOM_EXPONENTIAL,
        min_wait_seconds=2,
        max_wait_seconds=60,
        retryable_status_codes={408, 429, 500, 502, 503, 504},
    )
    return retry_async(config)


def retry_database(max_attempts: int = 3, timeout: float = 30) -> Callable[[F], F]:
    """Retry decorator specifically for database operations."""
    config = RetryConfig(
        max_attempts=max_attempts,
        timeout_seconds=timeout,
        strategy=RetryStrategy.LINEAR,
        min_wait_seconds=0.5,
        max_wait_seconds=5,
        retryable_exceptions={
            ConnectionError,
            TimeoutError,
            OSError,
        },
    )
    return retry_async(config)


# Export public API
__all__ = [
    'RetryConfig',
    'RetryStrategy',
    'CircuitBreaker',
    'retry_async',
    'retry_sync',
    'retry_network',
    'retry_api_call',
    'retry_database',
    'is_retryable_exception',
    'is_retryable_response',
    'check_memory_pressure',
    'cleanup_retry_state',
    'check_payload_size',
]