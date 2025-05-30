"""
Retry mechanism for robust operations.

Provides decorators and utilities for retrying failed operations.
"""

from __future__ import annotations
import asyncio
import functools
import logging
from typing import TypeVar, Callable, Optional, Union, Type, Tuple
from dataclasses import dataclass
import random

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class RetryPolicy:
    """
    Configuration for retry behavior.
    
    Attributes:
        max_attempts: Maximum number of retry attempts
        backoff_factor: Multiplier for exponential backoff
        max_delay: Maximum delay between retries (seconds)
        jitter: Whether to add random jitter to delays
        exceptions: Tuple of exceptions to retry on
    """
    max_attempts: int = 3
    backoff_factor: float = 2.0
    max_delay: float = 60.0
    jitter: bool = True
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for a given attempt number.
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        delay = min(self.backoff_factor ** attempt, self.max_delay)
        
        if self.jitter:
            # Add up to 25% jitter
            jitter_amount = delay * 0.25 * random.random()
            delay = delay + jitter_amount
        
        return delay


def with_retry(policy: Optional[RetryPolicy] = None) -> Callable:
    """
    Decorator for adding retry logic to async functions.
    
    Args:
        policy: Retry policy to use (defaults to standard policy)
        
    Returns:
        Decorated function with retry logic
    """
    if policy is None:
        policy = RetryPolicy()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(policy.max_attempts):
                try:
                    return await func(*args, **kwargs)
                    
                except policy.exceptions as e:
                    last_exception = e
                    
                    if attempt < policy.max_attempts - 1:
                        delay = policy.calculate_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1}/{policy.max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"All {policy.max_attempts} attempts failed for {func.__name__}: {e}"
                        )
            
            # If we get here, all attempts failed
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError(f"All retry attempts failed for {func.__name__}")
        
        return wrapper
    
    return decorator


def with_retry_sync(policy: Optional[RetryPolicy] = None) -> Callable:
    """
    Decorator for adding retry logic to synchronous functions.
    
    Args:
        policy: Retry policy to use (defaults to standard policy)
        
    Returns:
        Decorated function with retry logic
    """
    if policy is None:
        policy = RetryPolicy()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(policy.max_attempts):
                try:
                    return func(*args, **kwargs)
                    
                except policy.exceptions as e:
                    last_exception = e
                    
                    if attempt < policy.max_attempts - 1:
                        delay = policy.calculate_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1}/{policy.max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        import time
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {policy.max_attempts} attempts failed for {func.__name__}: {e}"
                        )
            
            # If we get here, all attempts failed
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError(f"All retry attempts failed for {func.__name__}")
        
        return wrapper
    
    return decorator


class RetryableOperation:
    """
    Context manager for retryable operations.
    
    Example:
        async with RetryableOperation(max_attempts=5) as retry:
            result = await retry.execute(some_async_function, arg1, arg2)
    """
    
    def __init__(self, policy: Optional[RetryPolicy] = None):
        """Initialize with retry policy."""
        self.policy = policy or RetryPolicy()
    
    async def __aenter__(self):
        """Enter context."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        pass
    
    async def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute a function with retry logic.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Result of the function
        """
        wrapped = with_retry(self.policy)(func)
        return await wrapped(*args, **kwargs)
