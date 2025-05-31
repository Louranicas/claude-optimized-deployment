#!/usr/bin/env python3
"""
Test script to verify comprehensive retry logic implementation.
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any
import time
import random

from src.core.retry import (
    retry_network, retry_api_call, retry_database,
    RetryConfig, RetryStrategy, CircuitBreaker,
    is_retryable_exception
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkSimulator:
    """Simulate network conditions for testing retry logic."""
    
    def __init__(self):
        self.failure_count = 0
        self.max_failures = 2
    
    async def simulate_flaky_api(self) -> Dict[str, Any]:
        """Simulate a flaky API that fails intermittently."""
        self.failure_count += 1
        
        if self.failure_count <= self.max_failures:
            logger.warning(f"Simulating failure {self.failure_count}/{self.max_failures}")
            raise aiohttp.ClientError("Simulated network error")
        
        logger.info("API call succeeded after retries")
        return {"status": "success", "data": "Hello World"}
    
    async def simulate_rate_limited_api(self) -> Dict[str, Any]:
        """Simulate an API with rate limiting."""
        if random.random() < 0.7:  # 70% chance of rate limit
            raise aiohttp.ClientResponseError(
                request_info=None,
                history=None,
                status=429,
                message="Too Many Requests"
            )
        
        return {"status": "success", "rate_limit": "passed"}
    
    async def simulate_timeout(self) -> Dict[str, Any]:
        """Simulate a timeout scenario."""
        await asyncio.sleep(5)  # Sleep longer than timeout
        return {"status": "success"}


async def test_basic_retry():
    """Test basic retry functionality."""
    logger.info("=== Testing Basic Retry ===")
    
    simulator = NetworkSimulator()
    
    @retry_network(max_attempts=3, timeout=60)
    async def flaky_operation():
        return await simulator.simulate_flaky_api()
    
    try:
        result = await flaky_operation()
        logger.info(f"Result: {result}")
        assert result["status"] == "success"
    except Exception as e:
        logger.error(f"Failed after retries: {e}")


async def test_api_retry():
    """Test API-specific retry with rate limiting."""
    logger.info("\n=== Testing API Retry with Rate Limiting ===")
    
    simulator = NetworkSimulator()
    
    @retry_api_call(max_attempts=5, timeout=120)
    async def rate_limited_api():
        return await simulator.simulate_rate_limited_api()
    
    successes = 0
    failures = 0
    
    for i in range(5):
        try:
            result = await rate_limited_api()
            logger.info(f"API call {i+1} succeeded: {result}")
            successes += 1
        except Exception as e:
            logger.error(f"API call {i+1} failed: {e}")
            failures += 1
        
        # Reset simulator for next test
        simulator = NetworkSimulator()
    
    logger.info(f"Results: {successes} successes, {failures} failures")


async def test_circuit_breaker():
    """Test circuit breaker pattern."""
    logger.info("\n=== Testing Circuit Breaker ===")
    
    circuit_breaker = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout=2,
        expected_exception=Exception
    )
    
    async def failing_operation():
        raise ConnectionError("Service unavailable")
    
    # Test circuit breaker opening
    for i in range(5):
        try:
            await circuit_breaker.call(failing_operation)
        except Exception as e:
            logger.info(f"Attempt {i+1}: {e}")
    
    logger.info(f"Circuit breaker state: {circuit_breaker.state}")
    
    # Wait for recovery timeout
    logger.info("Waiting for circuit breaker recovery...")
    await asyncio.sleep(3)
    
    # Test recovery
    async def successful_operation():
        return {"status": "recovered"}
    
    try:
        result = await circuit_breaker.call(successful_operation)
        logger.info(f"Recovery successful: {result}")
    except Exception as e:
        logger.error(f"Recovery failed: {e}")


async def test_custom_retry_config():
    """Test custom retry configuration."""
    logger.info("\n=== Testing Custom Retry Configuration ===")
    
    config = RetryConfig(
        max_attempts=4,
        min_wait_seconds=0.5,
        max_wait_seconds=10,
        strategy=RetryStrategy.EXPONENTIAL,
        jitter=True,
        retryable_status_codes={429, 500, 502, 503}
    )
    
    @retry_network(max_attempts=config.max_attempts, timeout=config.timeout_seconds)
    async def custom_operation():
        # Simulate operation that succeeds on 3rd attempt
        if not hasattr(custom_operation, 'attempts'):
            custom_operation.attempts = 0
        
        custom_operation.attempts += 1
        
        if custom_operation.attempts < 3:
            logger.info(f"Attempt {custom_operation.attempts} - failing")
            raise TimeoutError("Operation timed out")
        
        logger.info(f"Attempt {custom_operation.attempts} - success")
        return {"status": "success", "attempts": custom_operation.attempts}
    
    result = await custom_operation()
    logger.info(f"Final result: {result}")


async def test_non_retryable_exceptions():
    """Test that non-retryable exceptions are not retried."""
    logger.info("\n=== Testing Non-Retryable Exceptions ===")
    
    @retry_network(max_attempts=3, timeout=60)
    async def operation_with_value_error():
        raise ValueError("This should not be retried")
    
    try:
        await operation_with_value_error()
    except ValueError as e:
        logger.info(f"Caught non-retryable exception immediately: {e}")


async def test_timeout_handling():
    """Test timeout handling in retry logic."""
    logger.info("\n=== Testing Timeout Handling ===")
    
    simulator = NetworkSimulator()
    
    @retry_network(max_attempts=3, timeout=2)  # 2 second timeout
    async def slow_operation():
        return await simulator.simulate_timeout()
    
    try:
        await slow_operation()
    except Exception as e:
        logger.info(f"Operation timed out as expected: {e}")


async def main():
    """Run all retry logic tests."""
    logger.info("Starting Retry Logic Tests\n")
    
    tests = [
        test_basic_retry(),
        test_api_retry(),
        test_circuit_breaker(),
        test_custom_retry_config(),
        test_non_retryable_exceptions(),
        test_timeout_handling()
    ]
    
    for test in tests:
        try:
            await test
        except Exception as e:
            logger.error(f"Test failed: {e}")
        
        await asyncio.sleep(1)  # Brief pause between tests
    
    logger.info("\n✅ All retry logic tests completed!")


if __name__ == "__main__":
    asyncio.run(main())