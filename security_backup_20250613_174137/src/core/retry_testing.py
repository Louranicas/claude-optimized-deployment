"""
Comprehensive retry testing and validation framework.

This module provides:
- Unit tests for retry patterns
- Integration tests for retry systems
- Load testing for retry budgets
- Failure simulation and chaos testing
- Performance benchmarking
- Configuration validation testing
"""

import asyncio
import logging
import random
import statistics
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock, AsyncMock
import uuid

from src.core.retry_patterns import (
    RetryPolicyConfig, RetryStrategy, ServiceType, ComprehensiveRetryHandler,
    get_retry_handler
)
from src.core.retry_monitoring import get_retry_monitor, RetryEvent

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a retry test."""
    test_name: str
    success: bool
    duration: float
    attempts_made: int
    expected_attempts: Optional[int] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'test_name': self.test_name,
            'success': self.success,
            'duration': self.duration,
            'attempts_made': self.attempts_made,
            'expected_attempts': self.expected_attempts,
            'error_message': self.error_message,
            'metrics': self.metrics
        }


@dataclass
class LoadTestResult:
    """Result of a load test."""
    test_name: str
    total_operations: int
    successful_operations: int
    failed_operations: int
    duration: float
    throughput: float
    avg_response_time: float
    p95_response_time: float
    p99_response_time: float
    error_rate: float
    retry_budget_rejections: int
    circuit_breaker_activations: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'test_name': self.test_name,
            'total_operations': self.total_operations,
            'successful_operations': self.successful_operations,
            'failed_operations': self.failed_operations,
            'duration': self.duration,
            'throughput': self.throughput,
            'avg_response_time': self.avg_response_time,
            'p95_response_time': self.p95_response_time,
            'p99_response_time': self.p99_response_time,
            'error_rate': self.error_rate,
            'retry_budget_rejections': self.retry_budget_rejections,
            'circuit_breaker_activations': self.circuit_breaker_activations
        }


class MockService:
    """Mock service for testing retry behavior."""
    
    def __init__(
        self,
        failure_rate: float = 0.3,
        response_time: float = 0.1,
        response_time_variance: float = 0.05,
        timeout_rate: float = 0.1,
        intermittent_failure_rate: float = 0.05
    ):
        """Initialize mock service."""
        self.failure_rate = failure_rate
        self.response_time = response_time
        self.response_time_variance = response_time_variance
        self.timeout_rate = timeout_rate
        self.intermittent_failure_rate = intermittent_failure_rate
        self.call_count = 0
        self.consecutive_failures = 0
        self.is_down = False
        self.down_until: Optional[datetime] = None
    
    async def call(self, data: Any = None) -> str:
        """Simulate service call."""
        self.call_count += 1
        
        # Check if service is down
        if self.is_down and self.down_until and datetime.now() < self.down_until:
            raise ConnectionError("Service is down")
        elif self.is_down and self.down_until and datetime.now() >= self.down_until:
            self.is_down = False
            self.down_until = None
        
        # Simulate response time
        actual_response_time = max(
            0.01,
            random.normalvariate(self.response_time, self.response_time_variance)
        )
        await asyncio.sleep(actual_response_time)
        
        # Simulate timeout
        if random.random() < self.timeout_rate:
            await asyncio.sleep(10)  # Long delay to simulate timeout
            raise TimeoutError("Request timeout")
        
        # Simulate failure
        if random.random() < self.failure_rate:
            self.consecutive_failures += 1
            
            # Different types of failures
            error_type = random.choice([
                ConnectionError("Connection failed"),
                OSError("Network error"),
                Exception("Service error")
            ])
            raise error_type
        
        self.consecutive_failures = 0
        return f"Success response {self.call_count}"
    
    def make_unavailable(self, duration: timedelta):
        """Make service unavailable for a duration."""
        self.is_down = True
        self.down_until = datetime.now() + duration
    
    def set_failure_rate(self, rate: float):
        """Dynamically set failure rate."""
        self.failure_rate = max(0.0, min(1.0, rate))
    
    def reset(self):
        """Reset service state."""
        self.call_count = 0
        self.consecutive_failures = 0
        self.is_down = False
        self.down_until = None


class RetryTester:
    """Comprehensive retry testing framework."""
    
    def __init__(self):
        """Initialize retry tester."""
        self.test_results: List[TestResult] = []
        self.load_test_results: List[LoadTestResult] = []
        self.mock_services: Dict[str, MockService] = {}
    
    def create_mock_service(
        self,
        name: str,
        failure_rate: float = 0.3,
        response_time: float = 0.1
    ) -> MockService:
        """Create a mock service for testing."""
        service = MockService(failure_rate=failure_rate, response_time=response_time)
        self.mock_services[name] = service
        return service
    
    async def test_basic_retry(
        self,
        config: RetryPolicyConfig,
        mock_service: MockService,
        expected_attempts: int
    ) -> TestResult:
        """Test basic retry functionality."""
        test_name = f"basic_retry_{config.strategy.value}"
        start_time = time.time()
        
        handler = ComprehensiveRetryHandler(config)
        attempts_made = 0
        
        try:
            # Create wrapper to count attempts
            async def counted_call():
                nonlocal attempts_made
                attempts_made += 1
                return await mock_service.call()
            
            result = await handler.execute(counted_call)
            success = True
            error_message = None
            
        except Exception as e:
            success = False
            error_message = str(e)
        
        duration = time.time() - start_time
        
        test_result = TestResult(
            test_name=test_name,
            success=success,
            duration=duration,
            attempts_made=attempts_made,
            expected_attempts=expected_attempts,
            error_message=error_message,
            metrics=handler.get_metrics()
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def test_exponential_backoff(self, config: RetryPolicyConfig) -> TestResult:
        """Test exponential backoff timing."""
        test_name = "exponential_backoff_timing"
        start_time = time.time()
        
        # Create service that always fails
        mock_service = MockService(failure_rate=1.0, response_time=0.01)
        handler = ComprehensiveRetryHandler(config)
        
        attempt_times = []
        
        async def timed_call():
            attempt_times.append(time.time())
            return await mock_service.call()
        
        try:
            await handler.execute(timed_call)
            success = False  # Should have failed
            error_message = "Expected failure but succeeded"
        except Exception:
            success = True  # Expected to fail
            error_message = None
        
        duration = time.time() - start_time
        
        # Analyze timing
        delays = []
        for i in range(1, len(attempt_times)):
            delay = attempt_times[i] - attempt_times[i-1]
            delays.append(delay)
        
        test_result = TestResult(
            test_name=test_name,
            success=success,
            duration=duration,
            attempts_made=len(attempt_times),
            metrics={
                'delays': delays,
                'expected_exponential': True,
                'timing_analysis': delays
            }
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def test_circuit_breaker_integration(self, config: RetryPolicyConfig) -> TestResult:
        """Test circuit breaker integration."""
        test_name = "circuit_breaker_integration"
        start_time = time.time()
        
        # Create service that fails consistently
        mock_service = MockService(failure_rate=1.0, response_time=0.01)
        handler = ComprehensiveRetryHandler(config)
        
        circuit_breaker_triggered = False
        total_attempts = 0
        
        # Make multiple calls to trigger circuit breaker
        for i in range(10):
            try:
                await handler.execute(mock_service.call)
            except Exception as e:
                if "circuit" in str(e).lower() or "open" in str(e).lower():
                    circuit_breaker_triggered = True
                total_attempts += 1
        
        duration = time.time() - start_time
        
        test_result = TestResult(
            test_name=test_name,
            success=circuit_breaker_triggered if config.enable_circuit_breaker else True,
            duration=duration,
            attempts_made=total_attempts,
            metrics={
                'circuit_breaker_triggered': circuit_breaker_triggered,
                'circuit_breaker_enabled': config.enable_circuit_breaker
            }
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def test_retry_budget(self, config: RetryPolicyConfig) -> TestResult:
        """Test retry budget functionality."""
        test_name = "retry_budget"
        start_time = time.time()
        
        mock_service = MockService(failure_rate=0.8, response_time=0.01)
        handler = ComprehensiveRetryHandler(config)
        
        budget_rejections = 0
        total_calls = 0
        
        # Make many rapid calls to exhaust budget
        tasks = []
        for i in range(50):
            async def make_call():
                nonlocal budget_rejections, total_calls
                total_calls += 1
                try:
                    await handler.execute(mock_service.call)
                except Exception as e:
                    if "budget" in str(e).lower():
                        budget_rejections += 1
            
            tasks.append(make_call())
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        duration = time.time() - start_time
        
        test_result = TestResult(
            test_name=test_name,
            success=budget_rejections > 0 if config.enable_retry_budget else True,
            duration=duration,
            attempts_made=total_calls,
            metrics={
                'budget_rejections': budget_rejections,
                'retry_budget_enabled': config.enable_retry_budget,
                'total_calls': total_calls
            }
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def test_idempotency(self, config: RetryPolicyConfig) -> TestResult:
        """Test idempotency functionality."""
        test_name = "idempotency"
        start_time = time.time()
        
        mock_service = MockService(failure_rate=0.0, response_time=0.01)
        handler = ComprehensiveRetryHandler(config)
        
        # Make the same call multiple times
        results = []
        for i in range(3):
            try:
                result = await handler.execute(lambda: mock_service.call("same_data"))
                results.append(result)
            except Exception as e:
                results.append(str(e))
        
        duration = time.time() - start_time
        
        # Check if idempotency worked (should have fewer actual service calls)
        idempotency_working = (
            config.enable_idempotency and 
            mock_service.call_count < len(results)
        )
        
        test_result = TestResult(
            test_name=test_name,
            success=idempotency_working if config.enable_idempotency else True,
            duration=duration,
            attempts_made=len(results),
            metrics={
                'actual_service_calls': mock_service.call_count,
                'expected_calls': len(results),
                'idempotency_enabled': config.enable_idempotency,
                'results': results
            }
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def run_load_test(
        self,
        config: RetryPolicyConfig,
        concurrent_operations: int = 100,
        total_operations: int = 1000,
        failure_rate: float = 0.3
    ) -> LoadTestResult:
        """Run load test on retry system."""
        test_name = f"load_test_{concurrent_operations}x{total_operations}"
        
        mock_service = MockService(
            failure_rate=failure_rate,
            response_time=0.05,
            response_time_variance=0.02
        )
        
        handler = ComprehensiveRetryHandler(config)
        
        results = []
        response_times = []
        start_time = time.time()
        
        semaphore = asyncio.Semaphore(concurrent_operations)
        
        async def single_operation():
            async with semaphore:
                op_start = time.time()
                try:
                    await handler.execute(mock_service.call)
                    success = True
                except Exception:
                    success = False
                
                response_time = time.time() - op_start
                response_times.append(response_time)
                return success
        
        # Run operations
        tasks = [single_operation() for _ in range(total_operations)]
        operation_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        duration = time.time() - start_time
        
        # Calculate metrics
        successful_operations = sum(1 for r in operation_results if r is True)
        failed_operations = total_operations - successful_operations
        throughput = total_operations / duration
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        p99_response_time = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
        error_rate = failed_operations / total_operations
        
        load_result = LoadTestResult(
            test_name=test_name,
            total_operations=total_operations,
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            duration=duration,
            throughput=throughput,
            avg_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_rate=error_rate,
            retry_budget_rejections=0,  # Would need integration with retry budget
            circuit_breaker_activations=0  # Would need integration with circuit breaker
        )
        
        self.load_test_results.append(load_result)
        return load_result
    
    async def run_chaos_test(
        self,
        config: RetryPolicyConfig,
        chaos_duration: timedelta = timedelta(minutes=2)
    ) -> TestResult:
        """Run chaos test with random failures."""
        test_name = "chaos_test"
        start_time = time.time()
        
        mock_service = MockService(failure_rate=0.2, response_time=0.05)
        handler = ComprehensiveRetryHandler(config)
        
        end_time = datetime.now() + chaos_duration
        successful_operations = 0
        failed_operations = 0
        
        while datetime.now() < end_time:
            # Randomly change service behavior
            if random.random() < 0.1:  # 10% chance to change failure rate
                new_failure_rate = random.uniform(0.0, 0.8)
                mock_service.set_failure_rate(new_failure_rate)
            
            if random.random() < 0.05:  # 5% chance to make service unavailable
                outage_duration = timedelta(seconds=random.uniform(1, 10))
                mock_service.make_unavailable(outage_duration)
            
            # Make operation
            try:
                await handler.execute(mock_service.call)
                successful_operations += 1
            except Exception:
                failed_operations += 1
            
            # Small delay between operations
            await asyncio.sleep(0.1)
        
        duration = time.time() - start_time
        total_operations = successful_operations + failed_operations
        
        test_result = TestResult(
            test_name=test_name,
            success=successful_operations > 0,  # Success if any operations succeeded
            duration=duration,
            attempts_made=total_operations,
            metrics={
                'successful_operations': successful_operations,
                'failed_operations': failed_operations,
                'success_rate': successful_operations / total_operations if total_operations > 0 else 0
            }
        )
        
        self.test_results.append(test_result)
        return test_result
    
    async def benchmark_retry_strategies(
        self,
        strategies: List[RetryStrategy],
        base_config: RetryPolicyConfig
    ) -> Dict[RetryStrategy, TestResult]:
        """Benchmark different retry strategies."""
        results = {}
        
        for strategy in strategies:
            config = RetryPolicyConfig(
                max_attempts=base_config.max_attempts,
                base_delay=base_config.base_delay,
                max_delay=base_config.max_delay,
                strategy=strategy,
                service_name=f"benchmark_{strategy.value}",
                enable_circuit_breaker=False,  # Disable to isolate strategy testing
                enable_retry_budget=False
            )
            
            mock_service = MockService(failure_rate=0.5, response_time=0.01)
            handler = ComprehensiveRetryHandler(config)
            
            start_time = time.time()
            attempts = 0
            
            try:
                async def counted_call():
                    nonlocal attempts
                    attempts += 1
                    return await mock_service.call()
                
                await handler.execute(counted_call)
                success = True
                error_message = None
            except Exception as e:
                success = False
                error_message = str(e)
            
            duration = time.time() - start_time
            
            result = TestResult(
                test_name=f"benchmark_{strategy.value}",
                success=success,
                duration=duration,
                attempts_made=attempts,
                metrics={
                    'strategy': strategy.value,
                    'total_time': duration,
                    'avg_time_per_attempt': duration / attempts if attempts > 0 else 0
                }
            )
            
            results[strategy] = result
        
        return results
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result.success)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': total_tests - passed_tests,
                'success_rate': passed_tests / total_tests if total_tests > 0 else 0
            },
            'test_results': [result.to_dict() for result in self.test_results],
            'load_test_results': [result.to_dict() for result in self.load_test_results],
            'performance_summary': {
                'avg_test_duration': statistics.mean(
                    [r.duration for r in self.test_results]
                ) if self.test_results else 0,
                'total_test_time': sum(r.duration for r in self.test_results)
            }
        }
    
    def export_report(self, filepath: str):
        """Export test report to JSON file."""
        import json
        
        report = self.generate_test_report()
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Exported test report to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export test report to {filepath}: {e}")


async def run_comprehensive_test_suite(
    config_variations: Optional[List[RetryPolicyConfig]] = None
) -> Dict[str, Any]:
    """Run comprehensive test suite with multiple configurations."""
    tester = RetryTester()
    
    if config_variations is None:
        config_variations = [
            # Basic exponential backoff
            RetryPolicyConfig(
                max_attempts=3,
                base_delay=1.0,
                strategy=RetryStrategy.EXPONENTIAL,
                service_name="test_exponential"
            ),
            # Exponential with jitter
            RetryPolicyConfig(
                max_attempts=3,
                base_delay=1.0,
                strategy=RetryStrategy.EXPONENTIAL_JITTER,
                service_name="test_exponential_jitter"
            ),
            # Linear backoff
            RetryPolicyConfig(
                max_attempts=3,
                base_delay=0.5,
                strategy=RetryStrategy.LINEAR,
                service_name="test_linear"
            ),
            # Fixed delay
            RetryPolicyConfig(
                max_attempts=3,
                base_delay=1.0,
                strategy=RetryStrategy.FIXED,
                service_name="test_fixed"
            )
        ]
    
    results = {}
    
    for i, config in enumerate(config_variations):
        logger.info(f"Testing configuration {i+1}/{len(config_variations)}: {config.strategy.value}")
        
        # Create mock service for this configuration
        mock_service = tester.create_mock_service(f"service_{i}", failure_rate=0.3)
        
        # Run basic tests
        basic_result = await tester.test_basic_retry(config, mock_service, 3)
        backoff_result = await tester.test_exponential_backoff(config)
        circuit_result = await tester.test_circuit_breaker_integration(config)
        budget_result = await tester.test_retry_budget(config)
        idempotency_result = await tester.test_idempotency(config)
        
        # Run load test
        load_result = await tester.run_load_test(config, concurrent_operations=20, total_operations=100)
        
        results[f"config_{i}_{config.strategy.value}"] = {
            'config': config.__dict__,
            'basic_retry': basic_result.to_dict(),
            'backoff_timing': backoff_result.to_dict(),
            'circuit_breaker': circuit_result.to_dict(),
            'retry_budget': budget_result.to_dict(),
            'idempotency': idempotency_result.to_dict(),
            'load_test': load_result.to_dict()
        }
    
    # Run strategy benchmark
    strategies = [
        RetryStrategy.EXPONENTIAL,
        RetryStrategy.EXPONENTIAL_JITTER,
        RetryStrategy.LINEAR,
        RetryStrategy.FIXED
    ]
    
    base_config = RetryPolicyConfig(max_attempts=3, base_delay=1.0)
    benchmark_results = await tester.benchmark_retry_strategies(strategies, base_config)
    
    results['strategy_benchmark'] = {
        strategy.value: result.to_dict()
        for strategy, result in benchmark_results.items()
    }
    
    # Generate final report
    final_report = tester.generate_test_report()
    final_report['configuration_tests'] = results
    
    return final_report


# Export public API
__all__ = [
    'TestResult',
    'LoadTestResult',
    'MockService',
    'RetryTester',
    'run_comprehensive_test_suite',
]