"""
Standardized circuit breaker patterns for all services.

This module provides unified circuit breaker implementations for:
- Count-based circuit breakers
- Time-based circuit breakers  
- Percentage-based circuit breakers
- FastAPI middleware integration
- Database connection protection
- External API call protection
- MCP server communication protection
- Bulkhead pattern for service isolation
- Monitoring and metrics collection
- Configuration management
- Automatic recovery and health checking

All external dependencies should use these standardized patterns.
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque, defaultdict
from contextlib import asynccontextmanager
import json
from abc import ABC, abstractmethod
import weakref
import threading

# Import existing circuit breaker components
from src.core.circuit_breaker import (
    CircuitState, CircuitBreakerConfig, CircuitBreaker, 
    CircuitOpenError, CircuitBreakerManager, get_circuit_breaker_manager
)
from src.core.circuit_breaker_config import get_circuit_breaker_config

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class CircuitBreakerType(Enum):
    """Types of circuit breakers available."""
    COUNT_BASED = "count_based"
    TIME_BASED = "time_based"
    PERCENTAGE_BASED = "percentage_based"
    ADAPTIVE = "adaptive"


@dataclass
class BulkheadConfig:
    """Configuration for bulkhead pattern isolation."""
    max_concurrent_calls: int = 10
    max_wait_duration: float = 30.0
    isolation_pool_name: str = "default"
    enforce_timeout: bool = True
    queue_timeout: float = 5.0


@dataclass
class HealthCheckConfig:
    """Configuration for health checking and recovery."""
    health_check_interval: float = 30.0
    health_check_timeout: float = 5.0
    health_check_url: Optional[str] = None
    health_check_function: Optional[Callable[[], Awaitable[bool]]] = None
    recovery_factor: float = 0.1  # Gradual recovery percentage
    max_recovery_attempts: int = 3


@dataclass
class StandardCircuitBreakerConfig(CircuitBreakerConfig):
    """Extended configuration for standardized circuit breakers."""
    circuit_type: CircuitBreakerType = CircuitBreakerType.COUNT_BASED
    bulkhead_config: Optional[BulkheadConfig] = None
    health_check_config: Optional[HealthCheckConfig] = None
    auto_recovery_enabled: bool = True
    metrics_enabled: bool = True
    alert_threshold: float = 0.8  # Alert when failure rate exceeds this
    service_category: str = "unknown"  # ai, mcp, database, external
    priority: int = 1  # 1=high, 2=medium, 3=low
    
    def __post_init__(self):
        """Set defaults based on service category."""
        if self.bulkhead_config is None:
            self.bulkhead_config = BulkheadConfig()
        
        if self.health_check_config is None:
            self.health_check_config = HealthCheckConfig()


class AbstractCircuitBreaker(ABC):
    """Abstract base class for different circuit breaker types."""
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.name = config.name or f"CircuitBreaker_{id(self)}"
        self._lock = asyncio.Lock()
        self._metrics = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'rejected_calls': 0,
            'state_changes': []
        }
        
    @abstractmethod
    async def should_open_circuit(self) -> bool:
        """Determine if circuit should open based on type-specific logic."""
        pass
    
    @abstractmethod
    async def should_close_circuit(self) -> bool:
        """Determine if circuit should close based on type-specific logic."""
        pass
    
    @abstractmethod
    def reset_internal_state(self):
        """Reset internal state specific to circuit breaker type."""
        pass


class CountBasedCircuitBreaker(AbstractCircuitBreaker):
    """Circuit breaker that opens based on consecutive failure count."""
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        super().__init__(config)
        self._consecutive_failures = 0
        self._consecutive_successes = 0
    
    async def should_open_circuit(self) -> bool:
        """Open if consecutive failures exceed threshold."""
        return self._consecutive_failures >= self.config.failure_threshold
    
    async def should_close_circuit(self) -> bool:
        """Close if consecutive successes exceed threshold in half-open state."""
        return (self.state == CircuitState.HALF_OPEN and 
                self._consecutive_successes >= self.config.success_threshold)
    
    def record_success(self):
        """Record a successful call."""
        self._consecutive_failures = 0
        self._consecutive_successes += 1
    
    def record_failure(self):
        """Record a failed call."""
        self._consecutive_failures += 1
        self._consecutive_successes = 0
    
    def reset_internal_state(self):
        """Reset count-based state."""
        self._consecutive_failures = 0
        self._consecutive_successes = 0


class TimeBasedCircuitBreaker(AbstractCircuitBreaker):
    """Circuit breaker that opens based on failure rate over time windows."""
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        super().__init__(config)
        self._time_window = 60.0  # 1 minute window
        self._calls_in_window = deque()
        self._failures_in_window = deque()
    
    async def should_open_circuit(self) -> bool:
        """Open if failure rate in time window exceeds threshold."""
        self._cleanup_old_entries()
        
        if len(self._calls_in_window) < self.config.minimum_calls:
            return False
            
        failure_rate = len(self._failures_in_window) / len(self._calls_in_window)
        return failure_rate >= self.config.failure_rate_threshold
    
    async def should_close_circuit(self) -> bool:
        """Close based on recent success rate."""
        self._cleanup_old_entries()
        
        if len(self._calls_in_window) < 3:  # Need some recent calls
            return False
            
        # Look at recent successes
        recent_window = 10  # Last 10 calls
        recent_calls = list(self._calls_in_window)[-recent_window:]
        recent_failures = [f for f in self._failures_in_window if f in recent_calls]
        
        success_rate = (len(recent_calls) - len(recent_failures)) / len(recent_calls)
        return success_rate >= 0.8  # 80% success rate to close
    
    def record_success(self):
        """Record a successful call."""
        now = time.time()
        self._calls_in_window.append(now)
    
    def record_failure(self):
        """Record a failed call."""
        now = time.time()
        self._calls_in_window.append(now)
        self._failures_in_window.append(now)
    
    def _cleanup_old_entries(self):
        """Remove entries older than time window."""
        cutoff = time.time() - self._time_window
        
        while self._calls_in_window and self._calls_in_window[0] < cutoff:
            self._calls_in_window.popleft()
        
        while self._failures_in_window and self._failures_in_window[0] < cutoff:
            self._failures_in_window.popleft()
    
    def reset_internal_state(self):
        """Reset time-based state."""
        self._calls_in_window.clear()
        self._failures_in_window.clear()


class PercentageBasedCircuitBreaker(AbstractCircuitBreaker):
    """Circuit breaker that opens based on failure percentage in sliding window."""
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        super().__init__(config)
        self._sliding_window = deque(maxlen=config.sliding_window_size)
    
    async def should_open_circuit(self) -> bool:
        """Open if failure percentage exceeds threshold."""
        if len(self._sliding_window) < self.config.minimum_calls:
            return False
        
        failures = self._sliding_window.count(False)
        failure_rate = failures / len(self._sliding_window)
        return failure_rate >= self.config.failure_rate_threshold
    
    async def should_close_circuit(self) -> bool:
        """Close if recent success rate is good."""
        if len(self._sliding_window) < 5:
            return False
        
        # Look at recent 10 entries
        recent_entries = list(self._sliding_window)[-10:]
        successes = recent_entries.count(True)
        return successes >= 8  # 80% recent success rate
    
    def record_success(self):
        """Record a successful call."""
        self._sliding_window.append(True)
    
    def record_failure(self):
        """Record a failed call."""
        self._sliding_window.append(False)
    
    def reset_internal_state(self):
        """Reset percentage-based state."""
        self._sliding_window.clear()


class AdaptiveCircuitBreaker(AbstractCircuitBreaker):
    """Advanced circuit breaker that adapts thresholds based on service behavior."""
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        super().__init__(config)
        self._response_times = deque(maxlen=100)
        self._baseline_response_time = None
        self._adaptive_threshold = config.failure_threshold
        self._performance_degradation_factor = 2.0
    
    async def should_open_circuit(self) -> bool:
        """Open based on adaptive thresholds considering performance."""
        # Update adaptive threshold based on recent performance
        self._update_adaptive_threshold()
        
        # Use the base percentage-based logic with adaptive threshold
        if len(self._sliding_window) < self.config.minimum_calls:
            return False
        
        failures = self._sliding_window.count(False)
        failure_rate = failures / len(self._sliding_window)
        
        # Lower threshold if performance is degraded
        adjusted_threshold = self.config.failure_rate_threshold
        if self._is_performance_degraded():
            adjusted_threshold *= 0.7  # Lower threshold when performance is poor
        
        return failure_rate >= adjusted_threshold
    
    async def should_close_circuit(self) -> bool:
        """Close with consideration for performance recovery."""
        if len(self._sliding_window) < 5:
            return False
        
        # Require better performance for closing when adaptive
        recent_entries = list(self._sliding_window)[-10:]
        successes = recent_entries.count(True)
        success_rate = successes / len(recent_entries)
        
        # Also check response time recovery
        performance_ok = not self._is_performance_degraded()
        
        return success_rate >= 0.9 and performance_ok  # Higher bar for adaptive
    
    def record_success(self, response_time: float = None):
        """Record a successful call with optional response time."""
        self._sliding_window.append(True)
        if response_time is not None:
            self._response_times.append(response_time)
            if self._baseline_response_time is None and len(self._response_times) >= 10:
                self._baseline_response_time = sum(self._response_times) / len(self._response_times)
    
    def record_failure(self, response_time: float = None):
        """Record a failed call with optional response time."""
        self._sliding_window.append(False)
        if response_time is not None:
            self._response_times.append(response_time)
    
    def _update_adaptive_threshold(self):
        """Update failure threshold based on recent behavior."""
        if len(self._sliding_window) >= 50:
            recent_failure_rate = self._sliding_window.count(False) / len(self._sliding_window)
            
            # Increase sensitivity if historically stable
            if recent_failure_rate < 0.1:
                self._adaptive_threshold = max(2, self.config.failure_threshold - 1)
            else:
                self._adaptive_threshold = self.config.failure_threshold
    
    def _is_performance_degraded(self) -> bool:
        """Check if response time performance is degraded."""
        if not self._response_times or self._baseline_response_time is None:
            return False
        
        recent_avg = sum(list(self._response_times)[-10:]) / min(10, len(self._response_times))
        return recent_avg > self._baseline_response_time * self._performance_degradation_factor
    
    def reset_internal_state(self):
        """Reset adaptive state."""
        self._sliding_window = deque(maxlen=self.config.sliding_window_size)
        self._response_times.clear()
        self._baseline_response_time = None
        self._adaptive_threshold = self.config.failure_threshold


class BulkheadManager:
    """Manages bulkhead pattern for service isolation."""
    
    def __init__(self):
        self._pools: Dict[str, asyncio.Semaphore] = {}
        self._pool_configs: Dict[str, BulkheadConfig] = {}
        self._pool_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'active_calls': 0,
            'queued_calls': 0,
            'rejected_calls': 0,
            'total_calls': 0
        })
        self._lock = asyncio.Lock()
    
    async def get_or_create_pool(self, pool_name: str, config: BulkheadConfig) -> asyncio.Semaphore:
        """Get or create a bulkhead pool."""
        async with self._lock:
            if pool_name not in self._pools:
                self._pools[pool_name] = asyncio.Semaphore(config.max_concurrent_calls)
                self._pool_configs[pool_name] = config
                logger.info(f"Created bulkhead pool '{pool_name}' with {config.max_concurrent_calls} slots")
            
            return self._pools[pool_name]
    
    @asynccontextmanager
    async def acquire_slot(self, pool_name: str, config: BulkheadConfig):
        """Acquire a slot in the bulkhead pool."""
        semaphore = await self.get_or_create_pool(pool_name, config)
        
        self._pool_metrics[pool_name]['total_calls'] += 1
        self._pool_metrics[pool_name]['queued_calls'] += 1
        
        try:
            # Try to acquire with timeout
            acquired = await asyncio.wait_for(
                semaphore.acquire(), 
                timeout=config.queue_timeout
            )
            
            self._pool_metrics[pool_name]['queued_calls'] -= 1
            self._pool_metrics[pool_name]['active_calls'] += 1
            
            try:
                yield
            finally:
                semaphore.release()
                self._pool_metrics[pool_name]['active_calls'] -= 1
                
        except asyncio.TimeoutError:
            self._pool_metrics[pool_name]['queued_calls'] -= 1
            self._pool_metrics[pool_name]['rejected_calls'] += 1
            raise CircuitOpenError(f"Bulkhead pool '{pool_name}' queue timeout")
    
    def get_pool_metrics(self, pool_name: str) -> Dict[str, Any]:
        """Get metrics for a specific pool."""
        return dict(self._pool_metrics[pool_name])
    
    def get_all_pool_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all pools."""
        return {pool: dict(metrics) for pool, metrics in self._pool_metrics.items()}


class HealthChecker:
    """Manages health checking and automatic recovery."""
    
    def __init__(self):
        self._health_checks: Dict[str, HealthCheckConfig] = {}
        self._health_status: Dict[str, bool] = {}
        self._check_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
    
    async def register_health_check(self, service_name: str, config: HealthCheckConfig):
        """Register a health check for a service."""
        async with self._lock:
            self._health_checks[service_name] = config
            self._health_status[service_name] = True
            
            # Start health check task
            if service_name in self._check_tasks:
                self._check_tasks[service_name].cancel()
            
            self._check_tasks[service_name] = asyncio.create_task(
                self._health_check_loop(service_name, config)
            )
            
            logger.info(f"Registered health check for service '{service_name}'")
    
    async def _health_check_loop(self, service_name: str, config: HealthCheckConfig):
        """Continuous health check loop for a service."""
        while True:
            try:
                await asyncio.sleep(config.health_check_interval)
                
                # Perform health check
                is_healthy = await self._perform_health_check(service_name, config)
                
                async with self._lock:
                    old_status = self._health_status.get(service_name, True)
                    self._health_status[service_name] = is_healthy
                    
                    if old_status != is_healthy:
                        status_text = "healthy" if is_healthy else "unhealthy"
                        logger.info(f"Service '{service_name}' status changed to {status_text}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error for '{service_name}': {e}")
                async with self._lock:
                    self._health_status[service_name] = False
    
    async def _perform_health_check(self, service_name: str, config: HealthCheckConfig) -> bool:
        """Perform actual health check."""
        try:
            if config.health_check_function:
                return await asyncio.wait_for(
                    config.health_check_function(),
                    timeout=config.health_check_timeout
                )
            elif config.health_check_url:
                # Simple HTTP health check
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        config.health_check_url,
                        timeout=aiohttp.ClientTimeout(total=config.health_check_timeout)
                    ) as response:
                        return response.status == 200
            else:
                return True  # No health check configured, assume healthy
                
        except Exception as e:
            logger.debug(f"Health check failed for '{service_name}': {e}")
            return False
    
    def is_healthy(self, service_name: str) -> bool:
        """Check if a service is currently healthy."""
        return self._health_status.get(service_name, True)
    
    def get_health_status(self) -> Dict[str, bool]:
        """Get health status for all services."""
        return dict(self._health_status)


class StandardizedCircuitBreaker:
    """
    Standardized circuit breaker that unifies all patterns and features.
    
    This is the main interface for all circuit breaker usage across the system.
    """
    
    def __init__(self, config: StandardCircuitBreakerConfig):
        self.config = config
        self.name = config.name or f"StandardBreaker_{id(self)}"
        
        # Initialize the appropriate circuit breaker type
        if config.circuit_type == CircuitBreakerType.COUNT_BASED:
            self._breaker = CountBasedCircuitBreaker(config)
        elif config.circuit_type == CircuitBreakerType.TIME_BASED:
            self._breaker = TimeBasedCircuitBreaker(config)
        elif config.circuit_type == CircuitBreakerType.PERCENTAGE_BASED:
            self._breaker = PercentageBasedCircuitBreaker(config)
        elif config.circuit_type == CircuitBreakerType.ADAPTIVE:
            self._breaker = AdaptiveCircuitBreaker(config)
        else:
            raise ValueError(f"Unknown circuit breaker type: {config.circuit_type}")
        
        # Initialize managers
        self._bulkhead_manager = BulkheadManager()
        self._health_checker = HealthChecker()
        
        # Register health check if configured
        if config.health_check_config and config.auto_recovery_enabled:
            asyncio.create_task(self._health_checker.register_health_check(
                self.name, config.health_check_config
            ))
        
        # Metrics and monitoring
        self._last_failure_time = None
        self._state_transition_callbacks = []
        
        logger.info(f"Initialized standardized circuit breaker '{self.name}' "
                   f"(type: {config.circuit_type.value}, category: {config.service_category})")
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with full circuit breaker protection."""
        start_time = time.time()
        
        # Check health status first
        if not self._health_checker.is_healthy(self.name):
            logger.warning(f"Service '{self.name}' is unhealthy, rejecting call")
            raise CircuitOpenError(f"Service '{self.name}' is unhealthy")
        
        # Bulkhead protection
        if self.config.bulkhead_config:
            async with self._bulkhead_manager.acquire_slot(
                self.config.bulkhead_config.isolation_pool_name,
                self.config.bulkhead_config
            ):
                return await self._execute_with_circuit_protection(
                    func, start_time, *args, **kwargs
                )
        else:
            return await self._execute_with_circuit_protection(
                func, start_time, *args, **kwargs
            )
    
    async def _execute_with_circuit_protection(
        self, func: Callable[..., T], start_time: float, *args, **kwargs
    ) -> T:
        """Execute function with circuit breaker protection."""
        async with self._breaker._lock:
            # Check if circuit should transition
            if self._breaker.state == CircuitState.OPEN and self._should_attempt_reset():
                await self._transition_to_half_open()
            
            # Reject if circuit is open
            if self._breaker.state == CircuitState.OPEN:
                self._breaker._metrics['rejected_calls'] += 1
                
                if self.config.fallback:
                    logger.warning(f"Circuit '{self.name}' is OPEN, using fallback")
                    return await self._execute_fallback(*args, **kwargs)
                
                raise CircuitOpenError(f"Circuit breaker '{self.name}' is OPEN")
        
        # Execute the function
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, func, *args, **kwargs)
            
            # Record success
            duration = time.time() - start_time
            await self._record_success(duration)
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            await self._record_failure(e, duration)
            raise
    
    async def _record_success(self, duration: float):
        """Record a successful call."""
        async with self._breaker._lock:
            self._breaker._metrics['total_calls'] += 1
            self._breaker._metrics['successful_calls'] += 1
            
            # Type-specific recording
            if hasattr(self._breaker, 'record_success'):
                if isinstance(self._breaker, AdaptiveCircuitBreaker):
                    self._breaker.record_success(duration)
                else:
                    self._breaker.record_success()
            
            # Check if we should close the circuit
            if await self._breaker.should_close_circuit():
                await self._transition_to_closed()
    
    async def _record_failure(self, exception: Exception, duration: float):
        """Record a failed call."""
        async with self._breaker._lock:
            self._breaker._metrics['total_calls'] += 1
            self._breaker._metrics['failed_calls'] += 1
            self._last_failure_time = time.time()
            
            # Type-specific recording
            if hasattr(self._breaker, 'record_failure'):
                if isinstance(self._breaker, AdaptiveCircuitBreaker):
                    self._breaker.record_failure(duration)
                else:
                    self._breaker.record_failure()
            
            # Check if we should open the circuit
            if await self._breaker.should_open_circuit():
                await self._transition_to_open("Failure threshold exceeded")
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._last_failure_time is None:
            return True
        return time.time() - self._last_failure_time >= self.config.timeout
    
    async def _transition_to_closed(self):
        """Transition to closed state."""
        old_state = self._breaker.state
        self._breaker.state = CircuitState.CLOSED
        self._breaker.reset_internal_state()
        
        self._breaker._metrics['state_changes'].append({
            'timestamp': datetime.now().isoformat(),
            'from_state': old_state.value,
            'to_state': 'closed',
            'reason': 'Success threshold reached'
        })
        
        logger.info(f"Circuit '{self.name}' transitioned from {old_state.value} to CLOSED")
        await self._notify_state_change(old_state, CircuitState.CLOSED)
    
    async def _transition_to_open(self, reason: str):
        """Transition to open state."""
        old_state = self._breaker.state
        self._breaker.state = CircuitState.OPEN
        
        self._breaker._metrics['state_changes'].append({
            'timestamp': datetime.now().isoformat(),
            'from_state': old_state.value,
            'to_state': 'open',
            'reason': reason
        })
        
        logger.warning(f"Circuit '{self.name}' transitioned from {old_state.value} to OPEN: {reason}")
        await self._notify_state_change(old_state, CircuitState.OPEN)
    
    async def _transition_to_half_open(self):
        """Transition to half-open state."""
        old_state = self._breaker.state
        self._breaker.state = CircuitState.HALF_OPEN
        
        self._breaker._metrics['state_changes'].append({
            'timestamp': datetime.now().isoformat(),
            'from_state': old_state.value,
            'to_state': 'half_open',
            'reason': 'Timeout expired'
        })
        
        logger.info(f"Circuit '{self.name}' transitioned from {old_state.value} to HALF_OPEN")
        await self._notify_state_change(old_state, CircuitState.HALF_OPEN)
    
    async def _notify_state_change(self, from_state: CircuitState, to_state: CircuitState):
        """Notify registered callbacks about state changes."""
        for callback in self._state_transition_callbacks:
            try:
                await callback(self.name, from_state, to_state)
            except Exception as e:
                logger.error(f"State transition callback error: {e}")
    
    async def _execute_fallback(self, *args, **kwargs) -> T:
        """Execute the fallback function."""
        if not self.config.fallback:
            raise CircuitOpenError(f"No fallback configured for circuit '{self.name}'")
        
        if asyncio.iscoroutinefunction(self.config.fallback):
            return await self.config.fallback(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.config.fallback, *args, **kwargs)
    
    def add_state_transition_callback(self, callback: Callable[[str, CircuitState, CircuitState], Awaitable[None]]):
        """Add a callback for state transitions."""
        self._state_transition_callbacks.append(callback)
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self._breaker.state
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive circuit breaker metrics."""
        metrics = dict(self._breaker._metrics)
        metrics.update({
            'name': self.name,
            'state': self._breaker.state.value,
            'circuit_type': self.config.circuit_type.value,
            'service_category': self.config.service_category,
            'is_healthy': self._health_checker.is_healthy(self.name),
            'bulkhead_metrics': self._bulkhead_manager.get_all_pool_metrics()
        })
        return metrics
    
    def __call__(self, func: F) -> F:
        """Decorator usage."""
        async def wrapper(*args, **kwargs):
            return await self.call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.circuit_breaker = self
        
        return wrapper


class StandardizedCircuitBreakerFactory:
    """Factory for creating standardized circuit breakers with preset configurations."""
    
    @staticmethod
    def create_ai_provider_breaker(
        provider_name: str,
        circuit_type: CircuitBreakerType = CircuitBreakerType.ADAPTIVE
    ) -> StandardizedCircuitBreaker:
        """Create circuit breaker for AI providers."""
        config = get_circuit_breaker_config(provider_name, "ai_provider")
        
        standard_config = StandardCircuitBreakerConfig(
            name=f"ai_{provider_name}",
            circuit_type=circuit_type,
            failure_threshold=config.failure_threshold,
            timeout=config.timeout,
            failure_rate_threshold=config.failure_rate_threshold,
            minimum_calls=config.minimum_calls,
            service_category="ai",
            priority=1,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=20,
                isolation_pool_name=f"ai_{provider_name}",
                queue_timeout=10.0
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=30.0,
                health_check_timeout=5.0
            )
        )
        
        return StandardizedCircuitBreaker(standard_config)
    
    @staticmethod
    def create_mcp_service_breaker(
        service_name: str,
        circuit_type: CircuitBreakerType = CircuitBreakerType.COUNT_BASED
    ) -> StandardizedCircuitBreaker:
        """Create circuit breaker for MCP services."""
        config = get_circuit_breaker_config(service_name, "mcp_service")
        
        standard_config = StandardCircuitBreakerConfig(
            name=f"mcp_{service_name}",
            circuit_type=circuit_type,
            failure_threshold=config.failure_threshold,
            timeout=config.timeout,
            failure_rate_threshold=config.failure_rate_threshold,
            minimum_calls=config.minimum_calls,
            service_category="mcp",
            priority=2,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=10,
                isolation_pool_name=f"mcp_{service_name}",
                queue_timeout=5.0
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=60.0,
                health_check_timeout=10.0
            )
        )
        
        return StandardizedCircuitBreaker(standard_config)
    
    @staticmethod
    def create_database_breaker(
        db_name: str = "default",
        circuit_type: CircuitBreakerType = CircuitBreakerType.PERCENTAGE_BASED
    ) -> StandardizedCircuitBreaker:
        """Create circuit breaker for database connections."""
        standard_config = StandardCircuitBreakerConfig(
            name=f"database_{db_name}",
            circuit_type=circuit_type,
            failure_threshold=3,
            timeout=30.0,
            failure_rate_threshold=0.3,
            minimum_calls=20,
            service_category="database",
            priority=1,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=50,
                isolation_pool_name=f"database_{db_name}",
                queue_timeout=2.0
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=15.0,
                health_check_timeout=3.0
            )
        )
        
        return StandardizedCircuitBreaker(standard_config)
    
    @staticmethod
    def create_external_api_breaker(
        api_name: str,
        circuit_type: CircuitBreakerType = CircuitBreakerType.TIME_BASED
    ) -> StandardizedCircuitBreaker:
        """Create circuit breaker for external API calls."""
        standard_config = StandardCircuitBreakerConfig(
            name=f"external_{api_name}",
            circuit_type=circuit_type,
            failure_threshold=5,
            timeout=60.0,
            failure_rate_threshold=0.5,
            minimum_calls=10,
            service_category="external",
            priority=3,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=15,
                isolation_pool_name=f"external_{api_name}",
                queue_timeout=8.0
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=45.0,
                health_check_timeout=8.0
            )
        )
        
        return StandardizedCircuitBreaker(standard_config)


# Global registry for standardized circuit breakers
_standardized_breakers: Dict[str, StandardizedCircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_standardized_circuit_breaker(
    name: str,
    breaker_type: str = "external",
    circuit_type: CircuitBreakerType = None,
    config: StandardCircuitBreakerConfig = None
) -> StandardizedCircuitBreaker:
    """
    Get or create a standardized circuit breaker.
    
    Args:
        name: Service name
        breaker_type: Type of breaker (ai, mcp, database, external)
        circuit_type: Circuit breaker algorithm type
        config: Custom configuration (optional)
    
    Returns:
        Standardized circuit breaker instance
    """
    with _registry_lock:
        if name not in _standardized_breakers:
            if config:
                breaker = StandardizedCircuitBreaker(config)
            elif breaker_type == "ai":
                breaker = StandardizedCircuitBreakerFactory.create_ai_provider_breaker(
                    name, circuit_type or CircuitBreakerType.ADAPTIVE
                )
            elif breaker_type == "mcp":
                breaker = StandardizedCircuitBreakerFactory.create_mcp_service_breaker(
                    name, circuit_type or CircuitBreakerType.COUNT_BASED
                )
            elif breaker_type == "database":
                breaker = StandardizedCircuitBreakerFactory.create_database_breaker(
                    name, circuit_type or CircuitBreakerType.PERCENTAGE_BASED
                )
            else:  # external
                breaker = StandardizedCircuitBreakerFactory.create_external_api_breaker(
                    name, circuit_type or CircuitBreakerType.TIME_BASED
                )
            
            _standardized_breakers[name] = breaker
            logger.info(f"Created standardized circuit breaker for '{name}' (type: {breaker_type})")
        
        return _standardized_breakers[name]


def get_all_standardized_breakers() -> Dict[str, StandardizedCircuitBreaker]:
    """Get all standardized circuit breakers."""
    with _registry_lock:
        return dict(_standardized_breakers)


def reset_all_standardized_breakers():
    """Reset all standardized circuit breakers."""
    with _registry_lock:
        for breaker in _standardized_breakers.values():
            breaker._breaker.reset_internal_state()
            breaker._breaker.state = CircuitState.CLOSED
        logger.info("Reset all standardized circuit breakers")


# Export public API
__all__ = [
    'StandardizedCircuitBreaker',
    'StandardizedCircuitBreakerFactory',
    'StandardCircuitBreakerConfig',
    'CircuitBreakerType',
    'BulkheadConfig',
    'HealthCheckConfig',
    'get_standardized_circuit_breaker',
    'get_all_standardized_breakers',
    'reset_all_standardized_breakers',
    'BulkheadManager',
    'HealthChecker',
]