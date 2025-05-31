"""
Production-grade circuit breaker implementation for external service protection.

This module provides a comprehensive circuit breaker pattern implementation with:
- State management (closed, open, half-open)
- Configurable failure thresholds and recovery timeouts
- Metrics collection and monitoring
- Fallback strategies
- Integration with existing retry mechanisms
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Generic
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
import json
from contextlib import asynccontextmanager

try:
    from src.core.circuit_breaker_metrics import get_circuit_breaker_metrics
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests pass through
    OPEN = "open"         # Failure threshold exceeded, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5              # Number of failures before opening
    success_threshold: int = 3              # Number of successes in half-open before closing
    timeout: float = 60.0                   # Seconds before attempting to close circuit
    half_open_max_calls: int = 3            # Max concurrent calls in half-open state
    failure_rate_threshold: float = 0.5     # Failure rate to trigger open state
    minimum_calls: int = 10                 # Minimum calls before calculating failure rate
    sliding_window_size: int = 100          # Size of sliding window for metrics
    excluded_exceptions: Optional[List[type]] = None  # Exceptions that don't count as failures
    fallback: Optional[Callable[..., Any]] = None   # Fallback function when circuit is open
    name: Optional[str] = None              # Circuit breaker name for logging/metrics


@dataclass
class CircuitBreakerMetrics:
    """Metrics collected by the circuit breaker."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    fallback_calls: int = 0
    state_changes: List[Dict[str, Any]] = field(default_factory=list)
    call_durations: deque = field(default_factory=lambda: deque(maxlen=1000))
    failure_reasons: Dict[str, int] = field(default_factory=dict)
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    
    def get_failure_rate(self) -> float:
        """Calculate current failure rate."""
        if self.total_calls == 0:
            return 0.0
        return self.failed_calls / self.total_calls
    
    def get_average_duration(self) -> float:
        """Calculate average call duration in seconds."""
        if not self.call_durations:
            return 0.0
        return sum(self.call_durations) / len(self.call_durations)
    
    def record_state_change(self, from_state: CircuitState, to_state: CircuitState, reason: str):
        """Record a state change event."""
        self.state_changes.append({
            "timestamp": datetime.now().isoformat(),
            "from_state": from_state.value,
            "to_state": to_state.value,
            "reason": reason
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for monitoring."""
        return {
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "rejected_calls": self.rejected_calls,
            "fallback_calls": self.fallback_calls,
            "failure_rate": self.get_failure_rate(),
            "average_duration": self.get_average_duration(),
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "state_changes": self.state_changes[-10:],  # Last 10 state changes
            "failure_reasons": dict(sorted(
                self.failure_reasons.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10])  # Top 10 failure reasons
        }


class CircuitBreaker(Generic[T]):
    """
    Thread-safe circuit breaker implementation.
    
    Example:
        ```python
        # Create circuit breaker
        breaker = CircuitBreaker(
            config=CircuitBreakerConfig(
                failure_threshold=5,
                timeout=60,
                fallback=lambda: {"status": "service unavailable"}
            )
        )
        
        # Use with async function
        @breaker
        async def call_external_service():
            return await external_api.call()
        
        # Or use directly
        result = await breaker.call(external_api.call)
        ```
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """Initialize circuit breaker with configuration."""
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.metrics = CircuitBreakerMetrics()
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()
        self._sliding_window: deque = deque(maxlen=self.config.sliding_window_size)
        
        # Set name for logging
        self.name = self.config.name or f"CircuitBreaker_{id(self)}"
        
        # Initialize Prometheus metrics if available
        if METRICS_AVAILABLE:
            self._prometheus_metrics = get_circuit_breaker_metrics()
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.set_config_info(self.name, service_type, {
                'failure_threshold': self.config.failure_threshold,
                'timeout': self.config.timeout,
                'failure_rate_threshold': self.config.failure_rate_threshold,
                'minimum_calls': self.config.minimum_calls
            })
            self._prometheus_metrics.set_circuit_state(self.name, service_type, self.state.value)
        else:
            self._prometheus_metrics = None
        
        logger.info(f"Initialized circuit breaker '{self.name}' with config: {self.config}")
    
    def _infer_service_type(self, name: str) -> str:
        """Infer service type from circuit breaker name."""
        name_lower = name.lower()
        if 'claude' in name_lower or 'anthropic' in name_lower:
            return 'ai_claude'
        elif 'gpt' in name_lower or 'openai' in name_lower:
            return 'ai_openai'
        elif 'gemini' in name_lower or 'google' in name_lower:
            return 'ai_google'
        elif 'deepseek' in name_lower:
            return 'ai_deepseek'
        elif 'groq' in name_lower:
            return 'ai_groq'
        elif 'ollama' in name_lower:
            return 'ai_ollama'
        elif 'huggingface' in name_lower:
            return 'ai_huggingface'
        elif 'docker' in name_lower:
            return 'mcp_docker'
        elif 'kubernetes' in name_lower or 'kubectl' in name_lower:
            return 'mcp_kubernetes'
        elif 'desktop_commander' in name_lower:
            return 'mcp_commander'
        elif 'prometheus' in name_lower:
            return 'mcp_prometheus'
        elif 'slack' in name_lower:
            return 'mcp_slack'
        elif 's3' in name_lower or 'aws' in name_lower:
            return 'mcp_storage'
        elif 'security' in name_lower or 'scanner' in name_lower:
            return 'mcp_security'
        else:
            return 'unknown'
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or fallback result
            
        Raises:
            CircuitOpenError: If circuit is open and no fallback is configured
        """
        async with self._lock:
            # Check if circuit should transition from open to half-open
            if self.state == CircuitState.OPEN and self._should_attempt_reset():
                self._transition_to_half_open()
            
            # Reject calls if circuit is open
            if self.state == CircuitState.OPEN:
                self.metrics.rejected_calls += 1
                if self._prometheus_metrics:
                    service_type = self._infer_service_type(self.name)
                    self._prometheus_metrics.record_request(self.name, service_type, 'rejected')
                
                if self.config.fallback:
                    self.metrics.fallback_calls += 1
                    if self._prometheus_metrics:
                        service_type = self._infer_service_type(self.name)
                        self._prometheus_metrics.record_fallback_activation(self.name, service_type)
                    logger.warning(f"Circuit '{self.name}' is OPEN, using fallback")
                    return await self._execute_fallback(*args, **kwargs)
                raise CircuitOpenError(f"Circuit breaker '{self.name}' is OPEN")
            
            # Limit concurrent calls in half-open state
            if self.state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self.metrics.rejected_calls += 1
                    if self.config.fallback:
                        self.metrics.fallback_calls += 1
                        return await self._execute_fallback(*args, **kwargs)
                    raise CircuitOpenError(f"Circuit breaker '{self.name}' is HALF_OPEN with max calls reached")
                self._half_open_calls += 1
        
        # Execute the function
        start_time = time.time()
        try:
            result = await self._execute_function(func, *args, **kwargs)
            duration = time.time() - start_time
            
            async with self._lock:
                self._record_success(duration)
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            async with self._lock:
                self._record_failure(e, duration)
            
            raise
    
    async def _execute_function(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute the protected function."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args, **kwargs)
    
    async def _execute_fallback(self, *args, **kwargs) -> T:
        """Execute the fallback function."""
        if not self.config.fallback:
            raise CircuitOpenError(f"No fallback configured for circuit '{self.name}'")
        
        if asyncio.iscoroutinefunction(self.config.fallback):
            return await self.config.fallback(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.config.fallback, *args, **kwargs)
    
    def _record_success(self, duration: float):
        """Record a successful call."""
        self.metrics.total_calls += 1
        self.metrics.successful_calls += 1
        self.metrics.last_success_time = datetime.now()
        self.metrics.call_durations.append(duration)
        self._sliding_window.append(True)
        
        # Record Prometheus metrics
        if self._prometheus_metrics:
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.record_request(self.name, service_type, 'success')
            self._prometheus_metrics.record_response_time(self.name, service_type, duration)
            self._prometheus_metrics.set_health_score(self.name, service_type, self._calculate_health_score())
        
        if self.state == CircuitState.HALF_OPEN:
            self._success_count += 1
            self._half_open_calls -= 1
            
            if self._success_count >= self.config.success_threshold:
                self._transition_to_closed()
        elif self.state == CircuitState.CLOSED:
            self._failure_count = 0  # Reset consecutive failures
    
    def _record_failure(self, exception: Exception, duration: float):
        """Record a failed call."""
        # Check if exception should be excluded
        if self.config.excluded_exceptions:
            for excluded_type in self.config.excluded_exceptions:
                if isinstance(exception, excluded_type):
                    logger.debug(f"Excluding exception {type(exception).__name__} from circuit breaker")
                    return
        
        self.metrics.total_calls += 1
        self.metrics.failed_calls += 1
        self.metrics.last_failure_time = datetime.now()
        self.metrics.call_durations.append(duration)
        self._sliding_window.append(False)
        self._last_failure_time = time.time()
        
        # Track failure reason
        error_type = type(exception).__name__
        self.metrics.failure_reasons[error_type] = self.metrics.failure_reasons.get(error_type, 0) + 1
        
        # Record Prometheus metrics
        if self._prometheus_metrics:
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.record_request(self.name, service_type, 'failure')
            self._prometheus_metrics.record_failure(self.name, service_type, error_type)
            self._prometheus_metrics.record_response_time(self.name, service_type, duration)
            self._prometheus_metrics.set_health_score(self.name, service_type, self._calculate_health_score())
        
        if self.state == CircuitState.HALF_OPEN:
            self._half_open_calls -= 1
            self._transition_to_open("Failure in half-open state")
        elif self.state == CircuitState.CLOSED:
            self._failure_count += 1
            
            # Check if we should open the circuit
            if self._should_open_circuit():
                self._transition_to_open("Failure threshold exceeded")
    
    def _should_open_circuit(self) -> bool:
        """Determine if the circuit should open based on failures."""
        # Check consecutive failure threshold
        if self._failure_count >= self.config.failure_threshold:
            return True
        
        # Check failure rate if we have enough calls
        if len(self._sliding_window) >= self.config.minimum_calls:
            failure_rate = self._sliding_window.count(False) / len(self._sliding_window)
            if failure_rate >= self.config.failure_rate_threshold:
                return True
        
        return False
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._last_failure_time is None:
            return True
        return time.time() - self._last_failure_time >= self.config.timeout
    
    def _transition_to_closed(self):
        """Transition to closed state."""
        old_state = self.state
        self.state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self.metrics.record_state_change(old_state, self.state, "Success threshold reached")
        
        # Record Prometheus metrics
        if self._prometheus_metrics:
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.record_state_transition(self.name, service_type, old_state.value, self.state.value)
            self._prometheus_metrics.set_circuit_state(self.name, service_type, self.state.value)
        
        logger.info(f"Circuit '{self.name}' transitioned from {old_state.value} to CLOSED")
    
    def _transition_to_open(self, reason: str):
        """Transition to open state."""
        old_state = self.state
        self.state = CircuitState.OPEN
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self.metrics.record_state_change(old_state, self.state, reason)
        
        # Record Prometheus metrics
        if self._prometheus_metrics:
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.record_state_transition(self.name, service_type, old_state.value, self.state.value)
            self._prometheus_metrics.set_circuit_state(self.name, service_type, self.state.value)
        
        logger.warning(f"Circuit '{self.name}' transitioned from {old_state.value} to OPEN: {reason}")
    
    def _transition_to_half_open(self):
        """Transition to half-open state."""
        old_state = self.state
        self.state = CircuitState.HALF_OPEN
        self._success_count = 0
        self._half_open_calls = 0
        self.metrics.record_state_change(old_state, self.state, "Timeout expired")
        
        # Record Prometheus metrics
        if self._prometheus_metrics:
            service_type = self._infer_service_type(self.name)
            self._prometheus_metrics.record_state_transition(self.name, service_type, old_state.value, self.state.value)
            self._prometheus_metrics.set_circuit_state(self.name, service_type, self.state.value)
        
        logger.info(f"Circuit '{self.name}' transitioned from {old_state.value} to HALF_OPEN")
    
    def _calculate_health_score(self) -> float:
        """Calculate health score for the circuit breaker (0.0 to 1.0)."""
        if self.metrics.total_calls == 0:
            return 1.0  # No calls means healthy
        
        # Base score from success rate
        success_rate = self.metrics.successful_calls / self.metrics.total_calls
        health_score = success_rate
        
        # Adjust based on circuit state
        if self.state == CircuitState.OPEN:
            health_score = 0.0
        elif self.state == CircuitState.HALF_OPEN:
            health_score = min(0.5, health_score)
        
        # Factor in recent performance
        if len(self._sliding_window) >= self.config.minimum_calls:
            recent_success_rate = self._sliding_window.count(True) / len(self._sliding_window)
            health_score = (health_score + recent_success_rate) / 2
        
        # Factor in response time (if available)
        if self.metrics.call_durations:
            avg_duration = self.metrics.get_average_duration()
            # Penalize slow responses (arbitrary threshold of 5 seconds)
            if avg_duration > 5.0:
                health_score *= 0.8
            elif avg_duration > 10.0:
                health_score *= 0.6
        
        return max(0.0, min(1.0, health_score))
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self.state
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
                "half_open_max_calls": self.config.half_open_max_calls,
                "failure_rate_threshold": self.config.failure_rate_threshold,
            },
            "metrics": self.metrics.to_dict()
        }
    
    def reset(self):
        """Manually reset the circuit breaker to closed state."""
        with asyncio.Lock():
            self.state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0
            self._sliding_window.clear()
            logger.info(f"Circuit '{self.name}' manually reset to CLOSED")
    
    def __call__(self, func: F) -> F:
        """Decorator usage of circuit breaker."""
        async def wrapper(*args, **kwargs):
            return await self.call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.circuit_breaker = self  # Attach breaker for inspection
        
        return wrapper


class CircuitOpenError(Exception):
    """Exception raised when circuit is open."""
    pass


class CircuitBreakerManager:
    """
    Manager for multiple circuit breakers with centralized monitoring.
    
    Example:
        ```python
        manager = CircuitBreakerManager()
        
        # Register circuit breakers
        api_breaker = manager.get_or_create("api_service", CircuitBreakerConfig(
            failure_threshold=5,
            timeout=60
        ))
        
        db_breaker = manager.get_or_create("database", CircuitBreakerConfig(
            failure_threshold=3,
            timeout=30
        ))
        
        # Get all metrics
        metrics = manager.get_all_metrics()
        ```
    """
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()
    
    async def get_or_create(
        self, 
        name: str, 
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get existing circuit breaker or create new one."""
        async with self._lock:
            if name not in self._breakers:
                if config is None:
                    config = CircuitBreakerConfig()
                config.name = name
                self._breakers[name] = CircuitBreaker(config)
                logger.info(f"Created new circuit breaker: {name}")
            
            return self._breakers[name]
    
    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self._breakers.get(name)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all circuit breakers."""
        return {
            name: breaker.get_metrics()
            for name, breaker in self._breakers.items()
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all circuit breakers."""
        total_calls = 0
        total_failures = 0
        open_circuits = []
        half_open_circuits = []
        
        for name, breaker in self._breakers.items():
            metrics = breaker.metrics
            total_calls += metrics.total_calls
            total_failures += metrics.failed_calls
            
            if breaker.state == CircuitState.OPEN:
                open_circuits.append(name)
            elif breaker.state == CircuitState.HALF_OPEN:
                half_open_circuits.append(name)
        
        return {
            "total_breakers": len(self._breakers),
            "total_calls": total_calls,
            "total_failures": total_failures,
            "overall_failure_rate": total_failures / total_calls if total_calls > 0 else 0,
            "open_circuits": open_circuits,
            "half_open_circuits": half_open_circuits,
            "closed_circuits": [
                name for name, breaker in self._breakers.items()
                if breaker.state == CircuitState.CLOSED
            ]
        }
    
    def reset_all(self):
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()
        logger.info("Reset all circuit breakers")
    
    def export_metrics(self, filepath: str):
        """Export all metrics to JSON file."""
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "breakers": self.get_all_metrics()
        }
        
        with open(filepath, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"Exported circuit breaker metrics to {filepath}")


# Global circuit breaker manager instance
_manager = CircuitBreakerManager()


def get_circuit_breaker(
    name: str, 
    config: Optional[CircuitBreakerConfig] = None
) -> CircuitBreaker:
    """
    Get or create a circuit breaker from the global manager.
    
    Args:
        name: Name of the circuit breaker
        config: Configuration (only used if creating new breaker)
        
    Returns:
        Circuit breaker instance
    """
    # Run in sync context since this is often called at module level
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_manager.get_or_create(name, config))
    finally:
        loop.close()


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Get the global circuit breaker manager."""
    return _manager


# Convenience decorators with preset configurations
def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    timeout: float = 60,
    fallback: Optional[Callable] = None
) -> Callable[[F], F]:
    """
    Decorator to apply circuit breaker to a function.
    
    Args:
        name: Circuit breaker name
        failure_threshold: Number of failures before opening
        timeout: Seconds before attempting to close
        fallback: Fallback function when circuit is open
        
    Example:
        ```python
        @circuit_breaker("external_api", failure_threshold=3, timeout=30)
        async def call_api():
            return await external_api.request()
        ```
    """
    config = CircuitBreakerConfig(
        name=name,
        failure_threshold=failure_threshold,
        timeout=timeout,
        fallback=fallback
    )
    
    breaker = get_circuit_breaker(name, config)
    return breaker


# Export public API
__all__ = [
    'CircuitBreaker',
    'CircuitBreakerConfig',
    'CircuitBreakerManager',
    'CircuitBreakerMetrics',
    'CircuitState',
    'CircuitOpenError',
    'get_circuit_breaker',
    'get_circuit_breaker_manager',
    'circuit_breaker',
]