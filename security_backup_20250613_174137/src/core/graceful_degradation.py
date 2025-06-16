"""
Graceful degradation patterns for handling service failures.

This module provides:
- Fallback strategies for different failure scenarios
- Service mesh integration for degradation
- Quality of service (QoS) management
- Adaptive load shedding
- Bulkhead isolation patterns
- Timeout and deadline management
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from weakref import WeakValueDictionary
import random

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ServicePriority(Enum):
    """Service priority levels for degradation decisions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BEST_EFFORT = "best_effort"


class DegradationLevel(Enum):
    """Levels of service degradation."""
    NORMAL = "normal"
    REDUCED_FUNCTIONALITY = "reduced_functionality"
    ESSENTIAL_ONLY = "essential_only"
    EMERGENCY_MODE = "emergency_mode"
    UNAVAILABLE = "unavailable"


class QualityOfService(Enum):
    """Quality of service levels."""
    PREMIUM = "premium"
    STANDARD = "standard"
    BASIC = "basic"
    DEGRADED = "degraded"


@dataclass
class FallbackStrategy:
    """Configuration for fallback behavior."""
    name: str
    fallback_func: Optional[Callable] = None
    cache_enabled: bool = True
    cache_ttl: int = 300  # seconds
    static_response: Optional[Any] = None
    redirect_service: Optional[str] = None
    degraded_response: Optional[Any] = None
    timeout: float = 5.0
    priority: ServicePriority = ServicePriority.MEDIUM


@dataclass
class ServiceHealth:
    """Health metrics for a service."""
    service_name: str
    success_rate: float = 1.0
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    availability: float = 1.0
    load: float = 0.0
    last_check: datetime = field(default_factory=datetime.now)
    is_healthy: bool = True
    degradation_level: DegradationLevel = DegradationLevel.NORMAL


@dataclass
class LoadSheddingConfig:
    """Configuration for adaptive load shedding."""
    enable_shedding: bool = True
    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0
    response_time_threshold: float = 5.0
    error_rate_threshold: float = 0.1
    queue_length_threshold: int = 100
    shed_percentage: float = 0.1  # Percentage of requests to shed
    priority_based_shedding: bool = True


class FallbackCache:
    """Cache for fallback responses."""
    
    def __init__(self, max_size: int = 1000):
        """Initialize fallback cache."""
        self._cache: Dict[str, tuple] = {}  # key -> (value, timestamp, ttl)
        self.max_size = max_size
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        async with self._lock:
            if key in self._cache:
                value, timestamp, ttl = self._cache[key]
                if time.time() - timestamp < ttl:
                    return value
                else:
                    del self._cache[key]
        return None
    
    async def set(self, key: str, value: Any, ttl: int = 300):
        """Set cached value with TTL."""
        async with self._lock:
            # Evict oldest entries if cache is full
            if len(self._cache) >= self.max_size:
                oldest_key = min(
                    self._cache.keys(),
                    key=lambda k: self._cache[k][1]
                )
                del self._cache[oldest_key]
            
            self._cache[key] = (value, time.time(), ttl)
    
    async def clear(self):
        """Clear all cached entries."""
        async with self._lock:
            self._cache.clear()


class BulkheadIsolator:
    """Bulkhead pattern implementation for resource isolation."""
    
    def __init__(self, max_concurrent: int = 10, queue_size: int = 50):
        """Initialize bulkhead isolator."""
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.active_operations = 0
        self._lock = asyncio.Lock()
    
    @asynccontextmanager
    async def isolate(self):
        """Context manager for bulkhead isolation."""
        try:
            # Try to acquire resource
            acquired = False
            try:
                await asyncio.wait_for(self.semaphore.acquire(), timeout=1.0)
                acquired = True
                async with self._lock:
                    self.active_operations += 1
                yield
            except asyncio.TimeoutError:
                raise Exception("Bulkhead capacity exceeded")
        finally:
            if acquired:
                async with self._lock:
                    self.active_operations -= 1
                self.semaphore.release()
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics."""
        async with self._lock:
            return {
                'active_operations': self.active_operations,
                'available_capacity': self.semaphore._value,
                'queue_size': self.queue.qsize(),
                'is_at_capacity': self.semaphore._value == 0
            }


class AdaptiveLoadShedder:
    """Adaptive load shedding based on system metrics."""
    
    def __init__(self, config: LoadSheddingConfig):
        """Initialize load shedder."""
        self.config = config
        self.shed_count = 0
        self.total_requests = 0
        self.recent_response_times = deque(maxlen=100)
        self.recent_errors = deque(maxlen=100)
        self._lock = asyncio.Lock()
    
    async def should_shed_load(
        self,
        priority: ServicePriority = ServicePriority.MEDIUM,
        current_load: Optional[float] = None
    ) -> bool:
        """Determine if request should be shed."""
        if not self.config.enable_shedding:
            return False
        
        async with self._lock:
            self.total_requests += 1
            
            # Check system metrics
            should_shed = False
            
            # Response time based shedding
            if self.recent_response_times:
                avg_response_time = sum(self.recent_response_times) / len(self.recent_response_times)
                if avg_response_time > self.config.response_time_threshold:
                    should_shed = True
            
            # Error rate based shedding
            if self.recent_errors:
                error_rate = sum(self.recent_errors) / len(self.recent_errors)
                if error_rate > self.config.error_rate_threshold:
                    should_shed = True
            
            # Current load based shedding
            if current_load and current_load > 0.8:
                should_shed = True
            
            # Priority-based shedding
            if should_shed and self.config.priority_based_shedding:
                if priority == ServicePriority.CRITICAL:
                    should_shed = False  # Never shed critical requests
                elif priority == ServicePriority.LOW:
                    should_shed = True  # Always shed low priority when overloaded
                elif priority == ServicePriority.BEST_EFFORT:
                    should_shed = random.random() < 0.5  # Randomly shed 50%
            
            # Random shedding based on percentage
            if should_shed:
                should_shed = random.random() < self.config.shed_percentage
            
            if should_shed:
                self.shed_count += 1
            
            return should_shed
    
    async def record_response_time(self, response_time: float):
        """Record response time for metrics."""
        async with self._lock:
            self.recent_response_times.append(response_time)
    
    async def record_error(self, is_error: bool):
        """Record error occurrence."""
        async with self._lock:
            self.recent_errors.append(1 if is_error else 0)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get load shedding statistics."""
        async with self._lock:
            shed_rate = self.shed_count / self.total_requests if self.total_requests > 0 else 0
            avg_response_time = (
                sum(self.recent_response_times) / len(self.recent_response_times)
                if self.recent_response_times else 0
            )
            error_rate = (
                sum(self.recent_errors) / len(self.recent_errors)
                if self.recent_errors else 0
            )
            
            return {
                'total_requests': self.total_requests,
                'shed_count': self.shed_count,
                'shed_rate': shed_rate,
                'avg_response_time': avg_response_time,
                'error_rate': error_rate
            }


class ServiceMesh:
    """Service mesh for managing service interactions and degradation."""
    
    def __init__(self):
        """Initialize service mesh."""
        self.services: Dict[str, ServiceHealth] = {}
        self.fallback_strategies: Dict[str, FallbackStrategy] = {}
        self.bulkheads: Dict[str, BulkheadIsolator] = {}
        self.load_shedders: Dict[str, AdaptiveLoadShedder] = {}
        self.fallback_cache = FallbackCache()
        self._lock = asyncio.Lock()
    
    async def register_service(
        self,
        service_name: str,
        fallback_strategy: Optional[FallbackStrategy] = None,
        bulkhead_config: Optional[Dict[str, Any]] = None,
        load_shedding_config: Optional[LoadSheddingConfig] = None
    ):
        """Register a service in the mesh."""
        async with self._lock:
            self.services[service_name] = ServiceHealth(service_name=service_name)
            
            if fallback_strategy:
                self.fallback_strategies[service_name] = fallback_strategy
            
            if bulkhead_config:
                self.bulkheads[service_name] = BulkheadIsolator(**bulkhead_config)
            
            if load_shedding_config:
                self.load_shedders[service_name] = AdaptiveLoadShedder(load_shedding_config)
        
        logger.info(f"Registered service in mesh: {service_name}")
    
    async def call_service(
        self,
        service_name: str,
        operation: Callable[..., T],
        *args,
        priority: ServicePriority = ServicePriority.MEDIUM,
        timeout: Optional[float] = None,
        **kwargs
    ) -> T:
        """Call service with degradation patterns applied."""
        start_time = time.time()
        
        # Check if service is registered
        if service_name not in self.services:
            await self.register_service(service_name)
        
        # Check load shedding
        if service_name in self.load_shedders:
            load_shedder = self.load_shedders[service_name]
            current_load = await self._calculate_current_load(service_name)
            
            if await load_shedder.should_shed_load(priority, current_load):
                await load_shedder.record_error(True)
                raise Exception(f"Request shed due to high load for service: {service_name}")
        
        # Apply bulkhead isolation if configured
        bulkhead_context = None
        if service_name in self.bulkheads:
            bulkhead_context = self.bulkheads[service_name].isolate()
        
        try:
            if bulkhead_context:
                async with bulkhead_context:
                    result = await self._execute_with_degradation(
                        service_name, operation, priority, timeout, *args, **kwargs
                    )
            else:
                result = await self._execute_with_degradation(
                    service_name, operation, priority, timeout, *args, **kwargs
                )
            
            # Record successful execution
            response_time = time.time() - start_time
            await self._record_success(service_name, response_time)
            
            return result
            
        except Exception as e:
            # Record failure and attempt fallback
            response_time = time.time() - start_time
            await self._record_failure(service_name, response_time, e)
            
            # Try fallback
            fallback_result = await self._execute_fallback(
                service_name, operation, e, *args, **kwargs
            )
            
            if fallback_result is not None:
                return fallback_result
            
            raise
    
    async def _execute_with_degradation(
        self,
        service_name: str,
        operation: Callable[..., T],
        priority: ServicePriority,
        timeout: Optional[float],
        *args,
        **kwargs
    ) -> T:
        """Execute operation with degradation considerations."""
        service_health = self.services[service_name]
        
        # Adjust timeout based on service health and priority
        if timeout is None:
            timeout = self._calculate_adaptive_timeout(service_health, priority)
        
        # Execute with timeout
        try:
            if asyncio.iscoroutinefunction(operation):
                result = await asyncio.wait_for(operation(*args, **kwargs), timeout=timeout)
            else:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, operation, *args, **kwargs),
                    timeout=timeout
                )
            return result
        except asyncio.TimeoutError:
            raise TimeoutError(f"Operation timeout for service: {service_name}")
    
    def _calculate_adaptive_timeout(
        self,
        service_health: ServiceHealth,
        priority: ServicePriority
    ) -> float:
        """Calculate adaptive timeout based on service health and priority."""
        base_timeout = 5.0
        
        # Adjust based on service health
        if service_health.avg_response_time > 0:
            # Use 3x average response time as baseline
            base_timeout = max(base_timeout, service_health.avg_response_time * 3)
        
        # Adjust based on priority
        priority_multipliers = {
            ServicePriority.CRITICAL: 2.0,
            ServicePriority.HIGH: 1.5,
            ServicePriority.MEDIUM: 1.0,
            ServicePriority.LOW: 0.8,
            ServicePriority.BEST_EFFORT: 0.5
        }
        
        return base_timeout * priority_multipliers.get(priority, 1.0)
    
    async def _execute_fallback(
        self,
        service_name: str,
        original_operation: Callable,
        error: Exception,
        *args,
        **kwargs
    ) -> Optional[Any]:
        """Execute fallback strategy for failed operation."""
        if service_name not in self.fallback_strategies:
            return None
        
        strategy = self.fallback_strategies[service_name]
        
        # Try cached response first
        if strategy.cache_enabled:
            cache_key = f"{service_name}:{hash((args, tuple(sorted(kwargs.items()))))}"
            cached_result = await self.fallback_cache.get(cache_key)
            if cached_result is not None:
                logger.info(f"Using cached fallback for {service_name}")
                return cached_result
        
        fallback_result = None
        
        # Try custom fallback function
        if strategy.fallback_func:
            try:
                if asyncio.iscoroutinefunction(strategy.fallback_func):
                    fallback_result = await asyncio.wait_for(
                        strategy.fallback_func(*args, **kwargs),
                        timeout=strategy.timeout
                    )
                else:
                    loop = asyncio.get_event_loop()
                    fallback_result = await asyncio.wait_for(
                        loop.run_in_executor(None, strategy.fallback_func, *args, **kwargs),
                        timeout=strategy.timeout
                    )
                logger.info(f"Used custom fallback for {service_name}")
            except Exception as fallback_error:
                logger.warning(f"Custom fallback failed for {service_name}: {fallback_error}")
        
        # Try redirect to another service
        if fallback_result is None and strategy.redirect_service:
            try:
                if strategy.redirect_service in self.services:
                    fallback_result = await self.call_service(
                        strategy.redirect_service,
                        original_operation,
                        *args,
                        priority=ServicePriority.LOW,
                        **kwargs
                    )
                    logger.info(f"Redirected {service_name} to {strategy.redirect_service}")
            except Exception as redirect_error:
                logger.warning(f"Service redirect failed for {service_name}: {redirect_error}")
        
        # Use static response
        if fallback_result is None and strategy.static_response is not None:
            fallback_result = strategy.static_response
            logger.info(f"Used static fallback for {service_name}")
        
        # Use degraded response
        if fallback_result is None and strategy.degraded_response is not None:
            fallback_result = strategy.degraded_response
            logger.info(f"Used degraded response for {service_name}")
        
        # Cache the fallback result
        if fallback_result is not None and strategy.cache_enabled:
            cache_key = f"{service_name}:{hash((args, tuple(sorted(kwargs.items()))))}"
            await self.fallback_cache.set(cache_key, fallback_result, strategy.cache_ttl)
        
        return fallback_result
    
    async def _record_success(self, service_name: str, response_time: float):
        """Record successful service call."""
        async with self._lock:
            service = self.services[service_name]
            
            # Update health metrics (simple exponential moving average)
            alpha = 0.1
            service.avg_response_time = (
                alpha * response_time + (1 - alpha) * service.avg_response_time
            )
            service.success_rate = alpha * 1.0 + (1 - alpha) * service.success_rate
            service.error_rate = (1 - alpha) * service.error_rate
            service.last_check = datetime.now()
            service.is_healthy = True
            
            # Update degradation level based on metrics
            service.degradation_level = self._calculate_degradation_level(service)
        
        # Record in load shedder
        if service_name in self.load_shedders:
            await self.load_shedders[service_name].record_response_time(response_time)
            await self.load_shedders[service_name].record_error(False)
    
    async def _record_failure(self, service_name: str, response_time: float, error: Exception):
        """Record failed service call."""
        async with self._lock:
            service = self.services[service_name]
            
            # Update health metrics
            alpha = 0.1
            service.avg_response_time = (
                alpha * response_time + (1 - alpha) * service.avg_response_time
            )
            service.success_rate = (1 - alpha) * service.success_rate
            service.error_rate = alpha * 1.0 + (1 - alpha) * service.error_rate
            service.last_check = datetime.now()
            
            # Determine if service is healthy
            service.is_healthy = (
                service.success_rate > 0.8 and
                service.error_rate < 0.2 and
                service.avg_response_time < 10.0
            )
            
            # Update degradation level
            service.degradation_level = self._calculate_degradation_level(service)
        
        # Record in load shedder
        if service_name in self.load_shedders:
            await self.load_shedders[service_name].record_response_time(response_time)
            await self.load_shedders[service_name].record_error(True)
        
        logger.warning(
            f"Service call failed for {service_name}: {error}, "
            f"health: success_rate={service.success_rate:.2f}, "
            f"error_rate={service.error_rate:.2f}"
        )
    
    def _calculate_degradation_level(self, service: ServiceHealth) -> DegradationLevel:
        """Calculate degradation level based on service health."""
        if service.success_rate > 0.95 and service.error_rate < 0.05:
            return DegradationLevel.NORMAL
        elif service.success_rate > 0.8 and service.error_rate < 0.2:
            return DegradationLevel.REDUCED_FUNCTIONALITY
        elif service.success_rate > 0.5 and service.error_rate < 0.5:
            return DegradationLevel.ESSENTIAL_ONLY
        elif service.success_rate > 0.1:
            return DegradationLevel.EMERGENCY_MODE
        else:
            return DegradationLevel.UNAVAILABLE
    
    async def _calculate_current_load(self, service_name: str) -> float:
        """Calculate current load for a service."""
        if service_name in self.bulkheads:
            stats = await self.bulkheads[service_name].get_stats()
            capacity_usage = 1.0 - (stats['available_capacity'] / 10)  # Assuming max 10
            return capacity_usage
        return 0.0
    
    async def get_service_status(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive status for a service."""
        if service_name not in self.services:
            return None
        
        async with self._lock:
            service = self.services[service_name]
            status = {
                'service_name': service_name,
                'is_healthy': service.is_healthy,
                'success_rate': service.success_rate,
                'error_rate': service.error_rate,
                'avg_response_time': service.avg_response_time,
                'degradation_level': service.degradation_level.value,
                'last_check': service.last_check.isoformat(),
                'has_fallback': service_name in self.fallback_strategies,
                'has_bulkhead': service_name in self.bulkheads,
                'has_load_shedding': service_name in self.load_shedders
            }
        
        # Add bulkhead stats
        if service_name in self.bulkheads:
            bulkhead_stats = await self.bulkheads[service_name].get_stats()
            status['bulkhead_stats'] = bulkhead_stats
        
        # Add load shedding stats
        if service_name in self.load_shedders:
            shedding_stats = await self.load_shedders[service_name].get_stats()
            status['load_shedding_stats'] = shedding_stats
        
        return status
    
    async def get_mesh_overview(self) -> Dict[str, Any]:
        """Get overview of entire service mesh."""
        overview = {
            'total_services': len(self.services),
            'healthy_services': 0,
            'degraded_services': 0,
            'unhealthy_services': 0,
            'services': {}
        }
        
        for service_name in self.services:
            status = await self.get_service_status(service_name)
            if status:
                overview['services'][service_name] = status
                
                if status['is_healthy']:
                    overview['healthy_services'] += 1
                elif status['degradation_level'] in ['reduced_functionality', 'essential_only']:
                    overview['degraded_services'] += 1
                else:
                    overview['unhealthy_services'] += 1
        
        return overview


# Global service mesh instance
_service_mesh = ServiceMesh()


def get_service_mesh() -> ServiceMesh:
    """Get the global service mesh instance."""
    return _service_mesh


async def with_degradation(
    service_name: str,
    operation: Callable[..., T],
    *args,
    priority: ServicePriority = ServicePriority.MEDIUM,
    fallback_strategy: Optional[FallbackStrategy] = None,
    **kwargs
) -> T:
    """Execute operation with graceful degradation patterns."""
    mesh = get_service_mesh()
    
    # Register fallback strategy if provided
    if fallback_strategy and service_name not in mesh.fallback_strategies:
        await mesh.register_service(service_name, fallback_strategy)
    
    return await mesh.call_service(
        service_name, operation, *args, priority=priority, **kwargs
    )


# Decorator for graceful degradation
def graceful_degradation(
    service_name: str,
    priority: ServicePriority = ServicePriority.MEDIUM,
    fallback_strategy: Optional[FallbackStrategy] = None
):
    """Decorator for adding graceful degradation to functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            return await with_degradation(
                service_name, func, *args,
                priority=priority,
                fallback_strategy=fallback_strategy,
                **kwargs
            )
        return wrapper
    return decorator


# Export public API
__all__ = [
    'ServicePriority',
    'DegradationLevel',
    'QualityOfService',
    'FallbackStrategy',
    'ServiceHealth',
    'LoadSheddingConfig',
    'ServiceMesh',
    'BulkheadIsolator',
    'AdaptiveLoadShedder',
    'FallbackCache',
    'get_service_mesh',
    'with_degradation',
    'graceful_degradation',
]