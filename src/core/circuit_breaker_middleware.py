"""
FastAPI middleware for circuit breaker integration.

This module provides middleware that automatically applies circuit breaker protection
to FastAPI routes and external service calls.
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from fastapi import FastAPI, HTTPException, status
from dataclasses import dataclass
import json

from src.core.circuit_breaker_standard import (
    StandardizedCircuitBreaker,
    StandardCircuitBreakerConfig,
    CircuitBreakerType,
    get_standardized_circuit_breaker,
    CircuitOpenError,
    BulkheadConfig,
    HealthCheckConfig
)
from src.core.circuit_breaker import CircuitState

logger = logging.getLogger(__name__)


@dataclass
class RouteCircuitBreakerConfig:
    """Configuration for route-level circuit breakers."""
    route_pattern: str
    service_name: str
    circuit_type: CircuitBreakerType = CircuitBreakerType.COUNT_BASED
    failure_threshold: int = 5
    timeout: float = 60.0
    failure_rate_threshold: float = 0.5
    minimum_calls: int = 10
    enabled: bool = True
    fallback_response: Optional[Dict[str, Any]] = None
    max_concurrent_requests: int = 100


class CircuitBreakerMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that applies circuit breaker protection to routes.
    
    Features:
    - Route-level circuit breaker configuration
    - Automatic fallback responses
    - Request rate limiting via bulkhead pattern
    - Health check integration
    - Metrics collection
    """
    
    def __init__(
        self,
        app: FastAPI,
        route_configs: Optional[List[RouteCircuitBreakerConfig]] = None,
        global_config: Optional[StandardCircuitBreakerConfig] = None,
        enable_health_endpoint: bool = True
    ):
        """
        Initialize circuit breaker middleware.
        
        Args:
            app: FastAPI application
            route_configs: List of route-specific configurations
            global_config: Global circuit breaker configuration
            enable_health_endpoint: Whether to add health check endpoint
        """
        super().__init__(app)
        self.route_configs = route_configs or []
        self.global_config = global_config
        self._route_breakers: Dict[str, StandardizedCircuitBreaker] = {}
        self._route_patterns: Dict[str, RouteCircuitBreakerConfig] = {}
        
        # Build route pattern mapping
        for config in self.route_configs:
            self._route_patterns[config.route_pattern] = config
            
            # Create circuit breaker for route
            breaker_config = StandardCircuitBreakerConfig(
                name=f"route_{config.service_name}",
                circuit_type=config.circuit_type,
                failure_threshold=config.failure_threshold,
                timeout=config.timeout,
                failure_rate_threshold=config.failure_rate_threshold,
                minimum_calls=config.minimum_calls,
                service_category="api_route",
                priority=2,
                bulkhead_config=BulkheadConfig(
                    max_concurrent_calls=config.max_concurrent_requests,
                    isolation_pool_name=f"route_{config.service_name}",
                    queue_timeout=5.0
                ),
                fallback=self._create_fallback_handler(config.fallback_response)
            )
            
            self._route_breakers[config.route_pattern] = StandardizedCircuitBreaker(breaker_config)
        
        # Add health check endpoint if enabled
        if enable_health_endpoint:
            self._add_health_endpoint(app)
        
        logger.info(f"Initialized circuit breaker middleware with {len(self.route_configs)} route configs")
    
    def _create_fallback_handler(self, fallback_response: Optional[Dict[str, Any]]) -> Callable:
        """Create a fallback handler for circuit breaker."""
        def fallback_handler(*args, **kwargs):
            if fallback_response:
                return fallback_response
            return {
                "error": "Service temporarily unavailable",
                "status": "circuit_breaker_open",
                "retry_after": 60
            }
        return fallback_handler
    
    def _add_health_endpoint(self, app: FastAPI):
        """Add health check endpoint for circuit breaker status."""
        @app.get("/health/circuit-breakers")
        async def circuit_breaker_health():
            """Get circuit breaker health status."""
            breaker_status = {}
            overall_health = True
            
            for pattern, breaker in self._route_breakers.items():
                state = breaker.get_state()
                metrics = breaker.get_metrics()
                
                is_healthy = state != CircuitState.OPEN
                if not is_healthy:
                    overall_health = False
                
                breaker_status[pattern] = {
                    "state": state.value,
                    "is_healthy": is_healthy,
                    "total_calls": metrics.get("total_calls", 0),
                    "failure_rate": metrics.get("failed_calls", 0) / max(1, metrics.get("total_calls", 1)),
                    "last_state_change": metrics.get("state_changes", [])[-1] if metrics.get("state_changes") else None
                }
            
            return {
                "overall_health": overall_health,
                "circuit_breakers": breaker_status,
                "timestamp": time.time()
            }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through circuit breaker protection."""
        # Find matching route configuration
        route_config = self._find_route_config(request.url.path)
        
        if not route_config or not route_config.enabled:
            # No circuit breaker configured for this route
            return await call_next(request)
        
        # Get circuit breaker for this route
        breaker = self._route_breakers.get(route_config.route_pattern)
        if not breaker:
            logger.warning(f"No circuit breaker found for route pattern: {route_config.route_pattern}")
            return await call_next(request)
        
        # Execute request through circuit breaker
        try:
            response = await breaker.call(self._execute_request, request, call_next)
            return response
            
        except CircuitOpenError as e:
            logger.warning(f"Circuit breaker open for route {request.url.path}: {e}")
            
            # Return fallback response
            fallback_data = route_config.fallback_response or {
                "error": "Service temporarily unavailable",
                "status": "circuit_breaker_open",
                "route": request.url.path,
                "retry_after": route_config.timeout
            }
            
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=fallback_data,
                headers={"Retry-After": str(int(route_config.timeout))}
            )
            
        except Exception as e:
            logger.error(f"Unexpected error in circuit breaker middleware: {e}")
            # Let the error propagate to maintain normal error handling
            raise
    
    def _find_route_config(self, path: str) -> Optional[RouteCircuitBreakerConfig]:
        """Find route configuration that matches the given path."""
        for pattern, config in self._route_patterns.items():
            if self._path_matches_pattern(path, pattern):
                return config
        return None
    
    def _path_matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches the route pattern."""
        # Simple pattern matching - can be enhanced with regex if needed
        if pattern == path:
            return True
        
        # Handle wildcard patterns
        if "*" in pattern:
            pattern_parts = pattern.split("*")
            if len(pattern_parts) == 2:
                prefix, suffix = pattern_parts
                return path.startswith(prefix) and path.endswith(suffix)
        
        # Handle path parameters (FastAPI style)
        if "{" in pattern and "}" in pattern:
            pattern_normalized = pattern
            # Replace {param} with placeholder for matching
            import re
            pattern_normalized = re.sub(r'\{[^}]+\}', '[^/]+', pattern)
            pattern_normalized = f"^{pattern_normalized}$"
            return bool(re.match(pattern_normalized, path))
        
        return False
    
    async def _execute_request(self, request: Request, call_next: Callable) -> Response:
        """Execute the actual request."""
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Consider 5xx responses as failures
            if response.status_code >= 500:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Server error: {response.status_code}"
                )
            
            return response
            
        except Exception as e:
            # Log request details for debugging
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"(duration: {duration:.3f}s, error: {e})"
            )
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics for all route circuit breakers."""
        metrics = {
            "total_routes": len(self._route_breakers),
            "routes": {}
        }
        
        for pattern, breaker in self._route_breakers.items():
            metrics["routes"][pattern] = breaker.get_metrics()
        
        return metrics


class ExternalServiceCircuitBreakerManager:
    """
    Manager for external service circuit breakers in FastAPI context.
    
    Provides easy integration for protecting external service calls.
    """
    
    def __init__(self):
        self._service_breakers: Dict[str, StandardizedCircuitBreaker] = {}
        self._service_configs: Dict[str, Dict[str, Any]] = {}
    
    def register_service(
        self,
        service_name: str,
        base_url: str,
        circuit_type: CircuitBreakerType = CircuitBreakerType.TIME_BASED,
        config_overrides: Optional[Dict[str, Any]] = None
    ) -> StandardizedCircuitBreaker:
        """
        Register an external service with circuit breaker protection.
        
        Args:
            service_name: Name of the service
            base_url: Base URL of the service
            circuit_type: Type of circuit breaker to use
            config_overrides: Custom configuration overrides
        
        Returns:
            Configured circuit breaker
        """
        # Create configuration
        config = StandardCircuitBreakerConfig(
            name=f"external_{service_name}",
            circuit_type=circuit_type,
            failure_threshold=5,
            timeout=60.0,
            failure_rate_threshold=0.5,
            minimum_calls=10,
            service_category="external",
            priority=3,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=20,
                isolation_pool_name=f"external_{service_name}",
                queue_timeout=10.0
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=60.0,
                health_check_timeout=10.0,
                health_check_url=f"{base_url}/health" if base_url.endswith('/') else f"{base_url}/health"
            )
        )
        
        # Apply overrides
        if config_overrides:
            for key, value in config_overrides.items():
                if hasattr(config, key):
                    setattr(config, key, value)
        
        # Create and register circuit breaker
        breaker = StandardizedCircuitBreaker(config)
        self._service_breakers[service_name] = breaker
        self._service_configs[service_name] = {
            "base_url": base_url,
            "circuit_type": circuit_type.value,
            "config": config
        }
        
        logger.info(f"Registered external service '{service_name}' with circuit breaker")
        return breaker
    
    def get_service_breaker(self, service_name: str) -> Optional[StandardizedCircuitBreaker]:
        """Get circuit breaker for a service."""
        return self._service_breakers.get(service_name)
    
    async def call_service(
        self,
        service_name: str,
        request_func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Call external service through circuit breaker protection.
        
        Args:
            service_name: Name of the registered service
            request_func: Function that makes the actual request
            *args: Arguments for request function
            **kwargs: Keyword arguments for request function
        
        Returns:
            Response from the service
        
        Raises:
            CircuitOpenError: If circuit breaker is open
            Exception: Any exception from the request function
        """
        breaker = self._service_breakers.get(service_name)
        if not breaker:
            raise ValueError(f"Service '{service_name}' not registered")
        
        return await breaker.call(request_func, *args, **kwargs)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all registered services."""
        return {
            service_name: breaker.get_metrics()
            for service_name, breaker in self._service_breakers.items()
        }


# Global instance for external service management
_external_service_manager = ExternalServiceCircuitBreakerManager()


def get_external_service_manager() -> ExternalServiceCircuitBreakerManager:
    """Get the global external service circuit breaker manager."""
    return _external_service_manager


def setup_fastapi_circuit_breakers(
    app: FastAPI,
    route_configs: Optional[List[RouteCircuitBreakerConfig]] = None,
    enable_default_routes: bool = True
) -> CircuitBreakerMiddleware:
    """
    Set up circuit breaker middleware for FastAPI application.
    
    Args:
        app: FastAPI application instance
        route_configs: Custom route configurations
        enable_default_routes: Whether to enable default route protections
    
    Returns:
        Configured middleware instance
    """
    # Default route configurations for common patterns
    default_configs = []
    if enable_default_routes:
        default_configs = [
            RouteCircuitBreakerConfig(
                route_pattern="/api/v1/query/*",
                service_name="query_handler",
                circuit_type=CircuitBreakerType.ADAPTIVE,
                failure_threshold=3,
                timeout=30.0,
                max_concurrent_requests=50,
                fallback_response={
                    "error": "Query service temporarily unavailable",
                    "status": "circuit_breaker_open"
                }
            ),
            RouteCircuitBreakerConfig(
                route_pattern="/api/v1/experts/*",
                service_name="experts",
                circuit_type=CircuitBreakerType.COUNT_BASED,
                failure_threshold=5,
                timeout=60.0,
                max_concurrent_requests=30,
                fallback_response={
                    "error": "Expert services temporarily unavailable",
                    "status": "circuit_breaker_open"
                }
            ),
            RouteCircuitBreakerConfig(
                route_pattern="/api/v1/mcp/*",
                service_name="mcp_services",
                circuit_type=CircuitBreakerType.PERCENTAGE_BASED,
                failure_threshold=3,
                timeout=45.0,
                failure_rate_threshold=0.4,
                max_concurrent_requests=20,
                fallback_response={
                    "error": "MCP services temporarily unavailable",
                    "status": "circuit_breaker_open"
                }
            )
        ]
    
    # Combine default and custom configurations
    all_configs = default_configs + (route_configs or [])
    
    # Create and add middleware
    middleware = CircuitBreakerMiddleware(app, all_configs)
    app.add_middleware(CircuitBreakerMiddleware, app=app, route_configs=all_configs)
    
    logger.info(f"Set up FastAPI circuit breaker middleware with {len(all_configs)} route configurations")
    return middleware


# Convenience decorators for external service calls
def external_service_call(service_name: str):
    """
    Decorator for external service calls with circuit breaker protection.
    
    Usage:
        @external_service_call("payment_service")
        async def process_payment(amount: float):
            # This call will be protected by circuit breaker
            return await payment_api.charge(amount)
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            manager = get_external_service_manager()
            return await manager.call_service(service_name, func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


# Export public API
__all__ = [
    'CircuitBreakerMiddleware',
    'ExternalServiceCircuitBreakerManager',
    'RouteCircuitBreakerConfig',
    'setup_fastapi_circuit_breakers',
    'get_external_service_manager',
    'external_service_call',
]