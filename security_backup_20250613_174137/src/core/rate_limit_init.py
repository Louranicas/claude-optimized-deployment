"""
Rate Limiting Initialization

This module handles the initialization and setup of the distributed
rate limiting system for the application.
"""

import asyncio
import logging
import os
from typing import Optional

from fastapi import FastAPI

from .rate_limiter import (
    DistributedRateLimiter,
    initialize_rate_limiter,
    close_rate_limiter
)
from .rate_limit_config import (
    initialize_rate_limiting_config,
    get_rate_limiting_config
)
from .rate_limit_middleware import RateLimitMiddleware
from .rate_limit_monitoring import RateLimitMonitor

logger = logging.getLogger(__name__)


class RateLimitingSetup:
    """Handles the complete setup of rate limiting for the application."""
    
    def __init__(self):
        self.rate_limiter: Optional[DistributedRateLimiter] = None
        self.monitor: Optional[RateLimitMonitor] = None
        self.initialized = False
    
    async def initialize(
        self,
        redis_url: Optional[str] = None,
        environment: Optional[str] = None,
        enable_monitoring: bool = True
    ):
        """Initialize the rate limiting system."""
        try:
            # Get Redis URL from environment if not provided
            redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            environment = environment or os.getenv('ENVIRONMENT', 'development')
            
            logger.info(f"Initializing rate limiting system for {environment} environment")
            
            # Initialize rate limiting configuration
            config = initialize_rate_limiting_config(environment)
            logger.info(f"Rate limiting configuration initialized with {len(config.endpoint_configs)} endpoint rules")
            
            # Initialize the distributed rate limiter
            await initialize_rate_limiter(redis_url)
            self.rate_limiter = DistributedRateLimiter(redis_url)
            await self.rate_limiter.initialize()
            
            # Apply endpoint configurations
            endpoint_configs = config.get_endpoint_configs()
            for endpoint_pattern, configs in endpoint_configs.items():
                self.rate_limiter.configure_endpoint(endpoint_pattern, configs)
                logger.debug(f"Configured rate limiting for {endpoint_pattern}")
            
            # Initialize monitoring if enabled
            if enable_monitoring:
                self.monitor = RateLimitMonitor(self.rate_limiter.redis)
                await self.monitor.start()
                logger.info("Rate limiting monitoring started")
            
            self.initialized = True
            logger.info("Rate limiting system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize rate limiting system: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown the rate limiting system."""
        try:
            if self.monitor:
                await self.monitor.stop()
                logger.info("Rate limiting monitoring stopped")
            
            if self.rate_limiter:
                await self.rate_limiter.close()
                logger.info("Rate limiter closed")
            
            await close_rate_limiter()
            
            self.initialized = False
            logger.info("Rate limiting system shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during rate limiting shutdown: {e}")
    
    def add_middleware_to_app(
        self,
        app: FastAPI,
        skip_paths: Optional[list] = None,
        enable_headers: bool = True
    ):
        """Add rate limiting middleware to FastAPI app."""
        if not self.initialized:
            raise RuntimeError("Rate limiting system not initialized")
        
        skip_paths = skip_paths or [
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
            "/redoc"
        ]
        
        app.add_middleware(
            RateLimitMiddleware,
            rate_limiter=self.rate_limiter,
            skip_paths=skip_paths,
            enable_headers=enable_headers
        )
        
        logger.info(f"Rate limiting middleware added to FastAPI app (skipping {len(skip_paths)} paths)")
    
    async def health_check(self) -> dict:
        """Perform health check on rate limiting system."""
        if not self.initialized:
            return {
                "status": "not_initialized",
                "error": "Rate limiting system not initialized"
            }
        
        try:
            # Check rate limiter health
            metrics = await self.rate_limiter.get_metrics()
            redis_healthy = metrics.get("redis_info", {}).get("connected", False)
            
            # Check monitor health if enabled
            monitor_status = "disabled"
            if self.monitor:
                try:
                    real_time_stats = await self.monitor.get_real_time_stats()
                    monitor_status = "healthy" if "error" not in real_time_stats else "error"
                except Exception:
                    monitor_status = "error"
            
            return {
                "status": "healthy" if redis_healthy else "degraded",
                "redis_connected": redis_healthy,
                "monitor_status": monitor_status,
                "configured_endpoints": len(self.rate_limiter.endpoint_configs),
                "global_metrics": metrics.get("global_metrics", {})
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }


# Global setup instance
_rate_limiting_setup: Optional[RateLimitingSetup] = None


def get_rate_limiting_setup() -> RateLimitingSetup:
    """Get the global rate limiting setup instance."""
    global _rate_limiting_setup
    if _rate_limiting_setup is None:
        _rate_limiting_setup = RateLimitingSetup()
    return _rate_limiting_setup


async def initialize_rate_limiting_for_app(
    app: FastAPI,
    redis_url: Optional[str] = None,
    environment: Optional[str] = None,
    enable_monitoring: bool = True,
    skip_paths: Optional[list] = None,
    enable_headers: bool = True
):
    """
    Complete initialization of rate limiting for a FastAPI application.
    
    Args:
        app: FastAPI application instance
        redis_url: Redis connection URL
        environment: Environment name (development, production, testing)
        enable_monitoring: Whether to enable rate limiting monitoring
        skip_paths: List of paths to skip rate limiting
        enable_headers: Whether to add rate limit headers to responses
    """
    setup = get_rate_limiting_setup()
    
    # Initialize the system
    await setup.initialize(
        redis_url=redis_url,
        environment=environment,
        enable_monitoring=enable_monitoring
    )
    
    # Add middleware to app
    setup.add_middleware_to_app(
        app=app,
        skip_paths=skip_paths,
        enable_headers=enable_headers
    )
    
    # Add shutdown handler
    @app.on_event("shutdown")
    async def shutdown_rate_limiting():
        await setup.shutdown()
    
    return setup


def configure_custom_rate_limits(custom_configs: dict):
    """
    Configure custom rate limits for specific endpoints.
    
    Args:
        custom_configs: Dictionary mapping endpoint patterns to rate limit configs
    """
    setup = get_rate_limiting_setup()
    if not setup.initialized:
        raise RuntimeError("Rate limiting system not initialized")
    
    for endpoint_pattern, configs in custom_configs.items():
        setup.rate_limiter.configure_endpoint(endpoint_pattern, configs)
        logger.info(f"Applied custom rate limiting configuration for {endpoint_pattern}")


async def setup_production_rate_limiting(app: FastAPI):
    """Setup rate limiting optimized for production environment."""
    return await initialize_rate_limiting_for_app(
        app=app,
        environment="production",
        enable_monitoring=True,
        skip_paths=[
            "/health",
            "/metrics", 
            "/docs",
            "/openapi.json",
            "/redoc",
            "/static"
        ],
        enable_headers=True
    )


async def setup_development_rate_limiting(app: FastAPI):
    """Setup rate limiting optimized for development environment."""
    return await initialize_rate_limiting_for_app(
        app=app,
        environment="development",
        enable_monitoring=False,  # Disabled for development
        skip_paths=[
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/static",
            "/debug"
        ],
        enable_headers=True
    )


async def setup_testing_rate_limiting(app: FastAPI):
    """Setup rate limiting optimized for testing environment."""
    return await initialize_rate_limiting_for_app(
        app=app,
        environment="testing",
        enable_monitoring=False,
        skip_paths=[
            "/health",
            "/metrics",
            "/test"
        ],
        enable_headers=False  # Simplify testing
    )


# Configuration templates for common scenarios
PRODUCTION_RATE_LIMITS = {
    # Authentication endpoints - very strict
    "POST:/auth/login": [
        {
            "requests": 5,
            "window": 300,  # 5 minutes
            "algorithm": "fixed_window",
            "scope": "per_ip"
        },
        {
            "requests": 10,
            "window": 3600,  # 1 hour
            "algorithm": "sliding_window",
            "scope": "per_ip"
        }
    ],
    
    # API endpoints - moderate limits
    "*/api/*": [
        {
            "requests": 1000,
            "window": 3600,  # 1 hour
            "algorithm": "sliding_window",
            "scope": "per_user"
        },
        {
            "requests": 100,
            "window": 60,  # 1 minute
            "algorithm": "token_bucket",
            "scope": "per_ip",
            "burst": 150
        }
    ],
    
    # File upload endpoints - strict due to resource usage
    "POST:/upload/*": [
        {
            "requests": 10,
            "window": 300,  # 5 minutes
            "algorithm": "fixed_window",
            "scope": "per_ip"
        }
    ]
}

DEVELOPMENT_RATE_LIMITS = {
    # Very permissive for development
    "*": [
        {
            "requests": 10000,
            "window": 3600,
            "algorithm": "sliding_window",
            "scope": "global"
        }
    ]
}

TESTING_RATE_LIMITS = {
    # Minimal limits for testing
    "*": [
        {
            "requests": 1000000,
            "window": 3600,
            "algorithm": "sliding_window",
            "scope": "global"
        }
    ]
}