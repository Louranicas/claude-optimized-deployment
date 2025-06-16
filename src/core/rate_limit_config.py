"""
Rate Limiting Configuration

This module provides configuration management for rate limiting rules
across different endpoints and user types.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .rate_limiter import RateLimitAlgorithm, RateLimitConfig, RateLimitScope


@dataclass
class EndpointRateLimitConfig:
    """Rate limiting configuration for a specific endpoint."""
    endpoint_pattern: str
    configs: List[RateLimitConfig] = field(default_factory=list)
    description: str = ""
    
    def add_config(
        self,
        requests: int,
        window: int,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
        scope: RateLimitScope = RateLimitScope.PER_IP,
        burst: Optional[int] = None
    ):
        """Add a rate limit configuration to this endpoint."""
        config = RateLimitConfig(
            requests=requests,
            window=window,
            algorithm=algorithm,
            scope=scope,
            burst=burst
        )
        self.configs.append(config)


class RateLimitingConfig:
    """Central configuration for rate limiting."""
    
    def __init__(self):
        self.endpoint_configs: List[EndpointRateLimitConfig] = []
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.redis_pool_size = int(os.getenv('REDIS_POOL_SIZE', '20'))
        self.default_enabled = os.getenv('RATE_LIMITING_ENABLED', 'true').lower() == 'true'
    
    def configure_defaults(self):
        """Configure default rate limiting rules for common endpoints."""
        
        # Authentication endpoints - stricter limits
        auth_config = EndpointRateLimitConfig(
            endpoint_pattern="POST:/auth/*",
            description="Authentication endpoints - prevent brute force attacks"
        )
        # Very strict per-IP limit for auth
        auth_config.add_config(
            requests=5, window=60, 
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        # Slightly more lenient per-user limit for legitimate retries
        auth_config.add_config(
            requests=10, window=300,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        self.endpoint_configs.append(auth_config)
        
        # API endpoints - moderate limits with burst support
        api_config = EndpointRateLimitConfig(
            endpoint_pattern="*:/api/*",
            description="General API endpoints - balanced limits for normal usage"
        )
        # Per-IP limits with burst capability
        api_config.add_config(
            requests=100, window=60, burst=150,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            scope=RateLimitScope.PER_IP
        )
        # Per-user limits for authenticated requests
        api_config.add_config(
            requests=500, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        # Global rate limit to protect infrastructure
        api_config.add_config(
            requests=10000, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.GLOBAL
        )
        self.endpoint_configs.append(api_config)
        
        # Circle of Experts endpoints - higher limits for AI processing
        experts_config = EndpointRateLimitConfig(
            endpoint_pattern="POST:/circle-of-experts/*",
            description="AI processing endpoints - higher limits for complex queries"
        )
        # Per-user limits for authenticated AI requests
        experts_config.add_config(
            requests=50, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        # Per-IP limits to prevent abuse
        experts_config.add_config(
            requests=20, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        # Daily limits for expensive operations
        experts_config.add_config(
            requests=1000, window=86400,  # 24 hours
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        self.endpoint_configs.append(experts_config)
        
        # File upload endpoints - strict limits due to resource usage
        upload_config = EndpointRateLimitConfig(
            endpoint_pattern="POST:/upload/*",
            description="File upload endpoints - strict limits for resource protection"
        )
        upload_config.add_config(
            requests=10, window=300,  # 5 minutes
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        upload_config.add_config(
            requests=50, window=3600,  # 1 hour
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        self.endpoint_configs.append(upload_config)
        
        # Search endpoints - moderate limits with burst
        search_config = EndpointRateLimitConfig(
            endpoint_pattern="GET:/search/*",
            description="Search endpoints - burst-friendly for user interaction"
        )
        search_config.add_config(
            requests=60, window=60, burst=100,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            scope=RateLimitScope.PER_IP
        )
        search_config.add_config(
            requests=300, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        self.endpoint_configs.append(search_config)
        
        # Health check endpoints - very permissive
        health_config = EndpointRateLimitConfig(
            endpoint_pattern="GET:/health",
            description="Health check endpoints - permissive for monitoring"
        )
        health_config.add_config(
            requests=1000, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.GLOBAL
        )
        self.endpoint_configs.append(health_config)
        
        # WebSocket connections - connection-based limits
        websocket_config = EndpointRateLimitConfig(
            endpoint_pattern="*/ws/*",
            description="WebSocket endpoints - connection establishment limits"
        )
        websocket_config.add_config(
            requests=10, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        websocket_config.add_config(
            requests=50, window=300,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        self.endpoint_configs.append(websocket_config)
    
    def configure_development(self):
        """Configure lenient rate limits for development environment."""
        # Clear existing configs
        self.endpoint_configs = []
        
        # Very permissive development limits
        dev_config = EndpointRateLimitConfig(
            endpoint_pattern="*",
            description="Development - very permissive limits"
        )
        dev_config.add_config(
            requests=1000, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_IP
        )
        self.endpoint_configs.append(dev_config)
    
    def configure_production(self):
        """Configure strict rate limits for production environment."""
        # Use defaults which are production-ready
        self.configure_defaults()
        
        # Add additional strict global limits
        global_config = EndpointRateLimitConfig(
            endpoint_pattern="*",
            description="Production global limits"
        )
        global_config.add_config(
            requests=50000, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.GLOBAL
        )
        self.endpoint_configs.append(global_config)
    
    def configure_testing(self):
        """Configure minimal rate limits for testing."""
        # Clear existing configs
        self.endpoint_configs = []
        
        # Minimal testing limits
        test_config = EndpointRateLimitConfig(
            endpoint_pattern="*",
            description="Testing - minimal limits"
        )
        test_config.add_config(
            requests=10000, window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.GLOBAL
        )
        self.endpoint_configs.append(test_config)
    
    def add_custom_endpoint(self, config: EndpointRateLimitConfig):
        """Add a custom endpoint configuration."""
        self.endpoint_configs.append(config)
    
    def get_endpoint_configs(self) -> Dict[str, List[RateLimitConfig]]:
        """Get all endpoint configurations as a dictionary."""
        return {
            config.endpoint_pattern: config.configs
            for config in self.endpoint_configs
        }
    
    def apply_environment_config(self, environment: str = None):
        """Apply configuration based on environment."""
        env = environment or os.getenv('ENVIRONMENT', 'development').lower()
        
        if env == 'production':
            self.configure_production()
        elif env == 'testing':
            self.configure_testing()
        else:
            self.configure_development()


# Predefined configurations for different user tiers
class UserTierConfig:
    """Rate limiting configurations for different user tiers."""
    
    @staticmethod
    def free_tier() -> List[RateLimitConfig]:
        """Rate limits for free tier users."""
        return [
            RateLimitConfig(
                requests=100, window=3600,  # 100 requests per hour
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_USER
            ),
            RateLimitConfig(
                requests=10, window=60,  # 10 requests per minute
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_USER
            )
        ]
    
    @staticmethod
    def premium_tier() -> List[RateLimitConfig]:
        """Rate limits for premium tier users."""
        return [
            RateLimitConfig(
                requests=1000, window=3600,  # 1000 requests per hour
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_USER
            ),
            RateLimitConfig(
                requests=50, window=60, burst=100,  # 50 requests per minute with burst
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.PER_USER
            )
        ]
    
    @staticmethod
    def enterprise_tier() -> List[RateLimitConfig]:
        """Rate limits for enterprise tier users."""
        return [
            RateLimitConfig(
                requests=10000, window=3600,  # 10k requests per hour
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_USER
            ),
            RateLimitConfig(
                requests=200, window=60, burst=500,  # 200 requests per minute with large burst
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.PER_USER
            )
        ]


# Global configuration instance
_global_config: Optional[RateLimitingConfig] = None


def get_rate_limiting_config() -> RateLimitingConfig:
    """Get global rate limiting configuration."""
    global _global_config
    if _global_config is None:
        _global_config = RateLimitingConfig()
        _global_config.apply_environment_config()
    return _global_config


def initialize_rate_limiting_config(environment: str = None) -> RateLimitingConfig:
    """Initialize global rate limiting configuration."""
    global _global_config
    _global_config = RateLimitingConfig()
    _global_config.apply_environment_config(environment)
    return _global_config