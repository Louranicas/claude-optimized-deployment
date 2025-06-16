"""API configuration and settings management."""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class APIClientConfig:
    """Configuration for individual API clients."""
    api_key: str
    base_url: str
    max_retries: int = 3
    timeout: int = 30
    cache_ttl: int = 300
    rate_limit_requests: Optional[int] = None
    rate_limit_window: Optional[int] = None
    circuit_breaker_enabled: bool = True
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60


@dataclass
class APIManagerConfig:
    """Configuration for the unified API manager."""
    enable_fallbacks: bool = True
    max_concurrent_requests: int = 10
    default_cache_ttl: int = 300
    health_check_interval: int = 300  # 5 minutes
    
    # Client configurations
    tavily: Optional[APIClientConfig] = None
    smithery: Optional[APIClientConfig] = None
    brave: Optional[APIClientConfig] = None


class APIConfigManager:
    """Manages API configuration from environment variables and files."""
    
    # Environment variable names
    ENV_VARS = {
        'tavily_api_key': 'TAVILY_API_KEY',
        'smithery_api_key': 'SMITHERY_API_KEY',
        'brave_api_key': 'BRAVE_API_KEY',
        'enable_fallbacks': 'API_ENABLE_FALLBACKS',
        'max_concurrent_requests': 'API_MAX_CONCURRENT_REQUESTS',
        'default_cache_ttl': 'API_DEFAULT_CACHE_TTL'
    }
    
    # Default configurations for each service
    DEFAULT_CONFIGS = {
        'tavily': {
            'base_url': 'https://api.tavily.com',
            'timeout': 30,
            'cache_ttl': 600,  # 10 minutes for search results
            'rate_limit_requests': 50,
            'rate_limit_window': 60,
            'circuit_breaker_failure_threshold': 5
        },
        'smithery': {
            'base_url': 'https://api.smithery.ai',
            'timeout': 60,  # Longer timeout for AI processing
            'cache_ttl': 1800,  # 30 minutes for AI results
            'rate_limit_requests': 30,
            'rate_limit_window': 60,
            'circuit_breaker_failure_threshold': 3
        },
        'brave': {
            'base_url': 'https://api.search.brave.com',
            'timeout': 30,
            'cache_ttl': 600,  # 10 minutes for search results
            'rate_limit_requests': 100,
            'rate_limit_window': 60,
            'circuit_breaker_failure_threshold': 5
        }
    }
    
    @classmethod
    def from_environment(cls) -> APIManagerConfig:
        """Create configuration from environment variables."""
        # Get API keys
        tavily_key = os.getenv(cls.ENV_VARS['tavily_api_key'])
        smithery_key = os.getenv(cls.ENV_VARS['smithery_api_key'])
        brave_key = os.getenv(cls.ENV_VARS['brave_api_key'])
        
        # Create client configurations
        tavily_config = None
        if tavily_key:
            tavily_config = APIClientConfig(
                api_key=tavily_key,
                **cls.DEFAULT_CONFIGS['tavily']
            )
        
        smithery_config = None
        if smithery_key:
            smithery_config = APIClientConfig(
                api_key=smithery_key,
                **cls.DEFAULT_CONFIGS['smithery']
            )
        
        brave_config = None
        if brave_key:
            brave_config = APIClientConfig(
                api_key=brave_key,
                **cls.DEFAULT_CONFIGS['brave']
            )
        
        # Manager configuration
        enable_fallbacks = os.getenv(cls.ENV_VARS['enable_fallbacks'], 'true').lower() == 'true'
        max_concurrent = int(os.getenv(cls.ENV_VARS['max_concurrent_requests'], '10'))
        default_cache_ttl = int(os.getenv(cls.ENV_VARS['default_cache_ttl'], '300'))
        
        return APIManagerConfig(
            enable_fallbacks=enable_fallbacks,
            max_concurrent_requests=max_concurrent,
            default_cache_ttl=default_cache_ttl,
            tavily=tavily_config,
            smithery=smithery_config,
            brave=brave_config
        )
    
    @classmethod
    def from_dict(cls, config_dict: Dict) -> APIManagerConfig:
        """Create configuration from dictionary."""
        # Create client configurations
        tavily_config = None
        if 'tavily' in config_dict and config_dict['tavily'].get('api_key'):
            tavily_data = {**cls.DEFAULT_CONFIGS['tavily'], **config_dict['tavily']}
            tavily_config = APIClientConfig(**tavily_data)
        
        smithery_config = None
        if 'smithery' in config_dict and config_dict['smithery'].get('api_key'):
            smithery_data = {**cls.DEFAULT_CONFIGS['smithery'], **config_dict['smithery']}
            smithery_config = APIClientConfig(**smithery_data)
        
        brave_config = None
        if 'brave' in config_dict and config_dict['brave'].get('api_key'):
            brave_data = {**cls.DEFAULT_CONFIGS['brave'], **config_dict['brave']}
            brave_config = APIClientConfig(**brave_data)
        
        # Manager configuration
        manager_config = APIManagerConfig(
            enable_fallbacks=config_dict.get('enable_fallbacks', True),
            max_concurrent_requests=config_dict.get('max_concurrent_requests', 10),
            default_cache_ttl=config_dict.get('default_cache_ttl', 300),
            tavily=tavily_config,
            smithery=smithery_config,
            brave=brave_config
        )
        
        return manager_config
    
    @classmethod
    def get_test_config(cls) -> APIManagerConfig:
        """Get configuration for testing with provided API keys."""
        test_config = {
            'tavily': {
                'api_key': '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',
                'cache_ttl': 60,  # Shorter cache for testing
                'rate_limit_requests': 10,  # Lower limits for testing
                'rate_limit_window': 60
            },
            'smithery': {
                'api_key': '85861ba2-5eba-4599-b38d-61f4b3df44a7',
                'cache_ttl': 60,
                'rate_limit_requests': 5,
                'rate_limit_window': 60
            },
            'brave': {
                'api_key': 'BSAigVAUU4-V72PjB48t8_CqN00Hh5z',
                'cache_ttl': 60,
                'rate_limit_requests': 20,
                'rate_limit_window': 60
            },
            'enable_fallbacks': True,
            'max_concurrent_requests': 5,
            'default_cache_ttl': 60
        }
        
        return cls.from_dict(test_config)
    
    @classmethod
    def validate_config(cls, config: APIManagerConfig) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Check if at least one client is configured
        if not any([config.tavily, config.smithery, config.brave]):
            issues.append("No API clients configured")
        
        # Validate individual client configurations
        for client_name, client_config in [
            ('tavily', config.tavily),
            ('smithery', config.smithery),
            ('brave', config.brave)
        ]:
            if client_config:
                if not client_config.api_key:
                    issues.append(f"{client_name}: API key is required")
                
                if not client_config.base_url:
                    issues.append(f"{client_name}: Base URL is required")
                
                if client_config.timeout <= 0:
                    issues.append(f"{client_name}: Timeout must be positive")
                
                if client_config.max_retries < 0:
                    issues.append(f"{client_name}: Max retries cannot be negative")
                
                if client_config.cache_ttl < 0:
                    issues.append(f"{client_name}: Cache TTL cannot be negative")
        
        # Validate manager configuration
        if config.max_concurrent_requests <= 0:
            issues.append("Max concurrent requests must be positive")
        
        if config.default_cache_ttl < 0:
            issues.append("Default cache TTL cannot be negative")
        
        return issues


# Convenience function to get configuration
def get_api_config() -> APIManagerConfig:
    """Get API configuration from environment or return test config."""
    try:
        # Try to load from environment first
        config = APIConfigManager.from_environment()
        
        # If no API keys found in environment, use test config
        if not any([config.tavily, config.smithery, config.brave]):
            config = APIConfigManager.get_test_config()
        
        # Validate configuration
        issues = APIConfigManager.validate_config(config)
        if issues:
            raise ValueError(f"Configuration validation failed: {'; '.join(issues)}")
        
        return config
        
    except Exception as e:
        # Fallback to test config
        return APIConfigManager.get_test_config()