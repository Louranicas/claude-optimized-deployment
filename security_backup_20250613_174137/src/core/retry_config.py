"""
Retry configuration management and validation.

This module provides:
- Configuration loading from files and environment
- Validation of retry configurations
- Dynamic configuration updates
- Configuration templates for common scenarios
"""

import json
import logging
import os
import yaml
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.core.retry_patterns import (
    RetryPolicyConfig, RetryBudgetConfig, ServiceType, RetryStrategy, RetryBudgetType
)

logger = logging.getLogger(__name__)


@dataclass
class GlobalRetryConfig:
    """Global retry configuration settings."""
    enable_global_metrics: bool = True
    metrics_export_interval: int = 300  # seconds
    max_concurrent_retries_global: int = 100
    default_timeout: float = 300.0
    enable_debug_logging: bool = False
    circuit_breaker_enabled_globally: bool = True
    retry_budget_enabled_globally: bool = True
    idempotency_enabled_globally: bool = True
    
    # Redis configuration for distributed features
    redis_host: Optional[str] = None
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_db: int = 0
    
    # Monitoring and alerting
    prometheus_enabled: bool = False
    prometheus_port: int = 8000
    alert_on_high_failure_rate: bool = True
    failure_rate_threshold: float = 0.5
    
    # Rate limiting
    global_rate_limit_enabled: bool = True
    max_retries_per_minute_global: int = 1000
    max_retries_per_hour_global: int = 10000


class RetryConfigValidator:
    """Validator for retry configurations."""
    
    @staticmethod
    def validate_policy_config(config: RetryPolicyConfig) -> List[str]:
        """Validate retry policy configuration."""
        errors = []
        
        # Basic validation
        if config.max_attempts < 1:
            errors.append("max_attempts must be at least 1")
        
        if config.max_attempts > 20:
            errors.append("max_attempts should not exceed 20 to prevent excessive load")
        
        if config.base_delay < 0:
            errors.append("base_delay cannot be negative")
        
        if config.max_delay < config.base_delay:
            errors.append("max_delay must be greater than or equal to base_delay")
        
        if config.timeout < 0:
            errors.append("timeout cannot be negative")
        
        if config.backoff_multiplier < 1:
            errors.append("backoff_multiplier must be at least 1")
        
        if config.jitter_factor < 0 or config.jitter_factor > 1:
            errors.append("jitter_factor must be between 0 and 1")
        
        # Advanced validation
        if config.max_delay > 300:  # 5 minutes
            errors.append("max_delay exceeds recommended maximum of 300 seconds")
        
        if config.max_attempts > 10 and config.strategy == RetryStrategy.EXPONENTIAL:
            errors.append("High max_attempts with exponential strategy may cause very long delays")
        
        return errors
    
    @staticmethod
    def validate_budget_config(config: RetryBudgetConfig) -> List[str]:
        """Validate retry budget configuration."""
        errors = []
        
        if config.max_retries_per_minute < 1:
            errors.append("max_retries_per_minute must be at least 1")
        
        if config.max_retries_per_hour < config.max_retries_per_minute:
            errors.append("max_retries_per_hour must be at least max_retries_per_minute")
        
        if config.burst_capacity < 1:
            errors.append("burst_capacity must be at least 1")
        
        if config.refill_rate <= 0:
            errors.append("refill_rate must be positive")
        
        if config.adaptive_threshold < 0 or config.adaptive_threshold > 1:
            errors.append("adaptive_threshold must be between 0 and 1")
        
        return errors
    
    @staticmethod
    def validate_global_config(config: GlobalRetryConfig) -> List[str]:
        """Validate global retry configuration."""
        errors = []
        
        if config.metrics_export_interval < 60:
            errors.append("metrics_export_interval should be at least 60 seconds")
        
        if config.max_concurrent_retries_global < 1:
            errors.append("max_concurrent_retries_global must be at least 1")
        
        if config.default_timeout < 1:
            errors.append("default_timeout must be at least 1 second")
        
        if config.failure_rate_threshold < 0 or config.failure_rate_threshold > 1:
            errors.append("failure_rate_threshold must be between 0 and 1")
        
        if config.redis_port < 1 or config.redis_port > 65535:
            errors.append("redis_port must be a valid port number")
        
        if config.prometheus_port < 1 or config.prometheus_port > 65535:
            errors.append("prometheus_port must be a valid port number")
        
        return errors


class RetryConfigManager:
    """Manager for retry configurations."""
    
    def __init__(self):
        """Initialize configuration manager."""
        self.global_config = GlobalRetryConfig()
        self.service_configs: Dict[str, RetryPolicyConfig] = {}
        self.config_templates: Dict[str, RetryPolicyConfig] = {}
        self._initialize_templates()
    
    def _initialize_templates(self):
        """Initialize configuration templates."""
        # AI Services template
        self.config_templates["ai_service"] = RetryPolicyConfig(
            max_attempts=5,
            base_delay=2.0,
            max_delay=60.0,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            backoff_multiplier=2.0,
            jitter_factor=0.1,
            timeout=120.0,
            retryable_status_codes={408, 429, 500, 502, 503, 504},
            enable_circuit_breaker=True,
            enable_retry_budget=True,
            enable_idempotency=True,
            service_type=ServiceType.AI_CLAUDE
        )
        
        # Database template
        self.config_templates["database"] = RetryPolicyConfig(
            max_attempts=3,
            base_delay=0.5,
            max_delay=5.0,
            strategy=RetryStrategy.LINEAR,
            backoff_multiplier=1.5,
            timeout=30.0,
            enable_circuit_breaker=True,
            enable_retry_budget=True,
            enable_idempotency=False,
            service_type=ServiceType.DATABASE
        )
        
        # Cache template
        self.config_templates["cache"] = RetryPolicyConfig(
            max_attempts=2,
            base_delay=0.1,
            max_delay=1.0,
            strategy=RetryStrategy.FIXED,
            timeout=5.0,
            enable_circuit_breaker=False,
            enable_retry_budget=True,
            enable_idempotency=False,
            service_type=ServiceType.CACHE
        )
        
        # HTTP API template
        self.config_templates["http_api"] = RetryPolicyConfig(
            max_attempts=4,
            base_delay=1.0,
            max_delay=30.0,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            backoff_multiplier=2.0,
            jitter_factor=0.15,
            timeout=60.0,
            retryable_status_codes={408, 429, 500, 502, 503, 504},
            enable_circuit_breaker=True,
            enable_retry_budget=True,
            enable_idempotency=True,
            service_type=ServiceType.HTTP_API
        )
        
        # Message Queue template
        self.config_templates["message_queue"] = RetryPolicyConfig(
            max_attempts=5,
            base_delay=1.0,
            max_delay=60.0,
            strategy=RetryStrategy.EXPONENTIAL,
            backoff_multiplier=2.0,
            timeout=300.0,
            enable_circuit_breaker=True,
            enable_retry_budget=True,
            enable_idempotency=True,
            service_type=ServiceType.MESSAGE_QUEUE
        )
        
        # Microservice template
        self.config_templates["microservice"] = RetryPolicyConfig(
            max_attempts=3,
            base_delay=0.5,
            max_delay=10.0,
            strategy=RetryStrategy.EXPONENTIAL_JITTER,
            backoff_multiplier=2.0,
            jitter_factor=0.2,
            timeout=30.0,
            retryable_status_codes={408, 429, 500, 502, 503, 504},
            enable_circuit_breaker=True,
            enable_retry_budget=True,
            enable_idempotency=True,
            service_type=ServiceType.MICROSERVICE
        )
    
    def load_from_file(self, filepath: Union[str, Path]) -> bool:
        """Load configuration from file."""
        try:
            filepath = Path(filepath)
            
            if not filepath.exists():
                logger.error(f"Configuration file not found: {filepath}")
                return False
            
            with open(filepath, 'r') as f:
                if filepath.suffix.lower() in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            return self._load_from_dict(data)
            
        except Exception as e:
            logger.error(f"Failed to load configuration from {filepath}: {e}")
            return False
    
    def _load_from_dict(self, data: Dict[str, Any]) -> bool:
        """Load configuration from dictionary."""
        try:
            # Load global config
            if "global" in data:
                global_data = data["global"]
                self.global_config = GlobalRetryConfig(**global_data)
                
                # Validate global config
                errors = RetryConfigValidator.validate_global_config(self.global_config)
                if errors:
                    logger.error(f"Global configuration validation errors: {errors}")
                    return False
            
            # Load service configs
            if "services" in data:
                for service_name, service_data in data["services"].items():
                    # Handle template reference
                    if "template" in service_data:
                        template_name = service_data.pop("template")
                        if template_name in self.config_templates:
                            config = self._copy_template(template_name)
                            # Override with service-specific settings
                            for key, value in service_data.items():
                                if hasattr(config, key):
                                    setattr(config, key, value)
                        else:
                            logger.warning(f"Unknown template: {template_name}")
                            config = RetryPolicyConfig(**service_data)
                    else:
                        config = RetryPolicyConfig(**service_data)
                    
                    config.service_name = service_name
                    
                    # Validate service config
                    errors = RetryConfigValidator.validate_policy_config(config)
                    if errors:
                        logger.error(f"Service {service_name} configuration validation errors: {errors}")
                        continue
                    
                    self.service_configs[service_name] = config
                    logger.info(f"Loaded configuration for service: {service_name}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration from dictionary: {e}")
            return False
    
    def _copy_template(self, template_name: str) -> RetryPolicyConfig:
        """Create a copy of a template configuration."""
        template = self.config_templates[template_name]
        return RetryPolicyConfig(**asdict(template))
    
    def load_from_environment(self) -> bool:
        """Load configuration from environment variables."""
        try:
            # Global settings
            self.global_config.enable_global_metrics = os.getenv(
                'RETRY_GLOBAL_METRICS', 'true'
            ).lower() == 'true'
            
            self.global_config.metrics_export_interval = int(
                os.getenv('RETRY_METRICS_EXPORT_INTERVAL', '300')
            )
            
            self.global_config.max_concurrent_retries_global = int(
                os.getenv('RETRY_MAX_CONCURRENT_GLOBAL', '100')
            )
            
            self.global_config.default_timeout = float(
                os.getenv('RETRY_DEFAULT_TIMEOUT', '300.0')
            )
            
            self.global_config.enable_debug_logging = os.getenv(
                'RETRY_DEBUG_LOGGING', 'false'
            ).lower() == 'true'
            
            # Redis settings
            self.global_config.redis_host = os.getenv('REDIS_HOST')
            self.global_config.redis_port = int(os.getenv('REDIS_PORT', '6379'))
            self.global_config.redis_password = os.getenv('REDIS_PASSWORD')
            self.global_config.redis_db = int(os.getenv('REDIS_DB', '0'))
            
            # Prometheus settings
            self.global_config.prometheus_enabled = os.getenv(
                'PROMETHEUS_ENABLED', 'false'
            ).lower() == 'true'
            self.global_config.prometheus_port = int(os.getenv('PROMETHEUS_PORT', '8000'))
            
            logger.info("Loaded configuration from environment variables")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration from environment: {e}")
            return False
    
    def save_to_file(self, filepath: Union[str, Path], format: str = 'yaml') -> bool:
        """Save configuration to file."""
        try:
            filepath = Path(filepath)
            
            data = {
                "global": asdict(self.global_config),
                "services": {
                    name: asdict(config) 
                    for name, config in self.service_configs.items()
                }
            }
            
            with open(filepath, 'w') as f:
                if format.lower() == 'yaml':
                    yaml.dump(data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Saved configuration to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration to {filepath}: {e}")
            return False
    
    def get_service_config(self, service_name: str) -> Optional[RetryPolicyConfig]:
        """Get configuration for a service."""
        return self.service_configs.get(service_name)
    
    def add_service_config(self, service_name: str, config: RetryPolicyConfig) -> bool:
        """Add configuration for a service."""
        # Validate configuration
        errors = RetryConfigValidator.validate_policy_config(config)
        if errors:
            logger.error(f"Configuration validation errors for {service_name}: {errors}")
            return False
        
        config.service_name = service_name
        self.service_configs[service_name] = config
        logger.info(f"Added configuration for service: {service_name}")
        return True
    
    def update_service_config(
        self, 
        service_name: str, 
        updates: Dict[str, Any]
    ) -> bool:
        """Update configuration for a service."""
        if service_name not in self.service_configs:
            logger.error(f"Service configuration not found: {service_name}")
            return False
        
        config = self.service_configs[service_name]
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                logger.warning(f"Unknown configuration key: {key}")
        
        # Validate updated configuration
        errors = RetryConfigValidator.validate_policy_config(config)
        if errors:
            logger.error(f"Updated configuration validation errors for {service_name}: {errors}")
            return False
        
        logger.info(f"Updated configuration for service: {service_name}")
        return True
    
    def remove_service_config(self, service_name: str) -> bool:
        """Remove configuration for a service."""
        if service_name in self.service_configs:
            del self.service_configs[service_name]
            logger.info(f"Removed configuration for service: {service_name}")
            return True
        
        logger.warning(f"Service configuration not found: {service_name}")
        return False
    
    def get_template_config(self, template_name: str) -> Optional[RetryPolicyConfig]:
        """Get a template configuration."""
        if template_name in self.config_templates:
            return self._copy_template(template_name)
        return None
    
    def list_templates(self) -> List[str]:
        """List available configuration templates."""
        return list(self.config_templates.keys())
    
    def create_service_from_template(
        self, 
        service_name: str, 
        template_name: str, 
        overrides: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Create service configuration from template."""
        if template_name not in self.config_templates:
            logger.error(f"Template not found: {template_name}")
            return False
        
        config = self._copy_template(template_name)
        config.service_name = service_name
        
        # Apply overrides
        if overrides:
            for key, value in overrides.items():
                if hasattr(config, key):
                    setattr(config, key, value)
                else:
                    logger.warning(f"Unknown configuration key in overrides: {key}")
        
        return self.add_service_config(service_name, config)
    
    def export_summary(self) -> Dict[str, Any]:
        """Export configuration summary."""
        return {
            "global_config": asdict(self.global_config),
            "service_count": len(self.service_configs),
            "services": list(self.service_configs.keys()),
            "templates_available": list(self.config_templates.keys()),
            "validation_status": {
                service_name: len(RetryConfigValidator.validate_policy_config(config)) == 0
                for service_name, config in self.service_configs.items()
            }
        }


# Global configuration manager instance
_config_manager = RetryConfigManager()


def get_config_manager() -> RetryConfigManager:
    """Get the global configuration manager."""
    return _config_manager


def load_config_from_file(filepath: Union[str, Path]) -> bool:
    """Load configuration from file using global manager."""
    return _config_manager.load_from_file(filepath)


def load_config_from_environment() -> bool:
    """Load configuration from environment using global manager."""
    return _config_manager.load_from_environment()


def get_service_config(service_name: str) -> Optional[RetryPolicyConfig]:
    """Get service configuration from global manager."""
    return _config_manager.get_service_config(service_name)


def create_default_config_file(filepath: Union[str, Path]) -> bool:
    """Create a default configuration file with examples."""
    try:
        config_data = {
            "global": {
                "enable_global_metrics": True,
                "metrics_export_interval": 300,
                "max_concurrent_retries_global": 100,
                "default_timeout": 300.0,
                "enable_debug_logging": False,
                "circuit_breaker_enabled_globally": True,
                "retry_budget_enabled_globally": True,
                "idempotency_enabled_globally": True,
                "redis_host": None,
                "redis_port": 6379,
                "prometheus_enabled": False,
                "prometheus_port": 8000,
                "alert_on_high_failure_rate": True,
                "failure_rate_threshold": 0.5
            },
            "services": {
                "openai_api": {
                    "template": "ai_service",
                    "max_attempts": 5,
                    "base_delay": 2.0,
                    "service_type": "ai_openai"
                },
                "claude_api": {
                    "template": "ai_service",
                    "max_attempts": 5,
                    "base_delay": 2.0,
                    "service_type": "ai_claude"
                },
                "postgres_db": {
                    "template": "database",
                    "max_attempts": 3,
                    "base_delay": 0.5
                },
                "redis_cache": {
                    "template": "cache",
                    "max_attempts": 2,
                    "base_delay": 0.1
                },
                "external_api": {
                    "template": "http_api",
                    "max_attempts": 4,
                    "base_delay": 1.0
                }
            }
        }
        
        filepath = Path(filepath)
        with open(filepath, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
        
        logger.info(f"Created default configuration file: {filepath}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create default configuration file: {e}")
        return False


# Export public API
__all__ = [
    'GlobalRetryConfig',
    'RetryConfigValidator',
    'RetryConfigManager',
    'get_config_manager',
    'load_config_from_file',
    'load_config_from_environment',
    'get_service_config',
    'create_default_config_file',
]