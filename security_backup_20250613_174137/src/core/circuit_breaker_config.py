"""
Circuit breaker configuration management for different environments.

Provides environment-specific configurations and configuration loading utilities.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path

from src.core.circuit_breaker import CircuitBreakerConfig

__all__ = [
    "EnvironmentConfig",
    "CircuitBreakerConfigManager",
    "get_circuit_breaker_config_manager",
    "get_circuit_breaker_config"
]


logger = logging.getLogger(__name__)


@dataclass
class EnvironmentConfig:
    """Environment-specific circuit breaker configuration."""
    name: str
    ai_providers: Dict[str, CircuitBreakerConfig]
    mcp_services: Dict[str, CircuitBreakerConfig]
    global_defaults: CircuitBreakerConfig


class CircuitBreakerConfigManager:
    """
    Manages circuit breaker configurations for different environments.
    
    Provides configuration loading, environment detection, and service-specific
    circuit breaker configurations.
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_dir = config_dir or Path(__file__).parent.parent.parent / "config" / "circuit_breakers"
        self.environments: Dict[str, EnvironmentConfig] = {}
        self.current_environment = os.getenv('ENVIRONMENT', 'development')
        
        # Load configurations
        self._load_configurations()
    
    def _load_configurations(self):
        """Load circuit breaker configurations from files."""
        try:
            # Create config directory if it doesn't exist
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Load default configurations
            self._create_default_configurations()
            
            # Load custom configurations if they exist
            for config_file in self.config_dir.glob("*.json"):
                env_name = config_file.stem
                try:
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                    self._load_environment_config(env_name, config_data)
                    logger.info(f"Loaded circuit breaker config for environment: {env_name}")
                except Exception as e:
                    logger.error(f"Failed to load config from {config_file}: {e}")
            
        except Exception as e:
            logger.error(f"Failed to load circuit breaker configurations: {e}")
            # Fall back to default configurations
            self._create_default_configurations()
    
    def _create_default_configurations(self):
        """Create default configurations for all environments."""
        
        # Development environment - more lenient for testing
        dev_config = EnvironmentConfig(
            name="development",
            global_defaults=CircuitBreakerConfig(
                failure_threshold=10,
                timeout=180,
                failure_rate_threshold=0.7,
                minimum_calls=5
            ),
            ai_providers={
                "claude": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.6,
                    minimum_calls=3
                ),
                "gpt4": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.6,
                    minimum_calls=3
                ),
                "gemini": CircuitBreakerConfig(
                    failure_threshold=8,  # More tolerant for experimental models
                    timeout=150,
                    failure_rate_threshold=0.7,
                    minimum_calls=3
                ),
                "deepseek": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=180,  # Reasoning models can be slower
                    failure_rate_threshold=0.6,
                    minimum_calls=3
                ),
                "ollama": CircuitBreakerConfig(
                    failure_threshold=15,  # Local services can be flaky
                    timeout=300,
                    failure_rate_threshold=0.8,
                    minimum_calls=2
                ),
                "groq": CircuitBreakerConfig(
                    failure_threshold=3,  # Fast service, should be reliable
                    timeout=60,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                )
            },
            mcp_services={
                "docker": CircuitBreakerConfig(
                    failure_threshold=8,
                    timeout=120,
                    failure_rate_threshold=0.6,
                    minimum_calls=3
                ),
                "kubernetes": CircuitBreakerConfig(
                    failure_threshold=10,
                    timeout=180,
                    failure_rate_threshold=0.7,
                    minimum_calls=3
                ),
                "desktop_commander": CircuitBreakerConfig(
                    failure_threshold=15,
                    timeout=120,
                    failure_rate_threshold=0.8,
                    minimum_calls=3
                ),
                "prometheus": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=60,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "slack": CircuitBreakerConfig(
                    failure_threshold=8,
                    timeout=90,
                    failure_rate_threshold=0.6,
                    minimum_calls=3
                ),
                "s3": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "security_scanner": CircuitBreakerConfig(
                    failure_threshold=10,
                    timeout=300,  # Security scans can take time
                    failure_rate_threshold=0.7,
                    minimum_calls=2
                )
            }
        )
        self.environments["development"] = dev_config
        
        # Staging environment - moderate strictness
        staging_config = EnvironmentConfig(
            name="staging",
            global_defaults=CircuitBreakerConfig(
                failure_threshold=5,
                timeout=90,
                failure_rate_threshold=0.5,
                minimum_calls=10
            ),
            ai_providers={
                "claude": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=90,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "gpt4": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=90,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "gemini": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.6,
                    minimum_calls=5
                ),
                "deepseek": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=120,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "groq": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=45,
                    failure_rate_threshold=0.4,
                    minimum_calls=8
                )
            },
            mcp_services={
                "docker": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=90,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "kubernetes": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "desktop_commander": CircuitBreakerConfig(
                    failure_threshold=8,
                    timeout=90,
                    failure_rate_threshold=0.6,
                    minimum_calls=5
                ),
                "prometheus": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=45,
                    failure_rate_threshold=0.4,
                    minimum_calls=8
                ),
                "slack": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=60,
                    failure_rate_threshold=0.5,
                    minimum_calls=5
                ),
                "s3": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=90,
                    failure_rate_threshold=0.4,
                    minimum_calls=8
                ),
                "security_scanner": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=180,
                    failure_rate_threshold=0.5,
                    minimum_calls=3
                )
            }
        )
        self.environments["staging"] = staging_config
        
        # Production environment - strict for reliability
        prod_config = EnvironmentConfig(
            name="production",
            global_defaults=CircuitBreakerConfig(
                failure_threshold=3,
                timeout=60,
                failure_rate_threshold=0.4,
                minimum_calls=20
            ),
            ai_providers={
                "claude": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=60,
                    failure_rate_threshold=0.3,
                    minimum_calls=10
                ),
                "gpt4": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=60,
                    failure_rate_threshold=0.3,
                    minimum_calls=10
                ),
                "gemini": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=90,
                    failure_rate_threshold=0.4,
                    minimum_calls=10
                ),
                "deepseek": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=90,
                    failure_rate_threshold=0.3,
                    minimum_calls=10
                ),
                "groq": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=30,
                    failure_rate_threshold=0.3,
                    minimum_calls=15
                )
            },
            mcp_services={
                "docker": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=60,
                    failure_rate_threshold=0.4,
                    minimum_calls=10
                ),
                "kubernetes": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=90,
                    failure_rate_threshold=0.4,
                    minimum_calls=10
                ),
                "desktop_commander": CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=60,
                    failure_rate_threshold=0.5,
                    minimum_calls=10
                ),
                "prometheus": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=30,
                    failure_rate_threshold=0.3,
                    minimum_calls=15
                ),
                "slack": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=45,
                    failure_rate_threshold=0.4,
                    minimum_calls=10
                ),
                "s3": CircuitBreakerConfig(
                    failure_threshold=2,
                    timeout=60,
                    failure_rate_threshold=0.3,
                    minimum_calls=15
                ),
                "security_scanner": CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=120,
                    failure_rate_threshold=0.4,
                    minimum_calls=5
                )
            }
        )
        self.environments["production"] = prod_config
        
        # Testing environment - very lenient for CI/CD
        test_config = EnvironmentConfig(
            name="testing",
            global_defaults=CircuitBreakerConfig(
                failure_threshold=20,
                timeout=300,
                failure_rate_threshold=0.9,
                minimum_calls=2
            ),
            ai_providers={
                "claude": CircuitBreakerConfig(
                    failure_threshold=15,
                    timeout=240,
                    failure_rate_threshold=0.8,
                    minimum_calls=2
                ),
                "gpt4": CircuitBreakerConfig(
                    failure_threshold=15,
                    timeout=240,
                    failure_rate_threshold=0.8,
                    minimum_calls=2
                ),
                "gemini": CircuitBreakerConfig(
                    failure_threshold=20,
                    timeout=300,
                    failure_rate_threshold=0.9,
                    minimum_calls=2
                ),
                "ollama": CircuitBreakerConfig(
                    failure_threshold=50,  # Very lenient for testing
                    timeout=600,
                    failure_rate_threshold=0.95,
                    minimum_calls=1
                )
            },
            mcp_services={
                "docker": CircuitBreakerConfig(
                    failure_threshold=20,
                    timeout=300,
                    failure_rate_threshold=0.9,
                    minimum_calls=2
                ),
                "kubernetes": CircuitBreakerConfig(
                    failure_threshold=25,
                    timeout=360,
                    failure_rate_threshold=0.9,
                    minimum_calls=2
                ),
                "desktop_commander": CircuitBreakerConfig(
                    failure_threshold=30,
                    timeout=300,
                    failure_rate_threshold=0.95,
                    minimum_calls=1
                )
            }
        )
        self.environments["testing"] = test_config
    
    def _load_environment_config(self, env_name: str, config_data: Dict[str, Any]):
        """Load environment configuration from data."""
        try:
            # Parse global defaults
            global_defaults = CircuitBreakerConfig(**config_data.get("global_defaults", {}))
            
            # Parse AI provider configs
            ai_providers = {}
            for provider, config in config_data.get("ai_providers", {}).items():
                ai_providers[provider] = CircuitBreakerConfig(**config)
            
            # Parse MCP service configs
            mcp_services = {}
            for service, config in config_data.get("mcp_services", {}).items():
                mcp_services[service] = CircuitBreakerConfig(**config)
            
            # Create environment config
            env_config = EnvironmentConfig(
                name=env_name,
                global_defaults=global_defaults,
                ai_providers=ai_providers,
                mcp_services=mcp_services
            )
            
            self.environments[env_name] = env_config
            
        except Exception as e:
            logger.error(f"Failed to parse environment config for {env_name}: {e}")
    
    def get_config(self, service_name: str, service_type: str = "unknown") -> CircuitBreakerConfig:
        """
        Get circuit breaker configuration for a service.
        
        Args:
            service_name: Name of the service
            service_type: Type of service (ai_provider, mcp_service, etc.)
            
        Returns:
            Circuit breaker configuration
        """
        env_config = self.environments.get(self.current_environment)
        if not env_config:
            logger.warning(f"No configuration found for environment: {self.current_environment}")
            return CircuitBreakerConfig()  # Default config
        
        # Normalize service name
        normalized_name = self._normalize_service_name(service_name)
        
        # Try AI providers first
        if normalized_name in env_config.ai_providers:
            config = env_config.ai_providers[normalized_name]
        # Try MCP services
        elif normalized_name in env_config.mcp_services:
            config = env_config.mcp_services[normalized_name]
        # Fall back to global defaults
        else:
            config = env_config.global_defaults
            logger.info(f"Using global defaults for service: {service_name}")
        
        # Set the name for the config
        config.name = service_name
        return config
    
    def _normalize_service_name(self, service_name: str) -> str:
        """Normalize service name for lookup."""
        name = service_name.lower()
        
        # Extract key components
        if 'claude' in name:
            return 'claude'
        elif 'gpt' in name or 'openai' in name:
            return 'gpt4'
        elif 'gemini' in name or 'google' in name:
            return 'gemini'
        elif 'deepseek' in name:
            return 'deepseek'
        elif 'groq' in name:
            return 'groq'
        elif 'ollama' in name:
            return 'ollama'
        elif 'huggingface' in name:
            return 'huggingface'
        elif 'docker' in name:
            return 'docker'
        elif 'kubernetes' in name or 'kubectl' in name:
            return 'kubernetes'
        elif 'desktop_commander' in name:
            return 'desktop_commander'
        elif 'prometheus' in name:
            return 'prometheus'
        elif 'slack' in name:
            return 'slack'
        elif 's3' in name or 'aws' in name:
            return 's3'
        elif 'security' in name or 'scanner' in name:
            return 'security_scanner'
        else:
            return name
    
    def save_environment_config(self, env_name: str):
        """Save environment configuration to file."""
        try:
            env_config = self.environments.get(env_name)
            if not env_config:
                logger.error(f"No configuration found for environment: {env_name}")
                return
            
            config_data = {
                "global_defaults": asdict(env_config.global_defaults),
                "ai_providers": {k: asdict(v) for k, v in env_config.ai_providers.items()},
                "mcp_services": {k: asdict(v) for k, v in env_config.mcp_services.items()}
            }
            
            config_file = self.config_dir / f"{env_name}.json"
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Saved circuit breaker config for environment: {env_name}")
            
        except Exception as e:
            logger.error(f"Failed to save config for {env_name}: {e}")
    
    def get_all_environments(self) -> List[str]:
        """Get list of all available environments."""
        return list(self.environments.keys())
    
    def set_environment(self, env_name: str):
        """Set the current environment."""
        if env_name in self.environments:
            self.current_environment = env_name
            logger.info(f"Circuit breaker environment set to: {env_name}")
        else:
            logger.error(f"Unknown environment: {env_name}")
    
    def get_environment_summary(self, env_name: Optional[str] = None) -> Dict[str, Any]:
        """Get summary of environment configuration."""
        env_name = env_name or self.current_environment
        env_config = self.environments.get(env_name)
        
        if not env_config:
            return {"error": f"Environment {env_name} not found"}
        
        return {
            "environment": env_name,
            "global_defaults": asdict(env_config.global_defaults),
            "ai_providers": len(env_config.ai_providers),
            "mcp_services": len(env_config.mcp_services),
            "ai_provider_list": list(env_config.ai_providers.keys()),
            "mcp_service_list": list(env_config.mcp_services.keys())
        }


# Global configuration manager instance
_config_manager: Optional[CircuitBreakerConfigManager] = None


def get_circuit_breaker_config_manager() -> CircuitBreakerConfigManager:
    """Get or create the global circuit breaker configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = CircuitBreakerConfigManager()
    return _config_manager


def get_circuit_breaker_config(service_name: str, service_type: str = "unknown") -> CircuitBreakerConfig:
    """Get circuit breaker configuration for a service."""
    manager = get_circuit_breaker_config_manager()
    return manager.get_config(service_name, service_type)