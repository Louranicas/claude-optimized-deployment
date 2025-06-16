"""
Comprehensive configuration management for circuit breakers.

This module provides:
- Centralized configuration management
- Environment-specific settings
- Dynamic configuration updates
- Configuration validation
- Configuration templates
- Configuration backup and restore
- Runtime configuration changes
"""

import os
import json
import yaml
import logging
from typing import Any, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import hashlib

from src.core.circuit_breaker_standard import (
    StandardCircuitBreakerConfig,
    CircuitBreakerType,
    BulkheadConfig,
    HealthCheckConfig
)
from src.core.circuit_breaker_database import DatabaseCircuitBreakerConfig
from src.core.circuit_breaker_mcp import MCPServerConfig, MCPCircuitBreakerConfig, MCPServerType
from src.core.circuit_breaker_middleware import RouteCircuitBreakerConfig

logger = logging.getLogger(__name__)


class ConfigurationFormat(Enum):
    """Supported configuration formats."""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


@dataclass
class ConfigurationMetadata:
    """Metadata for configuration files."""
    version: str
    created_at: datetime
    updated_at: datetime
    environment: str
    hash: str
    description: Optional[str] = None
    tags: Set[str] = field(default_factory=set)


@dataclass
class CircuitBreakerTemplate:
    """Template for circuit breaker configurations."""
    name: str
    description: str
    service_category: str
    circuit_type: CircuitBreakerType
    base_config: StandardCircuitBreakerConfig
    environments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)


class ConfigurationValidator:
    """Validates circuit breaker configurations."""
    
    def __init__(self):
        """Initialize configuration validator."""
        self._validation_rules = {
            'failure_threshold': lambda x: isinstance(x, int) and x > 0,
            'timeout': lambda x: isinstance(x, (int, float)) and x > 0,
            'failure_rate_threshold': lambda x: isinstance(x, (int, float)) and 0 <= x <= 1,
            'minimum_calls': lambda x: isinstance(x, int) and x > 0,
            'max_concurrent_calls': lambda x: isinstance(x, int) and x > 0,
            'health_check_interval': lambda x: isinstance(x, (int, float)) and x > 0,
        }
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate a configuration dictionary.
        
        Args:
            config: Configuration to validate
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required fields
        required_fields = ['failure_threshold', 'timeout']
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
        
        # Validate field values
        for field, validator in self._validation_rules.items():
            if field in config:
                if not validator(config[field]):
                    errors.append(f"Invalid value for {field}: {config[field]}")
        
        # Validate circuit type
        if 'circuit_type' in config:
            try:
                CircuitBreakerType(config['circuit_type'])
            except ValueError:
                errors.append(f"Invalid circuit_type: {config['circuit_type']}")
        
        # Validate service category
        if 'service_category' in config:
            valid_categories = {'ai', 'mcp', 'database', 'external', 'api_route'}
            if config['service_category'] not in valid_categories:
                errors.append(f"Invalid service_category: {config['service_category']}")
        
        # Cross-field validation
        if 'failure_rate_threshold' in config and 'minimum_calls' in config:
            if config['minimum_calls'] < 3:
                errors.append("minimum_calls should be at least 3 for meaningful failure rate calculation")
        
        return errors
    
    def validate_database_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate database-specific configuration."""
        errors = []
        
        # Database-specific validations
        if 'max_connections' in config and 'min_connections' in config:
            if config['max_connections'] <= config['min_connections']:
                errors.append("max_connections must be greater than min_connections")
        
        if 'query_timeout' in config and config['query_timeout'] <= 0:
            errors.append("query_timeout must be positive")
        
        if 'health_check_query' in config and not isinstance(config['health_check_query'], str):
            errors.append("health_check_query must be a string")
        
        return errors
    
    def validate_mcp_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate MCP-specific configuration."""
        errors = []
        
        # MCP-specific validations
        if 'server_type' in config:
            try:
                MCPServerType(config['server_type'])
            except ValueError:
                errors.append(f"Invalid server_type: {config['server_type']}")
        
        if 'transport_uri' in config and not isinstance(config['transport_uri'], str):
            errors.append("transport_uri must be a string")
        
        if 'tools' in config and not isinstance(config['tools'], list):
            errors.append("tools must be a list")
        
        if 'resources' in config and not isinstance(config['resources'], list):
            errors.append("resources must be a list")
        
        return errors


class ConfigurationManager:
    """Manages circuit breaker configurations across environments."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Directory for configuration files
        """
        self.config_dir = config_dir or Path(__file__).parent.parent.parent / "config" / "circuit_breakers"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.validator = ConfigurationValidator()
        self._configurations: Dict[str, Dict[str, Any]] = {}
        self._metadata: Dict[str, ConfigurationMetadata] = {}
        self._templates: Dict[str, CircuitBreakerTemplate] = {}
        self._watchers: List[callable] = []
        
        # Load existing configurations
        self._load_configurations()
        self._setup_templates()
    
    def _load_configurations(self):
        """Load all configuration files from disk."""
        for config_file in self.config_dir.glob("*.json"):
            try:
                self._load_configuration_file(config_file)
            except Exception as e:
                logger.error(f"Failed to load config file {config_file}: {e}")
        
        for config_file in self.config_dir.glob("*.yaml"):
            try:
                self._load_configuration_file(config_file)
            except Exception as e:
                logger.error(f"Failed to load config file {config_file}: {e}")
    
    def _load_configuration_file(self, config_file: Path):
        """Load a single configuration file."""
        with open(config_file, 'r') as f:
            if config_file.suffix == '.json':
                data = json.load(f)
            elif config_file.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            else:
                raise ValueError(f"Unsupported file format: {config_file.suffix}")
        
        config_name = config_file.stem
        self._configurations[config_name] = data
        
        # Create metadata
        metadata = ConfigurationMetadata(
            version=data.get('metadata', {}).get('version', '1.0.0'),
            created_at=datetime.now(),
            updated_at=datetime.now(),
            environment=data.get('metadata', {}).get('environment', 'unknown'),
            hash=self._calculate_hash(data),
            description=data.get('metadata', {}).get('description'),
            tags=set(data.get('metadata', {}).get('tags', []))
        )
        self._metadata[config_name] = metadata
        
        logger.info(f"Loaded configuration: {config_name}")
    
    def _setup_templates(self):
        """Set up default configuration templates."""
        # AI Provider Template
        ai_template = CircuitBreakerTemplate(
            name="ai_provider",
            description="Template for AI provider services",
            service_category="ai",
            circuit_type=CircuitBreakerType.ADAPTIVE,
            base_config=StandardCircuitBreakerConfig(
                failure_threshold=5,
                timeout=60.0,
                failure_rate_threshold=0.5,
                minimum_calls=10,
                circuit_type=CircuitBreakerType.ADAPTIVE,
                service_category="ai",
                priority=1,
                bulkhead_config=BulkheadConfig(
                    max_concurrent_calls=20,
                    queue_timeout=10.0
                ),
                health_check_config=HealthCheckConfig(
                    health_check_interval=30.0,
                    health_check_timeout=5.0
                )
            ),
            environments={
                'development': {'failure_threshold': 10, 'timeout': 120.0},
                'staging': {'failure_threshold': 5, 'timeout': 60.0},
                'production': {'failure_threshold': 3, 'timeout': 30.0}
            },
            tags={'ai', 'adaptive', 'high_priority'}
        )
        self._templates["ai_provider"] = ai_template
        
        # Database Template
        db_template = CircuitBreakerTemplate(
            name="database",
            description="Template for database services",
            service_category="database",
            circuit_type=CircuitBreakerType.PERCENTAGE_BASED,
            base_config=StandardCircuitBreakerConfig(
                failure_threshold=3,
                timeout=30.0,
                failure_rate_threshold=0.3,
                minimum_calls=20,
                circuit_type=CircuitBreakerType.PERCENTAGE_BASED,
                service_category="database",
                priority=1,
                bulkhead_config=BulkheadConfig(
                    max_concurrent_calls=50,
                    queue_timeout=2.0
                ),
                health_check_config=HealthCheckConfig(
                    health_check_interval=15.0,
                    health_check_timeout=3.0
                )
            ),
            environments={
                'development': {'failure_threshold': 5, 'timeout': 60.0},
                'staging': {'failure_threshold': 3, 'timeout': 30.0},
                'production': {'failure_threshold': 2, 'timeout': 15.0}
            },
            tags={'database', 'percentage', 'critical'}
        )
        self._templates["database"] = db_template
        
        # MCP Template
        mcp_template = CircuitBreakerTemplate(
            name="mcp_service",
            description="Template for MCP services",
            service_category="mcp",
            circuit_type=CircuitBreakerType.COUNT_BASED,
            base_config=StandardCircuitBreakerConfig(
                failure_threshold=5,
                timeout=45.0,
                failure_rate_threshold=0.5,
                minimum_calls=5,
                circuit_type=CircuitBreakerType.COUNT_BASED,
                service_category="mcp",
                priority=2,
                bulkhead_config=BulkheadConfig(
                    max_concurrent_calls=10,
                    queue_timeout=5.0
                ),
                health_check_config=HealthCheckConfig(
                    health_check_interval=60.0,
                    health_check_timeout=10.0
                )
            ),
            environments={
                'development': {'failure_threshold': 8, 'timeout': 120.0},
                'staging': {'failure_threshold': 5, 'timeout': 45.0},
                'production': {'failure_threshold': 3, 'timeout': 30.0}
            },
            tags={'mcp', 'count_based', 'medium_priority'}
        )
        self._templates["mcp_service"] = mcp_template
        
        # External API Template
        external_template = CircuitBreakerTemplate(
            name="external_api",
            description="Template for external API services",
            service_category="external",
            circuit_type=CircuitBreakerType.TIME_BASED,
            base_config=StandardCircuitBreakerConfig(
                failure_threshold=5,
                timeout=60.0,
                failure_rate_threshold=0.5,
                minimum_calls=10,
                circuit_type=CircuitBreakerType.TIME_BASED,
                service_category="external",
                priority=3,
                bulkhead_config=BulkheadConfig(
                    max_concurrent_calls=15,
                    queue_timeout=8.0
                ),
                health_check_config=HealthCheckConfig(
                    health_check_interval=45.0,
                    health_check_timeout=8.0
                )
            ),
            environments={
                'development': {'failure_threshold': 10, 'timeout': 180.0},
                'staging': {'failure_threshold': 5, 'timeout': 60.0},
                'production': {'failure_threshold': 3, 'timeout': 30.0}
            },
            tags={'external', 'time_based', 'low_priority'}
        )
        self._templates["external_api"] = external_template
    
    def create_configuration(
        self,
        name: str,
        template_name: str,
        environment: str = "development",
        overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a new configuration from a template.
        
        Args:
            name: Configuration name
            template_name: Template to use
            environment: Target environment
            overrides: Configuration overrides
        
        Returns:
            Created configuration
        """
        if template_name not in self._templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = self._templates[template_name]
        
        # Start with base configuration
        config = asdict(template.base_config)
        
        # Apply environment-specific overrides
        if environment in template.environments:
            config.update(template.environments[environment])
        
        # Apply custom overrides
        if overrides:
            config.update(overrides)
        
        # Set name and metadata
        config['name'] = name
        config['metadata'] = {
            'version': '1.0.0',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'environment': environment,
            'template': template_name,
            'description': f"Configuration for {name} based on {template_name} template",
            'tags': list(template.tags)
        }
        
        # Validate configuration
        errors = self.validator.validate_config(config)
        if errors:
            raise ValueError(f"Configuration validation failed: {errors}")
        
        # Store configuration
        self._configurations[name] = config
        self._metadata[name] = ConfigurationMetadata(
            version=config['metadata']['version'],
            created_at=datetime.now(),
            updated_at=datetime.now(),
            environment=environment,
            hash=self._calculate_hash(config),
            description=config['metadata']['description'],
            tags=set(config['metadata']['tags'])
        )
        
        logger.info(f"Created configuration '{name}' from template '{template_name}'")
        return config
    
    def update_configuration(
        self,
        name: str,
        updates: Dict[str, Any],
        validate: bool = True
    ) -> Dict[str, Any]:
        """
        Update an existing configuration.
        
        Args:
            name: Configuration name
            updates: Updates to apply
            validate: Whether to validate the updated configuration
        
        Returns:
            Updated configuration
        """
        if name not in self._configurations:
            raise ValueError(f"Configuration '{name}' not found")
        
        # Create updated configuration
        config = self._configurations[name].copy()
        self._deep_update(config, updates)
        
        # Update metadata
        if 'metadata' not in config:
            config['metadata'] = {}
        config['metadata']['updated_at'] = datetime.now().isoformat()
        
        # Validate if requested
        if validate:
            errors = self.validator.validate_config(config)
            if errors:
                raise ValueError(f"Configuration validation failed: {errors}")
        
        # Store updated configuration
        old_hash = self._metadata[name].hash
        new_hash = self._calculate_hash(config)
        
        self._configurations[name] = config
        self._metadata[name].updated_at = datetime.now()
        self._metadata[name].hash = new_hash
        
        # Notify watchers of changes
        if old_hash != new_hash:
            self._notify_watchers(name, config)
        
        logger.info(f"Updated configuration '{name}'")
        return config
    
    def get_configuration(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a configuration by name."""
        return self._configurations.get(name)
    
    def get_all_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Get all configurations."""
        return dict(self._configurations)
    
    def get_configurations_by_environment(self, environment: str) -> Dict[str, Dict[str, Any]]:
        """Get all configurations for a specific environment."""
        result = {}
        for name, metadata in self._metadata.items():
            if metadata.environment == environment:
                result[name] = self._configurations[name]
        return result
    
    def get_configurations_by_tag(self, tag: str) -> Dict[str, Dict[str, Any]]:
        """Get all configurations with a specific tag."""
        result = {}
        for name, metadata in self._metadata.items():
            if tag in metadata.tags:
                result[name] = self._configurations[name]
        return result
    
    def delete_configuration(self, name: str) -> bool:
        """
        Delete a configuration.
        
        Args:
            name: Configuration name
        
        Returns:
            True if deleted, False if not found
        """
        if name not in self._configurations:
            return False
        
        del self._configurations[name]
        del self._metadata[name]
        
        # Remove file if it exists
        for suffix in ['.json', '.yaml', '.yml']:
            config_file = self.config_dir / f"{name}{suffix}"
            if config_file.exists():
                config_file.unlink()
                break
        
        logger.info(f"Deleted configuration '{name}'")
        return True
    
    def save_configuration(
        self,
        name: str,
        format: ConfigurationFormat = ConfigurationFormat.YAML
    ):
        """
        Save a configuration to disk.
        
        Args:
            name: Configuration name
            format: File format to use
        """
        if name not in self._configurations:
            raise ValueError(f"Configuration '{name}' not found")
        
        config = self._configurations[name]
        
        if format == ConfigurationFormat.JSON:
            config_file = self.config_dir / f"{name}.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2, default=str)
        elif format == ConfigurationFormat.YAML:
            config_file = self.config_dir / f"{name}.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Saved configuration '{name}' to {config_file}")
    
    def backup_configurations(self, backup_dir: Optional[Path] = None) -> Path:
        """
        Backup all configurations.
        
        Args:
            backup_dir: Directory for backup (defaults to config_dir/backups)
        
        Returns:
            Path to backup directory
        """
        if backup_dir is None:
            backup_dir = self.config_dir / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup configurations
        for name, config in self._configurations.items():
            backup_file = backup_dir / f"{name}.yaml"
            with open(backup_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        
        # Backup metadata
        metadata_file = backup_dir / "metadata.json"
        metadata_dict = {
            name: asdict(metadata) for name, metadata in self._metadata.items()
        }
        with open(metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2, default=str)
        
        logger.info(f"Backed up {len(self._configurations)} configurations to {backup_dir}")
        return backup_dir
    
    def restore_configurations(self, backup_dir: Path):
        """
        Restore configurations from backup.
        
        Args:
            backup_dir: Directory containing backup
        """
        if not backup_dir.exists():
            raise ValueError(f"Backup directory not found: {backup_dir}")
        
        # Clear current configurations
        self._configurations.clear()
        self._metadata.clear()
        
        # Restore configurations
        for config_file in backup_dir.glob("*.yaml"):
            if config_file.name == "metadata.yaml":
                continue
            
            try:
                self._load_configuration_file(config_file)
            except Exception as e:
                logger.error(f"Failed to restore config {config_file}: {e}")
        
        # Restore metadata if available
        metadata_file = backup_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata_dict = json.load(f)
                
                for name, metadata_data in metadata_dict.items():
                    if name in self._configurations:
                        self._metadata[name] = ConfigurationMetadata(
                            version=metadata_data['version'],
                            created_at=datetime.fromisoformat(metadata_data['created_at']),
                            updated_at=datetime.fromisoformat(metadata_data['updated_at']),
                            environment=metadata_data['environment'],
                            hash=metadata_data['hash'],
                            description=metadata_data.get('description'),
                            tags=set(metadata_data.get('tags', []))
                        )
            except Exception as e:
                logger.error(f"Failed to restore metadata: {e}")
        
        logger.info(f"Restored {len(self._configurations)} configurations from {backup_dir}")
    
    def add_configuration_watcher(self, callback: callable):
        """
        Add a callback to be notified of configuration changes.
        
        Args:
            callback: Function to call when configuration changes
                     Signature: callback(name: str, config: Dict[str, Any])
        """
        self._watchers.append(callback)
    
    def remove_configuration_watcher(self, callback: callable):
        """Remove a configuration watcher."""
        if callback in self._watchers:
            self._watchers.remove(callback)
    
    def get_template(self, name: str) -> Optional[CircuitBreakerTemplate]:
        """Get a configuration template by name."""
        return self._templates.get(name)
    
    def get_all_templates(self) -> Dict[str, CircuitBreakerTemplate]:
        """Get all configuration templates."""
        return dict(self._templates)
    
    def add_template(self, template: CircuitBreakerTemplate):
        """Add a new configuration template."""
        self._templates[template.name] = template
        logger.info(f"Added template '{template.name}'")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get summary of all configurations."""
        by_environment = {}
        by_category = {}
        by_template = {}
        
        for name, metadata in self._metadata.items():
            # By environment
            env = metadata.environment
            if env not in by_environment:
                by_environment[env] = 0
            by_environment[env] += 1
            
            # By category
            config = self._configurations[name]
            category = config.get('service_category', 'unknown')
            if category not in by_category:
                by_category[category] = 0
            by_category[category] += 1
            
            # By template
            template = config.get('metadata', {}).get('template', 'unknown')
            if template not in by_template:
                by_template[template] = 0
            by_template[template] += 1
        
        return {
            'total_configurations': len(self._configurations),
            'by_environment': by_environment,
            'by_category': by_category,
            'by_template': by_template,
            'available_templates': list(self._templates.keys())
        }
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
        """Deep update a dictionary."""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _calculate_hash(self, config: Dict[str, Any]) -> str:
        """Calculate hash of configuration for change detection."""
        # Remove metadata for hash calculation
        config_copy = config.copy()
        if 'metadata' in config_copy:
            metadata = config_copy['metadata'].copy()
            if 'updated_at' in metadata:
                del metadata['updated_at']
            config_copy['metadata'] = metadata
        
        config_str = json.dumps(config_copy, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]
    
    def _notify_watchers(self, name: str, config: Dict[str, Any]):
        """Notify all watchers of configuration changes."""
        for watcher in self._watchers:
            try:
                watcher(name, config)
            except Exception as e:
                logger.error(f"Error in configuration watcher: {e}")


# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None


def get_configuration_manager() -> ConfigurationManager:
    """Get or create the global configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    return _config_manager


def create_circuit_breaker_config(
    name: str,
    template: str,
    environment: str = "development",
    **overrides
) -> Dict[str, Any]:
    """
    Convenience function to create a circuit breaker configuration.
    
    Args:
        name: Configuration name
        template: Template to use
        environment: Target environment
        **overrides: Configuration overrides
    
    Returns:
        Created configuration
    """
    manager = get_configuration_manager()
    return manager.create_configuration(name, template, environment, overrides)


def get_circuit_breaker_config(name: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get a circuit breaker configuration.
    
    Args:
        name: Configuration name
    
    Returns:
        Configuration or None if not found
    """
    manager = get_configuration_manager()
    return manager.get_configuration(name)


def update_circuit_breaker_config(name: str, **updates) -> Dict[str, Any]:
    """
    Convenience function to update a circuit breaker configuration.
    
    Args:
        name: Configuration name
        **updates: Updates to apply
    
    Returns:
        Updated configuration
    """
    manager = get_configuration_manager()
    return manager.update_configuration(name, updates)


# Export public API
__all__ = [
    'ConfigurationManager',
    'ConfigurationValidator',
    'CircuitBreakerTemplate',
    'ConfigurationMetadata',
    'ConfigurationFormat',
    'get_configuration_manager',
    'create_circuit_breaker_config',
    'get_circuit_breaker_config',
    'update_circuit_breaker_config',
]