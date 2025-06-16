"""
Deployment Configuration Manager

Handles configuration management, environment-specific settings,
and configuration templating for MCP server deployments.
"""

from __future__ import annotations
import os
import json
import yaml
import jinja2
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import re
from datetime import datetime

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError

logger = get_logger(__name__)


@dataclass
class EnvironmentConfig:
    """Configuration for a specific environment"""
    name: str
    variables: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    networking: Dict[str, Any] = field(default_factory=dict)
    security_policies: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerConfig:
    """Configuration for a specific MCP server"""
    name: str
    server_type: str
    base_config: Dict[str, Any] = field(default_factory=dict)
    environment_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    templates: Dict[str, str] = field(default_factory=dict)
    validation_rules: List[str] = field(default_factory=list)


class DeploymentConfigManager:
    """
    Manages deployment configurations with environment-specific settings,
    templating, and configuration validation.
    """
    
    def __init__(self, config_directory: Optional[Path] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_directory: Directory containing configuration files
        """
        self.config_directory = config_directory or Path("deploy/config")
        self.environments: Dict[str, EnvironmentConfig] = {}
        self.server_configs: Dict[str, ServerConfig] = {}
        
        # Jinja2 environment for templating
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.config_directory)),
            undefined=jinja2.StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom template functions
        self.template_env.globals.update({
            'now': datetime.now,
            'env': os.environ.get,
            'random_string': self._generate_random_string,
            'base64_encode': self._base64_encode,
            'url_encode': self._url_encode
        })
        
        # Load configurations if directory exists
        if self.config_directory.exists():
            self._load_configurations()
    
    def _load_configurations(self):
        """Load all configuration files from the config directory."""
        logger.info(f"Loading configurations from {self.config_directory}")
        
        # Load environment configurations
        env_dir = self.config_directory / "environments"
        if env_dir.exists():
            for env_file in env_dir.glob("*.yaml"):
                try:
                    self._load_environment_config(env_file)
                except Exception as e:
                    logger.error(f"Failed to load environment config {env_file}: {e}")
        
        # Load server configurations
        servers_dir = self.config_directory / "servers"
        if servers_dir.exists():
            for server_file in servers_dir.glob("*.yaml"):
                try:
                    self._load_server_config(server_file)
                except Exception as e:
                    logger.error(f"Failed to load server config {server_file}: {e}")
    
    def _load_environment_config(self, config_file: Path):
        """Load environment configuration from file."""
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f)
        
        env_name = config_file.stem
        env_config = EnvironmentConfig(
            name=env_name,
            variables=data.get('variables', {}),
            secrets=data.get('secrets', {}),
            resource_limits=data.get('resource_limits', {}),
            networking=data.get('networking', {}),
            security_policies=data.get('security_policies', {})
        )
        
        self.environments[env_name] = env_config
        logger.info(f"Loaded environment config: {env_name}")
    
    def _load_server_config(self, config_file: Path):
        """Load server configuration from file."""
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f)
        
        server_name = data.get('name', config_file.stem)
        server_config = ServerConfig(
            name=server_name,
            server_type=data.get('server_type', ''),
            base_config=data.get('base_config', {}),
            environment_overrides=data.get('environment_overrides', {}),
            templates=data.get('templates', {}),
            validation_rules=data.get('validation_rules', [])
        )
        
        self.server_configs[server_name] = server_config
        logger.info(f"Loaded server config: {server_name}")
    
    def get_server_config(
        self, 
        server_name: str, 
        environment: str, 
        template_vars: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get fully resolved configuration for a server in a specific environment.
        
        Args:
            server_name: Name of the server
            environment: Target environment
            template_vars: Additional template variables
            
        Returns:
            Resolved configuration dictionary
        """
        if server_name not in self.server_configs:
            raise MCPError(f"Server configuration not found: {server_name}")
        
        if environment not in self.environments:
            raise MCPError(f"Environment configuration not found: {environment}")
        
        server_config = self.server_configs[server_name]
        env_config = self.environments[environment]
        
        # Start with base configuration
        config = server_config.base_config.copy()
        
        # Apply environment-specific overrides
        env_overrides = server_config.environment_overrides.get(environment, {})
        config = self._deep_merge(config, env_overrides)
        
        # Prepare template variables
        template_context = {
            'env': env_config.variables,
            'server': server_config.name,
            'environment': environment,
            'config': config,
            **(template_vars or {})
        }
        
        # Process templates
        config = self._process_templates(config, template_context)
        
        # Add environment-specific metadata
        config['_metadata'] = {
            'server_name': server_name,
            'environment': environment,
            'generated_at': datetime.now().isoformat(),
            'config_version': '1.0'
        }
        
        # Validate configuration
        self._validate_configuration(server_config, config)
        
        return config
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _process_templates(self, config: Any, context: Dict[str, Any]) -> Any:
        """Process Jinja2 templates in configuration values."""
        if isinstance(config, dict):
            return {key: self._process_templates(value, context) for key, value in config.items()}
        elif isinstance(config, list):
            return [self._process_templates(item, context) for item in config]
        elif isinstance(config, str):
            try:
                template = self.template_env.from_string(config)
                return template.render(**context)
            except jinja2.TemplateError as e:
                logger.warning(f"Template processing failed for '{config}': {e}")
                return config
        else:
            return config
    
    def _validate_configuration(self, server_config: ServerConfig, resolved_config: Dict[str, Any]):
        """Validate resolved configuration against validation rules."""
        for rule in server_config.validation_rules:
            try:
                self._apply_validation_rule(rule, resolved_config)
            except Exception as e:
                raise MCPError(f"Configuration validation failed for {server_config.name}: {e}")
    
    def _apply_validation_rule(self, rule: str, config: Dict[str, Any]):
        """Apply a single validation rule to configuration."""
        # Simple validation rule format: "required:path.to.field"
        if rule.startswith("required:"):
            field_path = rule[9:]  # Remove "required:" prefix
            if not self._get_nested_value(config, field_path):
                raise ValueError(f"Required field missing: {field_path}")
        
        # Format validation: "format:path.to.field:regex_pattern"
        elif rule.startswith("format:"):
            parts = rule.split(":", 2)
            if len(parts) == 3:
                field_path, pattern = parts[1], parts[2]
                value = self._get_nested_value(config, field_path)
                if value and not re.match(pattern, str(value)):
                    raise ValueError(f"Field {field_path} does not match pattern {pattern}")
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def create_environment_config(
        self, 
        name: str, 
        variables: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> EnvironmentConfig:
        """
        Create a new environment configuration.
        
        Args:
            name: Environment name
            variables: Environment variables
            **kwargs: Additional environment configuration
            
        Returns:
            Created environment configuration
        """
        env_config = EnvironmentConfig(
            name=name,
            variables=variables or {},
            **kwargs
        )
        
        self.environments[name] = env_config
        logger.info(f"Created environment configuration: {name}")
        
        return env_config
    
    def create_server_config(
        self,
        name: str,
        server_type: str,
        base_config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> ServerConfig:
        """
        Create a new server configuration.
        
        Args:
            name: Server name
            server_type: Type of MCP server
            base_config: Base configuration
            **kwargs: Additional server configuration
            
        Returns:
            Created server configuration
        """
        server_config = ServerConfig(
            name=name,
            server_type=server_type,
            base_config=base_config or {},
            **kwargs
        )
        
        self.server_configs[name] = server_config
        logger.info(f"Created server configuration: {name}")
        
        return server_config
    
    def export_configuration(
        self, 
        server_name: str, 
        environment: str, 
        output_path: Path,
        format: str = "yaml"
    ):
        """
        Export resolved configuration to file.
        
        Args:
            server_name: Name of the server
            environment: Target environment
            output_path: Output file path
            format: Output format ('yaml' or 'json')
        """
        config = self.get_server_config(server_name, environment)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            if format.lower() == 'json':
                json.dump(config, f, indent=2, default=str)
            else:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Exported configuration to {output_path}")
    
    def validate_all_configurations(self) -> Dict[str, List[str]]:
        """
        Validate all server configurations against all environments.
        
        Returns:
            Dictionary of validation errors by server and environment
        """
        validation_errors = {}
        
        for server_name in self.server_configs:
            for env_name in self.environments:
                try:
                    self.get_server_config(server_name, env_name)
                except Exception as e:
                    key = f"{server_name}:{env_name}"
                    if key not in validation_errors:
                        validation_errors[key] = []
                    validation_errors[key].append(str(e))
        
        return validation_errors
    
    def list_environments(self) -> List[str]:
        """List all available environments."""
        return list(self.environments.keys())
    
    def list_servers(self) -> List[str]:
        """List all configured servers."""
        return list(self.server_configs.keys())
    
    def get_environment_info(self, environment: str) -> Dict[str, Any]:
        """Get detailed information about an environment."""
        if environment not in self.environments:
            raise MCPError(f"Environment not found: {environment}")
        
        env_config = self.environments[environment]
        return {
            "name": env_config.name,
            "variables_count": len(env_config.variables),
            "secrets_count": len(env_config.secrets),
            "has_resource_limits": bool(env_config.resource_limits),
            "has_networking_config": bool(env_config.networking),
            "has_security_policies": bool(env_config.security_policies)
        }
    
    def get_server_info(self, server_name: str) -> Dict[str, Any]:
        """Get detailed information about a server configuration."""
        if server_name not in self.server_configs:
            raise MCPError(f"Server configuration not found: {server_name}")
        
        server_config = self.server_configs[server_name]
        return {
            "name": server_config.name,
            "server_type": server_config.server_type,
            "base_config_keys": list(server_config.base_config.keys()),
            "environment_overrides": list(server_config.environment_overrides.keys()),
            "templates_count": len(server_config.templates),
            "validation_rules_count": len(server_config.validation_rules)
        }
    
    # Utility functions for templates
    def _generate_random_string(self, length: int = 16) -> str:
        """Generate random string for templates."""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _base64_encode(self, value: str) -> str:
        """Base64 encode for templates."""
        import base64
        return base64.b64encode(value.encode()).decode()
    
    def _url_encode(self, value: str) -> str:
        """URL encode for templates."""
        import urllib.parse
        return urllib.parse.quote(value)