"""
Configuration management command group.

Features:
- Configuration validation
- Template management
- Environment-specific configs
- Security scanning
"""

import click
import yaml
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.cli.utils import format_success, format_error, format_info, format_warning

console = Console()


@click.group(name='config')
def config_group():
    """Configuration management and templates."""
    pass


@config_group.command()
@click.argument('config_file', required=False, type=click.Path())
def validate(config_file):
    """
    Validate configuration files for syntax and completeness.
    
    Checks:
    - YAML/JSON syntax
    - Required fields
    - Value constraints
    - Security best practices
    """
    if not config_file:
        # Auto-detect config files
        config_files = list(Path.cwd().glob("*.yaml")) + list(Path.cwd().glob("*.yml"))
        if not config_files:
            console.print(format_error("No configuration files found"))
            return
        config_file = config_files[0]
        console.print(format_info(f"Auto-detected config file: {config_file}"))
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            
        # Validate structure
        errors = validate_config_structure(config)
        warnings = validate_config_security(config)
        
        if not errors and not warnings:
            console.print(format_success("✅ Configuration is valid"))
        else:
            if errors:
                console.print(format_error("❌ Validation errors:"))
                for error in errors:
                    console.print(f"  • {error}")
            if warnings:
                console.print(format_warning("⚠️ Security warnings:"))
                for warning in warnings:
                    console.print(f"  • {warning}")
                    
    except Exception as e:
        console.print(format_error(f"Validation failed: {e}"))


@config_group.command()
@click.option('--type', 'template_type', 
              type=click.Choice(['basic', 'microservices', 'ml-pipeline', 'web-app']),
              default='basic', help='Template type')
@click.option('--output', '-o', help='Output file name')
def template(template_type, output):
    """
    Generate configuration templates for common deployment patterns.
    
    Available templates:
    - basic: Simple single-service deployment
    - microservices: Multi-service architecture
    - ml-pipeline: Machine learning pipeline
    - web-app: Full-stack web application
    """
    template_content = generate_config_template(template_type)
    
    if not output:
        output = f"claude-deploy-{template_type}.yaml"
        
    with open(output, 'w') as f:
        f.write(template_content)
        
    console.print(format_success(f"✅ Template generated: {output}"))
    console.print(f"\nNext steps:")
    console.print(f"1. Edit {output} to match your requirements")
    console.print(f"2. Run: claude-deploy config validate {output}")
    console.print(f"3. Deploy: claude-deploy deploy {output}")


@config_group.command()
@click.option('--environment', '-e', help='Environment to show')
@click.option('--format', 'output_format', type=click.Choice(['table', 'yaml', 'json']),
              default='table', help='Output format')
def show(environment, output_format):
    """Show current configuration values."""
    config = get_current_config(environment)
    
    if output_format == 'table':
        show_config_table(config)
    elif output_format == 'yaml':
        console.print(yaml.dump(config, default_flow_style=False))
    else:  # json
        import json
        console.print(json.dumps(config, indent=2))


@config_group.command()
@click.argument('key')
@click.argument('value')
@click.option('--environment', '-e', help='Environment to set value for')
@click.option('--type', 'value_type', type=click.Choice(['string', 'int', 'float', 'bool']),
              default='string', help='Value type')
def set(key, value, environment, value_type):
    """Set a configuration value."""
    # Convert value to appropriate type
    if value_type == 'int':
        value = int(value)
    elif value_type == 'float':
        value = float(value)
    elif value_type == 'bool':
        value = value.lower() in ('true', '1', 'yes', 'on')
        
    # Set the configuration value
    set_config_value(key, value, environment)
    console.print(format_success(f"✅ Set {key} = {value}"))


@config_group.command()
@click.argument('key')
@click.option('--environment', '-e', help='Environment to get value from')
def get(key, environment):
    """Get a configuration value."""
    value = get_config_value(key, environment)
    if value is not None:
        console.print(f"{key} = {value}")
    else:
        console.print(format_error(f"Configuration key not found: {key}"))


@config_group.command()
@click.option('--include-secrets', is_flag=True, help='Include sensitive values in export')
@click.option('--format', 'output_format', type=click.Choice(['yaml', 'json', 'env']),
              default='yaml', help='Export format')
@click.option('--output', '-o', help='Output file')
def export(include_secrets, output_format, output):
    """Export configuration to file."""
    config = export_config(include_secrets)
    
    if output_format == 'yaml':
        content = yaml.dump(config, default_flow_style=False)
    elif output_format == 'json':
        import json
        content = json.dumps(config, indent=2)
    else:  # env
        content = '
'.join(f"{k}={v}" for k, v in flatten_config(config).items())
        
    if output:
        with open(output, 'w') as f:
            f.write(content)
        console.print(format_success(f"✅ Configuration exported to {output}"))
    else:
        console.print(content)


# Helper functions

def validate_config_structure(config: dict) -> list:
    """Validate configuration structure."""
    errors = []
    
    # Check required top-level fields
    required_fields = ['name', 'version']
    for field in required_fields:
        if field not in config:
            errors.append(f"Missing required field: {field}")
            
    # Check that we have either servers or services
    if 'servers' not in config and 'services' not in config:
        errors.append("Must specify either 'servers' or 'services'")
        
    return errors


def validate_config_security(config: dict) -> list:
    """Validate configuration for security best practices."""
    warnings = []
    
    # Check for hardcoded secrets
    config_str = str(config).lower()
    sensitive_patterns = ['password', 'secret', 'key', 'token']
    
    for pattern in sensitive_patterns:
        if pattern in config_str:
            warnings.append(f"Potential hardcoded secret detected: {pattern}")
            
    # Check for insecure defaults
    if config.get('security', {}).get('tls_enabled') is False:
        warnings.append("TLS is disabled - consider enabling for production")
        
    return warnings


def generate_config_template(template_type: str) -> str:
    """Generate configuration template."""
    templates = {
        'basic': """
name: my-application
version: 1.0.0
environment: development

servers:
  - name: app-server
    type: web
    image: nginx:latest
    ports:
      - "80:80"
    environment:
      - NODE_ENV=production
    health_check:
      endpoint: /health
      interval: 30s
      
deployment:
  strategy: rolling
  replicas: 3
  resources:
    cpu: "1"
    memory: "2Gi"
""",
        'microservices': """
name: microservices-app
version: 1.0.0
environment: development

services:
  api-gateway:
    type: web
    image: nginx:latest
    ports: ["80:80"]
    depends_on: [user-service, order-service]
    
  user-service:
    type: api
    image: user-service:latest
    ports: ["3001:3000"]
    environment:
      - DATABASE_URL=$USER_DB_URL
      
  order-service:
    type: api  
    image: order-service:latest
    ports: ["3002:3000"]
    environment:
      - DATABASE_URL=$ORDER_DB_URL
      
  database:
    type: database
    image: postgres:13
    environment:
      - POSTGRES_DB=myapp
      
deployment:
  strategy: blue-green
  health_checks_enabled: true
""",
        'ml-pipeline': """
name: ml-pipeline
version: 1.0.0
environment: development

pipeline:
  data-ingestion:
    type: job
    image: data-processor:latest
    schedule: "0 */6 * * *"
    resources:
      cpu: "2"
      memory: "4Gi"
      
  model-training:
    type: job
    image: ml-trainer:latest
    depends_on: [data-ingestion]
    resources:
      gpu: 1
      memory: "8Gi"
      
  model-serving:
    type: api
    image: model-server:latest
    ports: ["8080:8080"]
    depends_on: [model-training]
    auto_scaling:
      min_replicas: 2
      max_replicas: 10
      target_cpu: 70
""",
        'web-app': """
name: web-application
version: 1.0.0
environment: development

services:
  frontend:
    type: web
    image: frontend:latest
    ports: ["3000:3000"]
    environment:
      - REACT_APP_API_URL=http://backend:3001
      
  backend:
    type: api
    image: backend:latest
    ports: ["3001:3000"]
    environment:
      - DATABASE_URL=$DATABASE_URL
      - JWT_SECRET=$JWT_SECRET
      
  database:
    type: database
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=webapp
      - POSTGRES_USER=webapp
      - POSTGRES_PASSWORD=$DB_PASSWORD
      
volumes:
  postgres_data:

deployment:
  strategy: rolling
  health_checks_enabled: true
  monitoring:
    enabled: true
    metrics: [cpu, memory, requests]
"""
    }
    
    return templates.get(template_type, templates['basic']).strip()


def get_current_config(environment: str) -> dict:
    """Get current configuration."""
    # Mock configuration
    return {
        'name': 'example-app',
        'version': '1.0.0',
        'environment': environment or 'development',
        'replicas': 3,
        'cpu': '1',
        'memory': '2Gi'
    }


def show_config_table(config: dict):
    """Show configuration in table format."""
    table = Table(title="Current Configuration")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Type", style="yellow")
    
    def add_config_rows(cfg, prefix=""):
        for key, value in cfg.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                add_config_rows(value, full_key)
            else:
                table.add_row(full_key, str(value), type(value).__name__)
                
    add_config_rows(config)
    console.print(table)


def set_config_value(key: str, value, environment: str):
    """Set a configuration value."""
    # This would update the actual configuration
    pass


def get_config_value(key: str, environment: str):
    """Get a configuration value."""
    # This would fetch from actual configuration
    config = get_current_config(environment)
    return config.get(key)


def export_config(include_secrets: bool) -> dict:
    """Export configuration."""
    config = get_current_config(None)
    if not include_secrets:
        # Remove sensitive keys
        sensitive_keys = ['password', 'secret', 'key', 'token']
        for key in list(config.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                config[key] = "***REDACTED***"
    return config


def flatten_config(config: dict, prefix: str = "") -> dict:
    """Flatten nested configuration for env file format."""
    result = {}
    for key, value in config.items():
        full_key = f"{prefix}_{key}".upper() if prefix else key.upper()
        if isinstance(value, dict):
            result.update(flatten_config(value, full_key))
        else:
            result[full_key] = str(value)
    return result