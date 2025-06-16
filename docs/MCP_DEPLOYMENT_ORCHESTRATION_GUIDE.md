# MCP Deployment Orchestration and Automation Guide

## Overview

The MCP Deployment Orchestration system provides comprehensive automated deployment capabilities for MCP servers with dependency management, health validation, error handling, and real-time monitoring.

## Architecture

### Core Components

1. **MCPDeploymentOrchestrator** - Core orchestration engine
2. **DeploymentConfigManager** - Configuration management and templating
3. **HealthValidator** - Automated health checks and validation
4. **RollbackManager** - Error handling and rollback mechanisms
5. **DeploymentMonitor** - Real-time monitoring and status reporting

### Key Features

- **Dependency Resolution** - Automatic server dependency ordering
- **Parallel Deployment** - Safe concurrent deployment where possible
- **Configuration Management** - Environment-specific settings with templating
- **Health Validation** - Comprehensive health checks with custom validators
- **Rollback Mechanisms** - Automatic rollback on failure with multiple strategies
- **Real-time Monitoring** - WebSocket-based monitoring with metrics collection
- **CLI Tools** - Command-line interface for deployment operations

## Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Make CLI tools executable
chmod +x src/mcp/deployment/cli.py
chmod +x scripts/deploy_mcp_servers.py
```

### 2. Configuration Setup

Create environment configurations:

```bash
# Create configuration directories
mkdir -p deploy/config/environments
mkdir -p deploy/config/servers
mkdir -p deploy/deployments
mkdir -p deploy/health-checks
```

### 3. Basic Deployment

```bash
# Using the CLI tool
./src/mcp/deployment/cli.py deploy start deploy/deployments/mcp-production-deployment.yaml --environment production

# Using the automation script
./scripts/deploy_mcp_servers.py deploy/deployments/mcp-production-deployment.yaml --environment production
```

## Configuration Management

### Environment Configuration

Environment configurations define environment-specific variables, secrets, and policies:

```yaml
# deploy/config/environments/production.yaml
variables:
  db_host: "{{ env('DB_HOST') or 'localhost' }}"
  api_port: 8000
  log_level: "INFO"

secrets:
  db_password: "DB_PASSWORD"
  api_key: "API_KEY"

resource_limits:
  cpu_cores: 4
  memory_gb: 8

security_policies:
  require_mfa: true
  encrypt_at_rest: true
```

### Server Configuration

Server configurations define server-specific settings with environment overrides:

```yaml
# deploy/config/servers/brave-search.yaml
name: brave-search
server_type: search

base_config:
  timeout_seconds: 30
  retry_attempts: 3
  api:
    rate_limit_per_minute: 100

environment_overrides:
  production:
    timeout_seconds: 15
    api:
      rate_limit_per_minute: 500

templates:
  api_key: "{{ env.brave_api_key }}"
  timeout: "{{ config.timeout_seconds }}"

validation_rules:
  - "required:api_key"
  - "format:timeout_seconds:^[0-9]+$"
```

### Deployment Specification

Deployment specifications define the complete deployment plan:

```yaml
# deploy/deployments/mcp-production-deployment.yaml
metadata:
  name: "mcp-production-deployment"
  environment: "production"

servers:
  - name: "brave-search"
    server_type: "search"
    priority: 100
    parallel_safe: true
    dependencies: []
    timeout_seconds: 300
    retry_attempts: 3
    health_checks:
      - "http_health"
      - "tcp_connectivity"

  - name: "security-scanner"
    server_type: "security"
    priority: 90
    parallel_safe: true
    dependencies: []
    timeout_seconds: 600

deployment_settings:
  parallel_deployment: true
  rollback_on_failure: true
  health_checks_enabled: true
  monitoring_enabled: true
```

## Health Validation

### Built-in Health Check Types

1. **HTTP** - Web endpoint health checks
2. **TCP** - Port connectivity checks
3. **Command** - Shell command execution
4. **File System** - File/directory validation
5. **Custom** - User-defined validation functions

### Health Check Configuration

```yaml
# deploy/health-checks/standard-checks.yaml
health_checks:
  - name: "http_health_api"
    type: "http"
    timeout_seconds: 15
    retry_attempts: 3
    critical: true
    tags: ["http", "api", "core"]
    config:
      url: "http://localhost:8000/health"
      expected_status: [200]
      expected_body: "healthy"

  - name: "tcp_api_port"
    type: "tcp"
    config:
      host: "localhost"
      port: 8000

  - name: "filesystem_health"
    type: "file_system"
    config:
      path: "/tmp"
      check_readable: true
      check_writable: true
      min_free_space_mb: 100
```

### Custom Health Checks

```python
from src.mcp.deployment.health_validator import HealthValidator

async def custom_database_check(config):
    # Custom validation logic
    return {
        "status": "healthy",
        "message": "Database connection successful",
        "details": {"connections": 10}
    }

# Register custom check
health_validator = HealthValidator()
health_validator.register_custom_function("database_check", custom_database_check)
```

## Rollback Management

### Rollback Strategies

1. **Immediate** - Immediate rollback on first failure
2. **Batch** - Rollback entire batch on failure
3. **Graceful** - Careful rollback with cleanup
4. **Aggressive** - Fast rollback without cleanup
5. **Manual** - Require manual approval

### Creating Snapshots

```python
from src.mcp.deployment.rollback_manager import RollbackManager

rollback_manager = RollbackManager()

# Create deployment snapshot
snapshot = await rollback_manager.create_deployment_snapshot(
    deployment_id="deploy_123",
    server_name="brave-search",
    state_data={"status": "running"},
    config_data={"api_key": "..."},
    files_to_backup=["/app/config.yaml"]
)
```

### Executing Rollback

```python
# Create rollback plan
plan = await rollback_manager.create_rollback_plan(
    deployment_id="deploy_123",
    failed_servers=["brave-search"],
    rollback_strategy=RollbackStrategy.GRACEFUL
)

# Execute rollback
results = await rollback_manager.execute_rollback_plan(plan)
```

## Monitoring and Status

### Real-time Monitoring

The deployment monitor provides real-time updates via WebSocket:

```python
from src.mcp.deployment.deployment_monitor import DeploymentMonitor

monitor = DeploymentMonitor(websocket_port=8765)
await monitor.start_monitoring()

# Monitor deployment
await monitor.start_deployment_monitoring(
    deployment_id="deploy_123",
    total_servers=5,
    server_names=["server1", "server2", "server3", "server4", "server5"]
)
```

### WebSocket Client Example

```javascript
const ws = new WebSocket('ws://localhost:8765');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    if (data.type === 'deployment_update') {
        console.log('Deployment progress:', data.data.progress_percentage);
    } else if (data.type === 'monitoring_event') {
        console.log('Event:', data.data.event_type, data.data.server_name);
    }
};
```

### Metrics Collection

```python
# Record performance metrics
await monitor.record_performance_metrics(
    deployment_id="deploy_123",
    server_name="brave-search",
    metrics={
        "cpu_usage": 45.2,
        "memory_usage": 62.1,
        "response_time_ms": 123.4
    }
)
```

## CLI Usage

### Deployment Commands

```bash
# Start deployment
./src/mcp/deployment/cli.py deploy start deployment.yaml --environment production

# Show deployment plan (dry run)
./src/mcp/deployment/cli.py deploy start deployment.yaml --dry-run

# Check deployment status
./src/mcp/deployment/cli.py deploy status deploy_123

# List recent deployments
./src/mcp/deployment/cli.py deploy list --limit 10
```

### Monitoring Commands

```bash
# Start monitoring server
./src/mcp/deployment/cli.py monitor start --port 8765

# Show deployment status
./src/mcp/deployment/cli.py monitor show deploy_123

# Show recent events
./src/mcp/deployment/cli.py monitor show --events

# Show system metrics
./src/mcp/deployment/cli.py monitor show --metrics
```

### Rollback Commands

```bash
# Start rollback
./src/mcp/deployment/cli.py rollback start deploy_123 --servers server1,server2

# Check rollback status
./src/mcp/deployment/cli.py rollback status rollback_456

# List available snapshots
./src/mcp/deployment/cli.py rollback list
```

### Configuration Commands

```bash
# Show resolved configuration
./src/mcp/deployment/cli.py config show brave-search production

# Validate all configurations
./src/mcp/deployment/cli.py config validate

# List environments and servers
./src/mcp/deployment/cli.py config list
```

### Health Check Commands

```bash
# Register health checks
./src/mcp/deployment/cli.py health register health-checks.yaml

# Run specific health check
./src/mcp/deployment/cli.py health run http_health_api

# Run all health checks
./src/mcp/deployment/cli.py health run --all

# Run checks by tags
./src/mcp/deployment/cli.py health run --tags http,api

# List registered checks
./src/mcp/deployment/cli.py health list
```

## Automation Script Usage

### Basic Usage

```bash
# Deploy with all features enabled
./scripts/deploy_mcp_servers.py deployment.yaml --environment production

# Dry run deployment
./scripts/deploy_mcp_servers.py deployment.yaml --dry-run

# Disable automatic rollback
./scripts/deploy_mcp_servers.py deployment.yaml --no-rollback

# Sequential deployment (disable parallelization)
./scripts/deploy_mcp_servers.py deployment.yaml --sequential

# Disable monitoring
./scripts/deploy_mcp_servers.py deployment.yaml --no-monitoring

# Custom directories
./scripts/deploy_mcp_servers.py deployment.yaml \
    --config-dir /custom/config \
    --backup-dir /custom/backups

# Verbose output
./scripts/deploy_mcp_servers.py deployment.yaml --verbose
```

## Advanced Features

### Custom Deployment Hooks

```python
from src.mcp.deployment.orchestrator import MCPDeploymentOrchestrator, DeploymentPhase

orchestrator = MCPDeploymentOrchestrator()

async def pre_deployment_hook(plan, stage):
    if stage == "pre":
        print(f"Starting deployment: {plan.deployment_id}")

# Register hook
orchestrator.register_deployment_hook(
    DeploymentPhase.PRE_VALIDATION,
    pre_deployment_hook
)
```

### Custom Rollback Actions

```python
from src.mcp.deployment.rollback_manager import RollbackManager

async def custom_cleanup_action(action):
    # Custom cleanup logic
    print(f"Performing custom cleanup for {action.server_name}")

rollback_manager = RollbackManager()
rollback_manager.register_custom_action_handler("custom_cleanup", custom_cleanup_action)
```

### Environment-Specific Templates

Configuration templates support Jinja2 templating with custom functions:

```yaml
# Template with custom functions
database_url: "postgresql://{{ env('DB_USER') }}:{{ env('DB_PASS') }}@{{ env('DB_HOST') }}/{{ env('DB_NAME') }}"
secret_key: "{{ random_string(32) }}"
encoded_value: "{{ base64_encode(config.secret) }}"
current_time: "{{ now().isoformat() }}"
```

## Best Practices

### Configuration Management

1. **Environment Separation** - Keep environment configs separate and secure
2. **Secret Management** - Use environment variables for sensitive data
3. **Validation Rules** - Define validation rules for critical configurations
4. **Template Testing** - Test configuration templates before deployment

### Deployment Strategy

1. **Dependency Management** - Clearly define server dependencies
2. **Parallel Safety** - Mark servers as parallel-safe only when appropriate
3. **Health Checks** - Define comprehensive health checks for all servers
4. **Rollback Strategy** - Plan rollback strategies for each deployment

### Monitoring and Alerting

1. **Real-time Monitoring** - Enable monitoring for production deployments
2. **Alert Thresholds** - Configure appropriate alert thresholds
3. **Performance Tracking** - Monitor key performance indicators
4. **Event Logging** - Maintain comprehensive event logs

### Security Considerations

1. **Access Control** - Implement proper access controls for deployment operations
2. **Secret Protection** - Never store secrets in configuration files
3. **Audit Logging** - Enable audit logging for all deployment activities
4. **Network Security** - Use secure communication channels

## Troubleshooting

### Common Issues

1. **Dependency Circular References**
   ```
   Error: Circular dependency detected in deployment plan involving 'server-a'
   ```
   - Solution: Review and fix circular dependencies in server specifications

2. **Configuration Template Errors**
   ```
   Error: Template processing failed for 'api_key': undefined variable
   ```
   - Solution: Ensure all template variables are defined in environment configuration

3. **Health Check Failures**
   ```
   Warning: Health check 'http_health' failed: Connection refused
   ```
   - Solution: Verify server is running and accessible on specified port

4. **Rollback Failures**
   ```
   Error: Rollback action failed: restore_config_server-1_123
   ```
   - Solution: Check rollback logs and verify snapshot integrity

### Debug Mode

Enable verbose logging for debugging:

```bash
# CLI with verbose output
./src/mcp/deployment/cli.py --verbose deploy start deployment.yaml

# Automation script with debug logging
./scripts/deploy_mcp_servers.py deployment.yaml --verbose
```

### Log Analysis

Check deployment logs for detailed information:

```bash
# View deployment logs
tail -f deploy/logs/deployment_*.log

# View monitoring logs
tail -f deploy/logs/monitoring_*.log

# View rollback logs
tail -f deploy/logs/rollback_*.log
```

## Integration

### CI/CD Integration

```yaml
# GitHub Actions example
name: Deploy MCP Servers
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Deploy MCP Servers
        run: |
          ./scripts/deploy_mcp_servers.py \
            deploy/deployments/mcp-production-deployment.yaml \
            --environment production \
            --no-monitoring
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          API_KEY: ${{ secrets.API_KEY }}
```

### Kubernetes Integration

The deployment system can be integrated with Kubernetes for container orchestration:

```yaml
# k8s/mcp-deployment.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: mcp-deployment
spec:
  template:
    spec:
      containers:
      - name: deployment
        image: mcp-deployment:latest
        command: ["./scripts/deploy_mcp_servers.py"]
        args: ["deployment.yaml", "--environment", "production"]
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
```

## Performance Optimization

### Parallel Deployment

- Mark independent servers as `parallel_safe: true`
- Group related servers in dependency chains
- Use appropriate timeout values
- Monitor resource usage during deployment

### Configuration Caching

- Enable configuration caching for large deployments
- Use configuration validation to catch errors early
- Pre-compile templates for faster processing

### Health Check Optimization

- Use appropriate timeout values for health checks
- Implement exponential backoff for retries
- Cache health check results when appropriate
- Use lightweight checks for frequent monitoring

## Support and Documentation

### Additional Resources

- [MCP Server Development Guide](./MCP_SERVER_DEVELOPMENT_GUIDE.md)
- [Configuration Reference](./CONFIGURATION_REFERENCE.md)
- [API Documentation](./API_DOCUMENTATION.md)
- [Security Guidelines](./SECURITY_GUIDELINES.md)

### Getting Help

1. Check the troubleshooting section above
2. Review the configuration examples
3. Enable verbose logging for detailed error information
4. Consult the API documentation for integration details

This deployment orchestration system provides a robust foundation for automated MCP server deployment with comprehensive monitoring, error handling, and recovery capabilities.