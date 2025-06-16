# Deploy-Code Module API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Rust API](#rust-api)
3. [Python API](#python-api)
4. [CLI Commands](#cli-commands)
5. [Configuration Schema](#configuration-schema)
6. [Error Codes](#error-codes)
7. [Extending the Module](#extending-the-module)

## Overview

The Deploy-Code module provides a bulletproof deployment orchestrator for the CODE environment. It offers APIs in both Rust and Python, with a unified CLI interface for managing deployments.

### Key Features

- Multi-language support (Rust core with Python bindings)
- Service dependency management
- Health checking and monitoring
- Automatic rollback on failure
- Resource allocation and management
- Circuit breaker pattern for reliability
- Prometheus metrics integration

## Rust API

### Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
deploy-code = { path = "../deploy-code-module" }
```

### Core Types

#### DeploymentOrchestrator

The main orchestrator for managing deployments.

```rust
use deploy_code::{DeploymentOrchestrator, DeploymentConfig};
use std::path::Path;

// Create orchestrator
let config = DeploymentConfig::load(Path::new("deploy-code.yaml")).await?;
let orchestrator = DeploymentOrchestrator::new(config).await?;

// Deploy services
let report = orchestrator.deploy(None, None).await?;
println!("Deployment success: {}", report.success);
```

#### DeploymentConfig

Configuration structure for deployments.

```rust
use deploy_code::config::{DeploymentConfig, ServiceConfig, ResourceRequirements};
use std::collections::HashMap;

let mut config = DeploymentConfig::default();

// Add a service
let service = ServiceConfig {
    enabled: true,
    service_type: "container".to_string(),
    container_image: "myapp:latest".to_string(),
    replicas: 2,
    resources: ResourceRequirements {
        cpu_cores: 1.0,
        memory_mb: 1024,
        storage_gb: 10,
        gpu_count: 0,
    },
    ports: vec![],
    environment: HashMap::new(),
    dependencies: vec!["database".to_string()],
    health_check: HealthCheckConfig {
        endpoint: "/health".to_string(),
        interval_seconds: 30,
        timeout_seconds: 10,
        retries: 3,
    },
};

config.services.insert("myapp".to_string(), service);
```

### Service Management

```rust
use deploy_code::services::{ServiceRegistry, ServiceStatus};

// Get service registry
let registry = ServiceRegistry::new();

// Register a service
registry.register("myapp", service_config).await?;

// Check service status
let status = registry.get_status("myapp").await?;
match status {
    ServiceStatus::Running => println!("Service is running"),
    ServiceStatus::Failed(err) => eprintln!("Service failed: {}", err),
    _ => {}
}

// Stop a service
registry.stop_service("myapp", Duration::from_secs(30)).await?;
```

### Resource Management

```rust
use deploy_code::resources::ResourceManager;

let resource_manager = ResourceManager::new();

// Allocate resources
let allocation = resource_manager.allocate(
    "myapp",
    ResourceRequirements {
        cpu_cores: 2.0,
        memory_mb: 4096,
        storage_gb: 50,
        gpu_count: 1,
    }
).await?;

// Check resource availability
let available = resource_manager.check_availability(&requirements).await?;
if available {
    println!("Resources available for deployment");
}
```

### Monitoring Integration

```rust
use deploy_code::monitoring::MetricsCollector;

let metrics = MetricsCollector::new();

// Get current metrics
let system_metrics = metrics.get_system_metrics().await?;
println!("CPU Usage: {}%", system_metrics.cpu_usage);
println!("Memory Usage: {}%", system_metrics.memory_usage);

// Get service metrics
let service_metrics = metrics.get_service_metrics("myapp").await?;
```

### Complete Example

```rust
use deploy_code::{DeploymentOrchestrator, DeploymentConfig};
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config_path = Path::new("deploy-code.yaml");
    let config = DeploymentConfig::load(config_path).await?;
    
    // Create orchestrator
    let orchestrator = DeploymentOrchestrator::new(config).await?;
    
    // Deploy specific services
    let services = vec!["postgresql", "redis", "auth_service"];
    let report = orchestrator.deploy(Some(services), None).await?;
    
    if report.success {
        println!("Deployment successful!");
        println!("Deployed: {}/{}", report.deployed_services, report.total_services);
        
        // Wait for services to be healthy
        orchestrator.wait_for_healthy(Duration::from_secs(300)).await?;
        
        // Get status
        let status = orchestrator.get_status(true).await?;
        println!("Overall health: {:?}", status.overall_health);
    } else {
        eprintln!("Deployment failed!");
        for error in &report.errors {
            eprintln!("  - {}", error);
        }
    }
    
    Ok(())
}
```

## Python API

### Installation

```bash
pip install deploy-code
```

### DeployCode Class

The main class for managing deployments from Python.

```python
from deploy_code import DeployCode, DeploymentStatus, ServiceStatus
import asyncio

# Initialize
deployer = DeployCode(
    config_path="deploy-code.yaml",
    dry_run=False,
    force=False
)

# Deploy services
async def deploy():
    report = await deployer.deploy(
        services=["postgresql", "redis"],
        skip_phases=["monitoring"]
    )
    
    if report.success:
        print(f"Deployed {report.deployed_services} services")
    else:
        print(f"Deployment failed: {report.errors}")
```

### Methods

#### deploy(services=None, skip_phases=None)

Deploy CODE services.

```python
# Deploy all services
report = await deployer.deploy()

# Deploy specific services
report = await deployer.deploy(services=["auth_service", "api_gateway"])

# Skip certain phases
report = await deployer.deploy(skip_phases=["monitoring", "logging"])
```

#### stop(timeout=30)

Stop all CODE services.

```python
await deployer.stop(timeout=60)  # 60 second timeout
```

#### status(detailed=False)

Get status of all services.

```python
# Basic status
status = await deployer.status()
print(f"Running services: {status['running_services']}")

# Detailed status
detailed_status = await deployer.status(detailed=True)
for service, info in detailed_status['services'].items():
    print(f"{service}: {info['status']} - {info['health']}")
```

#### restart(services=None)

Restart services.

```python
# Restart all services
await deployer.restart()

# Restart specific services
await deployer.restart(services=["auth_service", "api_gateway"])
```

#### validate()

Validate deployment configuration.

```python
validation = await deployer.validate()
if validation['is_valid']:
    print("Configuration is valid")
else:
    for error in validation['errors']:
        print(f"Error: {error}")
```

#### health(format="json")

Get health status.

```python
health = await deployer.health(format="json")
print(f"Overall status: {health['status']}")
```

#### wait_for_healthy(timeout=300, check_interval=5)

Wait for all services to become healthy.

```python
healthy = await deployer.wait_for_healthy(timeout=600)
if healthy:
    print("All services are healthy!")
```

#### monitor_deployment(callback=None)

Monitor deployment progress.

```python
def progress_callback(status):
    print(f"Progress: {status['deployed_services']}/{status['total_services']}")

await deployer.monitor_deployment(callback=progress_callback)
```

### Complete Example

```python
import asyncio
from deploy_code import DeployCode, DeploymentStatus

async def main():
    # Initialize deployer
    deployer = DeployCode(config_path="deploy-code.yaml")
    
    # Validate configuration
    validation = await deployer.validate()
    if not validation['is_valid']:
        print("Invalid configuration!")
        return
    
    # Deploy services
    print("Starting deployment...")
    report = await deployer.deploy()
    
    if report.success:
        print(f"Successfully deployed {report.deployed_services} services")
        
        # Wait for health
        print("Waiting for services to be healthy...")
        healthy = await deployer.wait_for_healthy(timeout=300)
        
        if healthy:
            # Get final status
            status = await deployer.status(detailed=True)
            print(f"Overall health: {status['overall_health']}")
            
            # Monitor for a while
            await asyncio.sleep(60)
            
            # Get metrics
            metrics = deployer.get_metrics()
            print(f"CPU Usage: {metrics['cpu_percent']}%")
    else:
        print(f"Deployment failed: {report.errors}")
        
        # Get logs for debugging
        for service in ["auth_service", "api_gateway"]:
            logs = deployer.get_service_logs(service, lines=50)
            print(f"\n--- {service} logs ---")
            for line in logs:
                print(line.strip())

if __name__ == "__main__":
    asyncio.run(main())
```

## CLI Commands

### Global Options

```bash
deploy-code [OPTIONS] <COMMAND>

OPTIONS:
    -c, --config <FILE>      Configuration file path [default: deploy-code.yaml]
    -l, --log-level <LEVEL>  Log level (trace, debug, info, warn, error) [default: info]
    --dry-run                Simulate deployment without executing
    --force                  Force deployment even if health checks fail
```

### Commands

#### deploy

Deploy CODE services.

```bash
# Deploy all services
deploy-code deploy

# Deploy specific services
deploy-code deploy --services postgresql,redis,auth_service

# Skip monitoring phase
deploy-code deploy --skip-phases monitoring

# Dry run
deploy-code --dry-run deploy
```

#### stop

Stop all services.

```bash
# Stop with default timeout
deploy-code stop

# Stop with custom timeout
deploy-code stop --timeout 60
```

#### status

Check service status.

```bash
# Basic status
deploy-code status

# Detailed status
deploy-code status --detailed
```

#### restart

Restart services.

```bash
# Restart all
deploy-code restart

# Restart specific services
deploy-code restart --services auth_service,api_gateway
```

#### validate

Validate configuration.

```bash
deploy-code validate
```

#### health

Check health status.

```bash
# Default text format
deploy-code health

# JSON format
deploy-code health --format json

# YAML format
deploy-code health --format yaml
```

### Python CLI

The Python module also provides CLI functionality:

```bash
# Using Python module directly
python -m deploy_code deploy --services postgresql,redis

# With custom config
python -m deploy_code --config production.yaml deploy

# Status check
python -m deploy_code status --detailed
```

## Configuration Schema

### Root Configuration

```yaml
version: "1.0.0"
environment: production  # development, staging, production
dry_run: false

infrastructure:
  # Infrastructure configuration
  
security:
  # Security settings
  
deployment:
  # Deployment strategy
  
monitoring:
  # Monitoring configuration
  
services:
  # Service definitions
```

### Infrastructure Configuration

```yaml
infrastructure:
  container_runtime: Docker  # Docker, Podman, Containerd
  orchestrator: DockerCompose  # DockerCompose, Kubernetes, Swarm
  
  network:
    mode: Bridge  # Bridge, Host, Overlay
    cidr: "172.20.0.0/16"
    dns_servers:
      - "8.8.8.8"
      - "1.1.1.1"
    port_range:
      start: 30000
      end: 40000
      
  storage:
    data_dir: "/var/lib/deploy-code"
    log_dir: "/var/log/deploy-code"
    temp_dir: "/tmp/deploy-code"
    backup_dir: "/var/backups/deploy-code"
```

### Security Configuration

```yaml
security:
  tls_enabled: true
  cert_path: "/etc/deploy-code/certs/server.crt"
  key_path: "/etc/deploy-code/certs/server.key"
  
  auth:
    enabled: true
    method: JWT  # JWT, OAuth2, Basic
    token_expiry_seconds: 3600
    
  rbac:
    enabled: true
    roles:
      - name: admin
        permissions: ["*"]
      - name: operator
        permissions: ["deploy", "status", "restart"]
      - name: viewer
        permissions: ["status", "health"]
```

### Deployment Configuration

```yaml
deployment:
  strategy: Sequential  # Sequential, Parallel, RollingUpdate, BlueGreen
  max_parallel: 10
  health_check_interval: 30
  timeout_seconds: 300
  rollback_on_failure: true
```

### Service Definition

```yaml
services:
  service_name:
    enabled: true
    replicas: 2
    command: "python"
    args: ["-m", "myapp"]
    working_dir: "/app"
    dependencies: ["database", "cache"]
    
    env:
      DATABASE_URL: "${DATABASE_URL}"
      API_KEY: "${API_KEY}"
      
    resources:
      cpu_cores: 2.0
      memory_mb: 4096
      storage_gb: 20
      gpu_count: 0
      
    health_check:
      endpoint: "http://localhost:8080/health"
      # OR
      command: ["curl", "-f", "http://localhost:8080/health"]
      interval_seconds: 30
      timeout_seconds: 10
      retries: 3
      start_period_seconds: 60
      
    ports:
      - container_port: 8080
        host_port: 8080
        protocol: "tcp"
        
    volumes:
      - name: data
        mount_path: "/data"
        read_only: false
```

### Monitoring Configuration

```yaml
monitoring:
  enabled: true
  
  prometheus:
    endpoint: "http://localhost:9090"
    scrape_interval: 15
    retention_days: 30
    
  grafana:
    endpoint: "http://localhost:3000"
    dashboards:
      - "code-platform-overview"
      - "service-health"
      
  alerting:
    enabled: true
    webhook_url: "http://localhost:9093/api/v1/alerts"
    rules:
      - name: service_down
        condition: "up == 0"
        severity: Critical
      - name: high_cpu
        condition: "cpu_usage > 90"
        severity: Warning
```

## Error Codes

### Deployment Errors

| Code | Error | Description |
|------|-------|-------------|
| E001 | CONFIG_NOT_FOUND | Configuration file not found |
| E002 | CONFIG_INVALID | Configuration validation failed |
| E003 | BINARY_NOT_FOUND | Deploy-code binary not found |
| E004 | INSUFFICIENT_RESOURCES | Not enough resources available |
| E005 | SERVICE_START_FAILED | Service failed to start |
| E006 | HEALTH_CHECK_FAILED | Service health check failed |
| E007 | DEPENDENCY_FAILED | Service dependency not available |
| E008 | TIMEOUT_EXCEEDED | Operation timeout exceeded |
| E009 | ROLLBACK_FAILED | Rollback operation failed |
| E010 | NETWORK_ERROR | Network configuration error |

### Service Errors

| Code | Error | Description |
|------|-------|-------------|
| S001 | SERVICE_NOT_FOUND | Service not found in registry |
| S002 | SERVICE_ALREADY_EXISTS | Service already registered |
| S003 | INVALID_SERVICE_CONFIG | Invalid service configuration |
| S004 | PORT_CONFLICT | Port already in use |
| S005 | VOLUME_MOUNT_FAILED | Failed to mount volume |

### Example Error Handling

```python
from deploy_code import DeployCode, DeployCodeError

try:
    deployer = DeployCode(config_path="deploy-code.yaml")
    report = await deployer.deploy()
except DeployCodeError as e:
    if "E001" in str(e):
        print("Configuration file not found")
    elif "E004" in str(e):
        print("Insufficient resources for deployment")
    else:
        print(f"Deployment error: {e}")
```

## Extending the Module

### Adding Custom Services

#### 1. Define Service Configuration

Create a service configuration in YAML:

```yaml
services:
  my_custom_service:
    enabled: true
    service_type: "custom"
    command: "/usr/local/bin/my-service"
    args: ["--port", "8090"]
    resources:
      cpu_cores: 1.0
      memory_mb: 1024
    health_check:
      endpoint: "http://localhost:8090/health"
```

#### 2. Implement Custom Service Handler (Rust)

```rust
use deploy_code::services::{Service, ServiceStatus};
use async_trait::async_trait;

pub struct MyCustomService {
    config: ServiceConfig,
}

#[async_trait]
impl Service for MyCustomService {
    async fn start(&self) -> Result<()> {
        // Custom start logic
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        // Custom stop logic
        Ok(())
    }
    
    async fn health_check(&self) -> Result<ServiceStatus> {
        // Custom health check
        Ok(ServiceStatus::Running)
    }
}
```

#### 3. Register Custom Service Type

```rust
use deploy_code::services::ServiceRegistry;

let registry = ServiceRegistry::new();
registry.register_type("custom", |config| {
    Box::new(MyCustomService::new(config))
});
```

### Creating Custom Deployment Strategies

```rust
use deploy_code::orchestrator::DeploymentStrategy;
use async_trait::async_trait;

pub struct CanaryDeployment {
    canary_percentage: f32,
}

#[async_trait]
impl DeploymentStrategy for CanaryDeployment {
    async fn deploy(&self, services: Vec<String>) -> Result<DeploymentReport> {
        // Deploy canary percentage first
        let canary_count = (services.len() as f32 * self.canary_percentage) as usize;
        let canary_services = &services[..canary_count];
        
        // Deploy canary
        self.deploy_services(canary_services).await?;
        
        // Wait and check metrics
        tokio::time::sleep(Duration::from_secs(300)).await;
        
        if self.check_canary_health().await? {
            // Deploy remaining services
            self.deploy_services(&services[canary_count..]).await?;
        }
        
        Ok(DeploymentReport::success())
    }
}
```

### Adding Custom Monitoring

```python
from deploy_code import DeployCode
import prometheus_client

class MonitoredDeployCode(DeployCode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Create Prometheus metrics
        self.deployment_counter = prometheus_client.Counter(
            'deployments_total', 
            'Total number of deployments'
        )
        self.deployment_duration = prometheus_client.Histogram(
            'deployment_duration_seconds',
            'Deployment duration in seconds'
        )
    
    async def deploy(self, *args, **kwargs):
        with self.deployment_duration.time():
            report = await super().deploy(*args, **kwargs)
            
        self.deployment_counter.inc()
        return report
```

### Plugin System

Create a plugin for extended functionality:

```python
from deploy_code.plugins import Plugin
import asyncio

class SlackNotificationPlugin(Plugin):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    async def on_deployment_start(self, services):
        await self.send_notification(
            f"Starting deployment of {len(services)} services"
        )
    
    async def on_deployment_complete(self, report):
        if report.success:
            await self.send_notification(
                f"✅ Deployment successful! Deployed {report.deployed_services} services"
            )
        else:
            await self.send_notification(
                f"❌ Deployment failed! Errors: {report.errors}"
            )
    
    async def send_notification(self, message):
        # Send to Slack
        pass

# Use plugin
deployer = DeployCode(config_path="deploy-code.yaml")
deployer.add_plugin(SlackNotificationPlugin("https://hooks.slack.com/..."))
```

## Best Practices

1. **Always validate configuration before deployment**
   ```python
   validation = await deployer.validate()
   if not validation['is_valid']:
       raise Exception("Invalid configuration")
   ```

2. **Use dry-run for testing**
   ```bash
   deploy-code --dry-run deploy
   ```

3. **Monitor deployment progress**
   ```python
   await deployer.monitor_deployment(callback=progress_handler)
   ```

4. **Handle errors gracefully**
   ```python
   try:
       report = await deployer.deploy()
   except DeployCodeError as e:
       # Log error and attempt rollback
       await deployer.stop()
   ```

5. **Use health checks**
   ```python
   if await deployer.wait_for_healthy(timeout=300):
       print("Deployment successful and healthy")
   ```

## Support

For issues and questions:
- GitHub Issues: https://github.com/org/deploy-code/issues
- Documentation: https://deploy-code.readthedocs.io
- API Reference: https://docs.rs/deploy-code