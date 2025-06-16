# Deploy-Code Integration Guide

## Overview

Deploy-Code is a sophisticated deployment orchestration module that manages the entire CODE platform ecosystem. It provides unified deployment, monitoring, and lifecycle management for all CODE components including MCP servers, Circle of Experts, BashGod, and supporting infrastructure.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Integrations](#component-integrations)
3. [Deployment Flow](#deployment-flow)
4. [Integration Patterns](#integration-patterns)
5. [Configuration Management](#configuration-management)
6. [Monitoring & Observability](#monitoring--observability)
7. [Security Integration](#security-integration)
8. [Troubleshooting](#troubleshooting)

## Architecture Overview

Deploy-Code acts as the central orchestrator for the CODE platform, managing:

```
┌─────────────────────────────────────────────────────────────┐
│                     Deploy-Code Module                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Orchestrator│  │   Scheduler  │  │    Executor     │   │
│  │   Engine    │  │              │  │                 │   │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                 │                    │            │
│  ┌──────┴─────────────────┴────────────────────┴─────────┐ │
│  │            Service Registry & Resource Manager         │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
     ┌────────────────────────┼────────────────────────┐
     │                        │                        │
┌────┴─────┐          ┌───────┴──────┐         ┌──────┴──────┐
│   MCP    │          │   Circle of  │         │   Docker/   │
│ Servers  │          │   Experts    │         │ Kubernetes  │
└──────────┘          └──────────────┘         └─────────────┘
```

## Component Integrations

### 1. MCP Server Integration

Deploy-Code manages 27+ MCP servers with automatic lifecycle management:

#### Core MCP Servers
- **Filesystem MCP**: File system access and management
- **GitHub MCP**: Repository and code management
- **Memory MCP**: Persistent memory and context storage
- **PostgreSQL MCP**: Database operations
- **BashGod MCP**: Advanced system administration

#### Integration Points
```yaml
services:
  mcp_filesystem:
    enabled: true
    replicas: 2
    command: "npx"
    args: ["@modelcontextprotocol/server-filesystem", "--port", "3001"]
    dependencies: ["auth_service"]
    health_check:
      endpoint: "http://localhost:3001/health"
      interval_seconds: 30
```

#### MCP Communication Flow
```
┌──────────────┐     REST/gRPC     ┌─────────────────┐
│ Deploy-Code  ├──────────────────►│   MCP Server    │
│              │                    │                 │
│              │◄──────────────────┤                 │
└──────────────┘   Health Status   └─────────────────┘
       │
       │ Metrics
       ▼
┌──────────────┐
│  Prometheus  │
└──────────────┘
```

### 2. Circle of Experts Integration

Deploy-Code orchestrates the Circle of Experts AI consultation system:

#### Deployment Configuration
```yaml
circle_of_experts:
  enabled: true
  replicas: 3
  resources:
    cpu_cores: 4.0
    memory_mb: 8192
    gpu_count: 1
  env:
    OPENAI_API_KEY: "${OPENAI_API_KEY}"
    ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"
    GOOGLE_API_KEY: "${GOOGLE_API_KEY}"
```

#### Integration Flow
```
┌─────────────┐     Deploy      ┌──────────────────┐
│Deploy-Code  ├────────────────►│Circle of Experts │
│             │                 │                  │
│             │◄────────────────┤   ┌──────────┐  │
└─────────────┘   Status/Metrics│   │Expert 1  │  │
                                │   │Expert 2  │  │
                                │   │Expert N  │  │
                                │   └──────────┘  │
                                └──────────────────┘
```

### 3. BashGod Integration

Deploy-Code integrates with BashGod for system administration capabilities:

#### Security-First Deployment
```yaml
mcp_bash_god:
  enabled: true
  replicas: 1
  env:
    BASH_GOD_MODE: "restricted"
    MAX_CONCURRENT_COMMANDS: "10"
  security:
    sandboxed: true
    capabilities:
      - CAP_SYS_ADMIN
      - CAP_NET_ADMIN
```

#### Command Execution Flow
```
┌─────────────┐    Secure Channel   ┌─────────────┐
│Deploy-Code  ├────────────────────►│   BashGod   │
│             │                     │             │
│             │◄────────────────────┤  ┌───────┐ │
└─────────────┘   Execution Result  │  │Sandbox│ │
                                    │  └───────┘ │
                                    └─────────────┘
```

### 4. Docker/Kubernetes Integration

Deploy-Code supports multiple container orchestration platforms:

#### Docker Integration
```python
# Deploy service using Docker
async def deploy_docker_service(self, service_config):
    container = await self.docker_client.containers.run(
        image=service_config.image,
        ports=service_config.ports,
        environment=service_config.env,
        volumes=service_config.volumes,
        detach=True,
        name=f"code-{service_config.name}"
    )
    return container.id
```

#### Kubernetes Integration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: code-platform-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: code-service
  template:
    metadata:
      labels:
        app: code-service
    spec:
      containers:
      - name: service
        image: code-platform:latest
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
```

### 5. Monitoring Integration

Deploy-Code integrates with Prometheus and Grafana for comprehensive monitoring:

#### Prometheus Configuration
```yaml
monitoring:
  prometheus:
    endpoint: "http://localhost:9090"
    scrape_interval: 15
    retention_days: 30
```

#### Grafana Dashboards
- CODE Platform Overview
- Service Health Status
- Resource Usage Metrics
- Deployment History

#### Metrics Collection Flow
```
┌─────────────┐   Metrics Export   ┌─────────────┐
│  Services   ├───────────────────►│ Prometheus  │
└─────────────┘                    └──────┬──────┘
                                          │
┌─────────────┐                          │
│Deploy-Code  ├──────────────────────────┘
│  Metrics    │     Query Metrics
└─────────────┘
```

## Deployment Flow

### Sequential Deployment Process

```
┌────────────────────────────────────────────────────────────┐
│                  Deployment Orchestration                   │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Phase 1: Pre-deployment Validation                        │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐             │
│  │Validate  │─►│Resource  │─►│Network     │             │
│  │Config    │  │Check     │  │Validation  │             │
│  └──────────┘  └──────────┘  └────────────┘             │
│                                                            │
│  Phase 2: Infrastructure Setup                             │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐             │
│  │Database  │─►│Redis     │─►│Message     │             │
│  │Setup     │  │Setup     │  │Queue       │             │
│  └──────────┘  └──────────┘  └────────────┘             │
│                                                            │
│  Phase 3: Core Services                                    │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐             │
│  │Auth      │─►│MCP       │─►│API         │             │
│  │Service   │  │Servers   │  │Gateway     │             │
│  └──────────┘  └──────────┘  └────────────┘             │
│                                                            │
│  Phase 4: Application Layer                                │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐             │
│  │Circle of │─►│Code Base │─►│Monitoring  │             │
│  │Experts   │  │Crawler   │  │Stack       │             │
│  └──────────┘  └──────────┘  └────────────┘             │
│                                                            │
│  Phase 5: Post-deployment                                  │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐             │
│  │Health    │─►│Alerts    │─►│State       │             │
│  │Checks    │  │Setup     │  │Backup      │             │
│  └──────────┘  └──────────┘  └────────────┘             │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Dependency Resolution

Deploy-Code automatically resolves service dependencies:

```python
# Example dependency graph
dependencies = {
    "api_gateway": ["auth_service", "circle_of_experts"],
    "circle_of_experts": ["redis", "postgresql"],
    "mcp_memory": ["redis"],
    "auth_service": ["postgresql", "redis"]
}
```

## Integration Patterns

### 1. Service Discovery Pattern

```python
# Automatic service registration
async def register_service(self, service_name: str, endpoint: str):
    await self.service_registry.register(
        name=service_name,
        endpoint=endpoint,
        health_check=f"{endpoint}/health"
    )
```

### 2. Circuit Breaker Pattern

```python
# Fault tolerance for service calls
async def call_service_with_circuit_breaker(self, service: str):
    if not await self.circuit_breaker.can_execute(service):
        raise ServiceUnavailableError(f"{service} circuit breaker open")
    
    try:
        result = await self.execute_service_call(service)
        await self.circuit_breaker.record_success(service)
        return result
    except Exception as e:
        await self.circuit_breaker.record_failure(service)
        raise
```

### 3. Health Check Pattern

```python
# Unified health checking
async def check_service_health(self, service: str) -> bool:
    health_endpoint = f"http://{service}/health"
    try:
        response = await self.http_client.get(health_endpoint)
        return response.status == 200
    except:
        return False
```

## Configuration Management

### Environment Variables

Deploy-Code uses environment variables for sensitive configuration:

```bash
# Required environment variables
export JWT_SECRET="your-secret-key"
export MCP_AUTH_TOKEN="mcp-auth-token"
export GITHUB_TOKEN="github-personal-access-token"
export OPENAI_API_KEY="openai-api-key"
export ANTHROPIC_API_KEY="anthropic-api-key"
```

### Dynamic Configuration

```python
# Runtime configuration updates
async def update_service_config(self, service: str, config: dict):
    await self.config_manager.update(service, config)
    await self.restart_service(service)
```

## Security Integration

### Authentication Flow

```
┌──────────┐    JWT Token    ┌─────────────┐    Validate    ┌──────────┐
│  Client  ├─────────────────►│Deploy-Code  ├───────────────►│   Auth   │
│          │                  │             │                │ Service  │
│          │◄─────────────────┤             │◄───────────────┤          │
└──────────┘    API Response  └─────────────┘    Auth Result └──────────┘
```

### RBAC Integration

```yaml
rbac:
  roles:
    - name: admin
      permissions: ["*"]
    - name: operator
      permissions: ["deploy", "status", "restart"]
    - name: viewer
      permissions: ["status", "health"]
```

## Troubleshooting

### Common Integration Issues

#### 1. MCP Server Connection Failures

**Symptom**: MCP servers fail to register or respond to health checks

**Solution**:
```bash
# Check MCP server logs
docker logs code-mcp-filesystem

# Verify network connectivity
curl http://localhost:3001/health

# Check authentication token
echo $MCP_AUTH_TOKEN
```

#### 2. Service Dependency Failures

**Symptom**: Services fail to start due to missing dependencies

**Solution**:
```python
# Use deploy-code validation
deploy_code = DeployCode()
validation = await deploy_code.validate()
print(validation.errors)
```

#### 3. Resource Allocation Issues

**Symptom**: Services fail due to insufficient resources

**Solution**:
```bash
# Check resource availability
deploy-code status --detailed

# Adjust resource limits in deploy-code.yaml
resources:
  cpu_cores: 2.0  # Reduce if needed
  memory_mb: 2048
```

#### 4. Network Configuration Problems

**Symptom**: Services cannot communicate with each other

**Solution**:
```bash
# Verify network setup
docker network ls
docker network inspect code-network

# Check port allocations
netstat -tlnp | grep -E "(3001|8080|9090)"
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Set debug environment
export RUST_LOG=debug
export DEPLOY_CODE_DEBUG=true

# Run with verbose output
deploy-code deploy --verbose --dry-run
```

### Health Check Endpoints

All integrated services expose standardized health endpoints:

- MCP Servers: `http://localhost:300X/health`
- Circle of Experts: `http://localhost:8080/health`
- Auth Service: `http://localhost:8000/health`
- API Gateway: `http://localhost:80/health`

### Recovery Procedures

#### Automatic Recovery
```python
# Deploy-Code automatically attempts recovery
recovery_manager.attempt_recovery(
    service="mcp_filesystem",
    max_retries=3,
    backoff_seconds=30
)
```

#### Manual Recovery
```bash
# Stop all services
deploy-code stop --all --timeout 60

# Clean up resources
deploy-code cleanup

# Restart deployment
deploy-code deploy --force
```

## Best Practices

1. **Always validate before deployment**
   ```bash
   deploy-code validate
   ```

2. **Use dry-run for testing**
   ```bash
   deploy-code deploy --dry-run
   ```

3. **Monitor deployment progress**
   ```bash
   deploy-code status --watch
   ```

4. **Backup state before major changes**
   ```bash
   deploy-code backup --state
   ```

5. **Use phased deployments for production**
   ```bash
   deploy-code deploy --phases "validation,resources,network,deployment"
   ```

## Conclusion

Deploy-Code provides a robust integration layer for the entire CODE platform ecosystem. By following this guide and understanding the integration patterns, you can effectively deploy and manage all CODE components in a unified, reliable manner.

For additional support, refer to:
- [API Documentation](../API_INTEGRATION_GUIDE.md)
- [MCP Server Guide](../ai_docs/infrastructure/MCP_INTEGRATION_GUIDE.md)
- [Troubleshooting Guide](../TROUBLESHOOTING.md)