# Deploy-Code Quick Reference

## Essential Commands

### Deployment Operations
```bash
# Full platform deployment
deploy-code deploy

# Deploy specific services
deploy-code deploy --services "mcp_filesystem,auth_service"

# Dry run (test without executing)
deploy-code deploy --dry-run

# Force deployment (ignore errors)
deploy-code deploy --force

# Skip specific phases
deploy-code deploy --skip-phases "validation,health"
```

### Status and Health
```bash
# Overall platform status
deploy-code status

# Detailed status with metrics
deploy-code status --detailed

# Health check
deploy-code health

# Service-specific status
deploy-code status --service mcp_filesystem
```

### Service Management
```bash
# Restart all services
deploy-code restart

# Restart specific services
deploy-code restart --services "mcp_filesystem,redis"

# Stop all services
deploy-code stop --all

# Scale service replicas
deploy-code scale --service circle_of_experts --replicas 5
```

### Configuration
```bash
# Validate configuration
deploy-code validate

# Show current configuration
deploy-code config --show

# Update environment variable
deploy-code config --update-env GITHUB_TOKEN=new_token
```

## Python API Usage

### Basic Operations
```python
import asyncio
from deploy_code import DeployCode

async def main():
    # Initialize deployer
    deployer = DeployCode(config_path="deploy-code.yaml")
    
    # Deploy all services
    report = await deployer.deploy()
    print(f"Deployed {report.deployed_services}/{report.total_services}")
    
    # Check status
    status = await deployer.get_status(detailed=True)
    print(f"Platform health: {status.overall_health}")
    
    # Restart specific service
    await deployer.restart(["mcp_filesystem"])

if __name__ == "__main__":
    asyncio.run(main())
```

### Service Health Monitoring
```python
async def monitor_services():
    deployer = DeployCode()
    
    # Get health report
    health = await deployer.get_health()
    print(f"Health Score: {health.score}/100")
    
    # Check specific service
    status = await deployer.get_status(detailed=True)
    for service, details in status.services.items():
        print(f"{service}: {details.status} ({details.health})")
```

## Configuration Quick Reference

### Essential Environment Variables
```bash
# Authentication
export JWT_SECRET="your-secret-key"
export MCP_AUTH_TOKEN="mcp-auth-token"

# External APIs
export GITHUB_TOKEN="github-token"
export OPENAI_API_KEY="openai-key"
export ANTHROPIC_API_KEY="anthropic-key"

# Database
export POSTGRES_PASSWORD="secure-password"
export REDIS_PASSWORD="redis-password"
```

### Service Configuration Template
```yaml
service_name:
  enabled: true
  replicas: 2
  command: "python"
  args: ["-m", "service_module"]
  dependencies: ["redis", "postgresql"]
  env:
    VAR_NAME: "value"
  resources:
    cpu_cores: 1.0
    memory_mb: 1024
    storage_gb: 10
  health_check:
    endpoint: "http://localhost:8080/health"
    interval_seconds: 30
  ports:
    - container_port: 8080
      host_port: 8080
```

## Common Troubleshooting

### Quick Diagnostics
```bash
# Check logs
tail -f /var/log/deploy-code/orchestrator.log

# Test connectivity
curl http://localhost:3001/health  # MCP Filesystem
curl http://localhost:8080/health  # Circle of Experts

# Resource usage
deploy-code resources --usage

# Network status
deploy-code network --test-connectivity
```

### Emergency Procedures
```bash
# Emergency stop
deploy-code emergency-stop

# Reset configuration
deploy-code config --reset-to-defaults

# Restore from backup
deploy-code restore --from-backup /var/backups/latest

# Force service restart
deploy-code restart --force --service problematic_service
```

## Service Port Reference

| Service | Port | Protocol | Health Endpoint |
|---------|------|----------|-----------------|
| PostgreSQL | 5432 | TCP | pg_isready |
| Redis | 6379 | TCP | redis-cli ping |
| Auth Service | 8000 | HTTP | /health |
| MCP Filesystem | 3001 | HTTP | /health |
| MCP GitHub | 3002 | HTTP | /health |
| MCP Memory | 3003 | HTTP | /health |
| MCP BashGod | 3010 | HTTP | /health |
| Circle of Experts | 8080 | HTTP | /health |
| Code Base Crawler | 8090 | HTTP | /health |
| API Gateway | 80/443 | HTTP/HTTPS | /health |
| Prometheus | 9090 | HTTP | /-/healthy |
| Grafana | 3000 | HTTP | /api/health |
| Jaeger | 16686 | HTTP | / |

## Deployment Phases

1. **Validation** - Configuration and dependency checks
2. **Resources** - CPU, memory, storage allocation
3. **Network** - Port allocation and service mesh setup
4. **Deployment** - Service container orchestration
5. **Health** - Service health verification
6. **Post-deployment** - Monitoring and state backup

## Security Quick Reference

### RBAC Roles
- **admin**: Full access to all operations
- **operator**: Deploy, status, restart permissions
- **viewer**: Read-only status and health access

### Security Commands
```bash
# Check permissions
deploy-code auth --check-permissions $USER

# Regenerate certificates
deploy-code certs --regenerate

# Update security policies
deploy-code security --update-policies
```

## Monitoring Endpoints

### Prometheus Metrics
- `http://localhost:9090/metrics` - Prometheus metrics
- `http://localhost:8080/metrics` - Circle of Experts metrics
- `http://localhost:3001/metrics` - MCP server metrics

### Grafana Dashboards
- `http://localhost:3000/d/platform` - Platform overview
- `http://localhost:3000/d/services` - Service health
- `http://localhost:3000/d/resources` - Resource usage

### Jaeger Tracing
- `http://localhost:16686` - Distributed tracing UI

## Resource Planning

### Minimum Requirements
- CPU: 8 cores
- Memory: 16GB RAM
- Storage: 100GB SSD
- Network: 1Gbps

### Recommended Production
- CPU: 16+ cores
- Memory: 32+ GB RAM
- Storage: 500GB+ NVMe SSD
- Network: 10Gbps
- GPU: RTX 4090 (for Circle of Experts)

## Backup and Recovery

### Backup Commands
```bash
# Full system backup
deploy-code backup --full

# Configuration backup
deploy-code config --backup

# Database backup
deploy-code db --backup

# State checkpoint
deploy-code checkpoint --create
```

### Recovery Commands
```bash
# Restore from backup
deploy-code restore --from-backup /path/to/backup

# Rollback deployment
deploy-code rollback

# Reset to checkpoint
deploy-code reset --to-checkpoint checkpoint-name
```

## Performance Tuning

### Resource Optimization
```yaml
# High-performance configuration
deployment:
  strategy: Parallel
  max_parallel: 10
  timeout_seconds: 120

resources:
  enable_gpu: true
  cpu_affinity: true
  memory_hugepages: true
```

### Network Optimization
```yaml
network:
  enable_jumbo_frames: true
  tcp_window_scaling: true
  connection_pooling: true
```

This quick reference provides the most commonly used Deploy-Code commands and configurations for daily operations.