# Deploy-Code Module

A bulletproof deployment orchestrator for the CODE platform, built with Rust for maximum performance and reliability.

## Overview

Deploy-Code is a comprehensive deployment orchestration system designed to manage the entire lifecycle of CODE platform services. It provides automated deployment, health monitoring, resource management, and rollback capabilities with a focus on reliability and performance.

### Key Features

- **Automated Deployment**: Single-command deployment of the entire CODE platform
- **Service Orchestration**: Intelligent dependency resolution and phased deployment
- **Health Monitoring**: Real-time health checks and automated recovery
- **Resource Management**: Dynamic resource allocation and optimization
- **Network Management**: Automated network configuration and service mesh setup
- **Rollback Support**: Automatic rollback on deployment failures
- **Circuit Breaker**: Fault tolerance with circuit breaker pattern
- **Dry Run Mode**: Test deployments without making changes
- **Python Integration**: Python API wrapper for scripting and automation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Deploy-Code CLI                           │
├─────────────────────────────────────────────────────────────────┤
│                    Orchestration Engine                          │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐   │
│  │  Scheduler   │  │   Executor   │  │  Service Registry   │   │
│  └─────────────┘  └──────────────┘  └─────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                     Core Components                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐     │
│  │   Resources  │  │   Network    │  │   Reliability    │     │
│  │   Manager    │  │   Manager    │  │   Manager        │     │
│  └──────────────┘  └──────────────┘  └──────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐     │
│  │    Docker    │  │  Kubernetes  │  │   Monitoring     │     │
│  │  Runtime     │  │  (Future)    │  │   (Prometheus)   │     │
│  └──────────────┘  └──────────────┘  └──────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Rust 1.75+ (for building from source)
- Docker or Podman (for container runtime)
- Python 3.9+ (for Python integration)
- PostgreSQL 14+ (for state management)
- Redis 7+ (for caching and coordination)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/claude-optimized-deployment.git
cd claude-optimized-deployment/deploy-code-module

# Build the Rust binary
cargo build --release

# Install Python dependencies
pip install -r requirements.txt

# Run tests
cargo test
python -m pytest tests/
```

### Using Pre-built Binaries

```bash
# Download the latest release
curl -L https://github.com/your-org/deploy-code/releases/latest/download/deploy-code-linux-amd64 -o deploy-code
chmod +x deploy-code

# Verify installation
./deploy-code --version
```

## Configuration

Deploy-Code uses YAML configuration files. The default configuration file is `deploy-code.yaml`.

### Basic Configuration

```yaml
version: "1.0.0"
environment: production
dry_run: false

infrastructure:
  container_runtime: Docker
  network:
    mode: Bridge
    cidr: "172.20.0.0/16"

deployment:
  strategy: Sequential
  max_parallel: 10
  timeout_seconds: 300
  rollback_on_failure: true

services:
  postgresql:
    enabled: true
    replicas: 1
    command: "docker"
    args: ["run", "--name", "code-postgres", "-d", "postgres:16"]
    dependencies: []
    resources:
      cpu_cores: 2.0
      memory_mb: 4096
```

## Usage

### Command Line Interface

```bash
# Deploy all services
deploy-code deploy

# Deploy specific services
deploy-code deploy --services postgresql,redis,auth_service

# Dry run deployment
deploy-code deploy --dry-run

# Check service status
deploy-code status --detailed

# Stop all services
deploy-code stop --timeout 60

# Restart services
deploy-code restart --services api_gateway

# Validate configuration
deploy-code validate

# Show health status
deploy-code health --format json
```

### Python API

```python
from deploy_code import DeployCode, DeploymentReport

# Initialize the deployment orchestrator
deployer = DeployCode(config_path="deploy-code.yaml", dry_run=False)

# Deploy services
async def deploy():
    report = await deployer.deploy(services=["postgresql", "redis"])
    print(f"Deployment {'succeeded' if report.success else 'failed'}")
    print(f"Deployed: {report.deployed_services}/{report.total_services}")

# Check status
async def check_status():
    status = await deployer.get_status(detailed=True)
    for service, info in status.services.items():
        print(f"{service}: {info.status} ({info.health})")

# Run deployment
asyncio.run(deploy())
```

## Service Dependencies

Deploy-Code automatically manages service dependencies. Services are deployed in phases based on their dependency graph:

```
Phase 1: Core Infrastructure
├── PostgreSQL
└── Redis

Phase 2: Authentication & Security
└── Auth Service (depends on PostgreSQL, Redis)

Phase 3: MCP Servers
├── MCP Filesystem (depends on Auth Service)
├── MCP GitHub (depends on Auth Service)
├── MCP Memory (depends on Auth Service, Redis)
└── MCP Bash God (depends on Auth Service, MCP Memory)

Phase 4: AI Services
└── Circle of Experts (depends on Auth Service, Redis, MCP Memory)

Phase 5: Code Base Crawler
└── CBC Server (depends on PostgreSQL, MCP Filesystem)

Phase 6: API Gateway
└── API Gateway (depends on all services)

Phase 7: Monitoring
├── Prometheus
├── Grafana (depends on Prometheus)
└── Jaeger
```

## Monitoring and Health Checks

Deploy-Code includes comprehensive monitoring capabilities:

- **Health Endpoints**: All services expose `/health` endpoints
- **Metrics Collection**: Prometheus-compatible metrics
- **Distributed Tracing**: OpenTelemetry integration
- **Alerting**: Configurable alerts for service failures

### Health Check Configuration

```yaml
health_check:
  endpoint: "http://localhost:8080/health"
  interval_seconds: 30
  timeout_seconds: 10
  retries: 3
  start_period_seconds: 60
```

## Troubleshooting

### Common Issues

1. **Service fails to start**
   ```bash
   # Check logs
   deploy-code logs --service postgresql
   
   # Validate configuration
   deploy-code validate
   ```

2. **Resource allocation failures**
   ```bash
   # Check resource availability
   deploy-code resources --status
   
   # Force deployment (skip resource checks)
   deploy-code deploy --force
   ```

3. **Network connectivity issues**
   ```bash
   # Check network configuration
   deploy-code network --diagnose
   
   # Reset network
   deploy-code network --reset
   ```

## Development

### Project Structure

```
deploy-code-module/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── orchestrator/        # Orchestration engine
│   ├── services/            # Service management
│   ├── resources/           # Resource management
│   ├── network/             # Network management
│   ├── reliability/         # Fault tolerance
│   └── monitoring/          # Metrics and monitoring
├── tests/                   # Test suite
├── deploy_code.py           # Python integration
├── deploy-code.yaml         # Default configuration
└── Cargo.toml              # Rust dependencies
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Running Tests

```bash
# Run Rust tests
cargo test

# Run integration tests
cargo test --test '*' -- --test-threads=1

# Run Python tests
python -m pytest tests/ -v

# Run with coverage
cargo tarpaulin --out Html
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📚 Documentation Index

### Core Documentation
- **[Integration Guide](INTEGRATION_GUIDE.md)** - Comprehensive integration patterns and component relationships
- **[Deployment Flow](DEPLOYMENT_FLOW.md)** - Detailed sequence diagrams and deployment orchestration
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and resolution procedures
- **[Quick Reference](QUICK_REFERENCE.md)** - Essential commands and configuration snippets

### Configuration Files
- **[deploy-code.yaml](deploy-code.yaml)** - Main production configuration
- **[deploy-code-test.yaml](deploy-code-test.yaml)** - Test environment configuration

### Related Documentation
- [API Integration Guide](../API_INTEGRATION_GUIDE.md)
- [MCP Server Documentation](../ai_docs/infrastructure/MCP_INTEGRATION_GUIDE.md)
- [Circle of Experts Guide](../examples/circle_of_experts_usage.py)
- [Security Best Practices](../ai_docs/security/)
- [Performance Tuning](../benchmarks/)

## 🔗 Managed Components

Deploy-Code orchestrates the following components:

### Core Infrastructure (Phase 1)
- **PostgreSQL** - Primary database (Port 5432)
- **Redis** - Caching and session storage (Port 6379)

### Authentication & Security (Phase 2)
- **Auth Service** - JWT-based authentication (Port 8000)

### MCP Server Ecosystem (Phase 3)
- **Filesystem MCP** - File system operations (Port 3001)
- **GitHub MCP** - Repository management (Port 3002)
- **Memory MCP** - Persistent context storage (Port 3003)
- **BashGod MCP** - System administration (Port 3010)
- **Plus 20+ additional specialized MCP servers**

### AI Services (Phase 4)
- **Circle of Experts** - Multi-AI consultation system (Port 8080)

### Code Analysis (Phase 5)
- **Code Base Crawler** - Intelligent code analysis (Port 8090)

### Gateway & Routing (Phase 6)
- **API Gateway** - Unified API endpoint (Port 80/443)

### Monitoring Stack (Phase 7)
- **Prometheus** - Metrics collection (Port 9090)
- **Grafana** - Visualization dashboards (Port 3000)
- **Jaeger** - Distributed tracing (Port 16686)

## Support

- Documentation: https://docs.codeplatform.io/deploy-code
- Issues: https://github.com/your-org/deploy-code/issues
- Discussions: https://github.com/your-org/deploy-code/discussions
- Email: support@codeplatform.io