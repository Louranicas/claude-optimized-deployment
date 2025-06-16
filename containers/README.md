# Claude Optimized Deployment - Container Infrastructure

This directory contains the complete containerized infrastructure for the Claude Optimized Deployment project, optimized for systems with 32GB RAM and NVMe storage.

## Directory Structure

```
containers/
├── development/          # Development environment containers
│   ├── Dockerfile.rust-dev      # Rust development container
│   ├── Dockerfile.python-ml     # Python ML container with GPU support
│   ├── Dockerfile.mcp-server    # MCP server development container
│   ├── docker-compose.dev.yml   # Main development stack
│   └── docker-compose.mcp.yml   # MCP server development stack
├── production/          # Production environment containers
│   ├── Dockerfile.rust-service     # Optimized Rust service
│   ├── Dockerfile.python-api       # Optimized Python API
│   ├── Dockerfile.mcp-server-prod  # Production MCP servers
│   ├── docker-compose.prod.yml     # Main production stack
│   └── docker-compose.mcp-prod.yml # MCP production stack
├── management/          # Container management tools
│   └── container-manager.sh        # Advanced container operations
├── monitoring/          # Monitoring configurations
├── networking/          # Network configurations
├── security/           # Security policies
└── quick-start.sh      # Quick start script

```

## Quick Start

### Development Environment

1. **Check system requirements:**
   ```bash
   ./quick-start.sh check
   ```

2. **Set up directories and build containers:**
   ```bash
   ./quick-start.sh setup
   ./quick-start.sh build-dev
   ```

3. **Start development environment:**
   ```bash
   ./quick-start.sh dev
   ```

### Production Environment

1. **Set required environment variables:**
   ```bash
   export DB_PASSWORD="your-secure-password"
   export SECRET_KEY="your-secret-key"
   export ELASTIC_PASSWORD="your-elastic-password"
   ```

2. **Build production containers:**
   ```bash
   ./quick-start.sh build-prod
   ```

3. **Start production environment:**
   ```bash
   ./quick-start.sh prod
   ```

## Container Details

### Development Containers

#### Rust Development (claude-rust-dev)
- **Base:** Rust 1.75 with Debian
- **Features:** 
  - Optimized for Ryzen 7 7800X3D
  - Includes rust-analyzer, clippy, cargo tools
  - sccache for build acceleration
  - 8GB RAM, 8 CPU cores allocated

#### Python ML (claude-python-ml)
- **Base:** NVIDIA CUDA 12.2 with Python 3.11
- **Features:**
  - PyTorch with CUDA support
  - TensorFlow, Transformers, scikit-learn
  - Jupyter Lab included
  - 16GB RAM, 12 CPU cores allocated
  - GPU support ready

#### MCP Servers (claude-mcp-dev)
- **Base:** Node.js 20
- **Features:**
  - MCP SDK pre-installed
  - TypeScript support
  - Multiple server instances
  - 4GB RAM, 4 CPU cores allocated

### Production Containers

All production containers include:
- Multi-stage builds for minimal size
- Non-root user execution
- Read-only root filesystem
- Security hardening
- Health checks
- Resource limits

## Services

### Core Services
- **PostgreSQL:** Main database (dev: 5432, prod: 5433)
- **Redis:** Caching and sessions (dev: 6379, prod: 6380)
- **Elasticsearch:** Search functionality (port 9200)
- **MinIO:** S3-compatible storage (port 9000)

### MCP Servers
- **Filesystem:** Port 3000
- **Git:** Port 3001
- **Database:** Port 3002
- **Memory:** Port 3003
- **Search:** Port 3004
- **Web:** Port 3005
- **Python Tools:** Port 3006

### Monitoring
- **Prometheus:** Metrics collection (port 9090)
- **Grafana:** Visualization (dev: 3001)
- **Node Exporter:** System metrics

## Container Management

Use the container management script for advanced operations:

```bash
cd management/

# Monitor container health
./container-manager.sh monitor

# Check resource usage
./container-manager.sh resources

# Backup data
./container-manager.sh backup prod

# Scale services
./container-manager.sh scale python-api 5

# View logs
./container-manager.sh logs claude-api-prod 200

# Rolling updates
./container-manager.sh update python-api
```

## Performance Optimization

The containers are optimized for:
- **AMD Ryzen 7 7800X3D:** CPU-specific optimizations
- **32GB RAM:** Efficient memory allocation
- **NVMe Storage:** Fast I/O operations

### Resource Allocation

Development environment uses approximately:
- 30GB RAM total
- 16 CPU cores
- 100GB storage

Production environment uses approximately:
- 24GB RAM total
- 14 CPU cores
- 200GB storage

## Security Features

- All containers run as non-root users
- Minimal base images
- Read-only root filesystems in production
- Network isolation
- Secret management
- Regular security scanning with Trivy

## Networking

- **Development:** Single bridge network (172.20.0.0/16)
- **Production:** 
  - Web network for external access
  - Internal network for service communication

## Backup and Recovery

Automated backup support for:
- PostgreSQL databases
- Redis data
- Application volumes
- Configuration files

Run backups with:
```bash
./management/container-manager.sh backup prod
```

## Troubleshooting

### Common Issues

1. **Out of memory:**
   - Check system resources: `free -h`
   - Reduce container limits in docker-compose files

2. **Port conflicts:**
   - Check used ports: `netstat -tlnp`
   - Modify port mappings in docker-compose files

3. **Build failures:**
   - Clear Docker cache: `docker system prune -a`
   - Check disk space: `df -h`

### Logs

View container logs:
```bash
# All logs
docker-compose -f development/docker-compose.dev.yml logs

# Specific service
docker logs claude-rust-dev -f

# Using management script
./management/container-manager.sh logs claude-api-prod
```

## Kubernetes Deployment

For Kubernetes deployment, use the manifests in `/k8s`:
```bash
kubectl apply -f ../k8s/namespace.yaml
kubectl apply -f ../k8s/mcp-deployment.yaml
```

## Contributing

When adding new containers:
1. Follow the existing Dockerfile patterns
2. Include health checks
3. Use multi-stage builds for production
4. Document resource requirements
5. Add to relevant docker-compose files

## License

See the main project LICENSE file.