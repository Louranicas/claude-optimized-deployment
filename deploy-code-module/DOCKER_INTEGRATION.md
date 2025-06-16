# Docker Integration Guide

## Overview

Deploy-Code provides seamless integration with Docker for containerized deployments of all CODE platform components. This guide covers Docker-specific configuration patterns, container orchestration, and best practices.

## Docker Configuration

### Basic Docker Service Definition

```yaml
services:
  mcp_filesystem:
    enabled: true
    replicas: 2
    runtime: docker
    image: "mcp/filesystem:latest"
    command: "npx"
    args: ["@modelcontextprotocol/server-filesystem", "--port", "3001"]
    ports:
      - container_port: 3001
        host_port: 3001
        protocol: "tcp"
    environment:
      MCP_AUTH_TOKEN: "${MCP_AUTH_TOKEN}"
      NODE_ENV: "production"
    volumes:
      - name: mcp_data
        mount_path: "/data"
        host_path: "/var/lib/deploy-code/mcp-data"
        read_only: false
    resources:
      cpu_cores: 0.5
      memory_mb: 512
      storage_gb: 10
```

### Container Runtime Options

Deploy-Code supports multiple container runtimes:

```yaml
infrastructure:
  container_runtime: Docker  # Docker, Podman, Containerd
  docker:
    socket_path: "/var/run/docker.sock"
    registry_auth: true
    build_context: "/app/build"
    network_mode: "bridge"
    restart_policy: "unless-stopped"
    log_driver: "json-file"
    log_options:
      max_size: "100m"
      max_file: "5"
```

## Container Networking

### Network Configuration

```yaml
network:
  mode: Bridge
  docker_network: "code-platform"
  cidr: "172.20.0.0/16"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
  port_range:
    start: 30000
    end: 40000
```

### Service-to-Service Communication

```python
# Deploy-Code automatically creates a Docker network
# Services can communicate using service names
async def setup_docker_network(self):
    network_config = {
        "Name": "code-platform",
        "Driver": "bridge",
        "IPAM": {
            "Config": [{"Subnet": "172.20.0.0/16"}]
        },
        "Options": {
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "true"
        }
    }
    
    await self.docker_client.networks.create(**network_config)
```

## Volume Management

### Persistent Storage

```yaml
volumes:
  postgres_data:
    type: named
    driver: local
    driver_opts:
      type: none
      o: bind
      device: "/var/lib/deploy-code/postgres"
  
  mcp_shared:
    type: bind
    source: "/opt/code-platform/shared"
    target: "/shared"
    read_only: false
    
  config_volume:
    type: tmpfs
    tmpfs_opts:
      size: "100m"
      mode: "0755"
```

### Dynamic Volume Allocation

```python
async def allocate_volumes(self, service_config):
    """Dynamically allocate volumes for a service"""
    volumes = {}
    
    for volume_name, volume_config in service_config.volumes.items():
        if volume_config.type == "named":
            # Create named volume
            volume = await self.docker_client.volumes.create(
                name=f"code-{service_config.name}-{volume_name}",
                driver=volume_config.driver,
                driver_opts=volume_config.driver_opts
            )
            volumes[volume_name] = volume.name
        
        elif volume_config.type == "bind":
            # Ensure host directory exists
            os.makedirs(volume_config.source, exist_ok=True)
            volumes[volume_name] = volume_config.source
    
    return volumes
```

## Container Lifecycle Management

### Service Startup Sequence

```python
async def deploy_docker_service(self, service_name: str, config: ServiceConfig):
    """Deploy a service using Docker"""
    
    # 1. Pull image if needed
    if config.image:
        await self.pull_image(config.image)
    
    # 2. Create volumes
    volumes = await self.allocate_volumes(config)
    
    # 3. Setup environment
    environment = self.prepare_environment(config.env)
    
    # 4. Configure networking
    network_config = await self.setup_service_network(service_name)
    
    # 5. Create container
    container = await self.docker_client.containers.create(
        image=config.image,
        command=config.command,
        environment=environment,
        ports=self.map_ports(config.ports),
        volumes=volumes,
        network=network_config.name,
        name=f"code-{service_name}",
        restart_policy={"Name": "unless-stopped"},
        labels={
            "deploy-code.service": service_name,
            "deploy-code.version": config.version,
            "deploy-code.managed": "true"
        }
    )
    
    # 6. Start container
    await container.start()
    
    # 7. Register with service registry
    await self.register_service(service_name, container)
    
    return container
```

### Health Check Integration

```yaml
health_check:
  test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

```python
async def configure_health_check(self, container, health_config):
    """Configure Docker health check"""
    health_check = {
        "test": health_config.test,
        "interval": health_config.interval * 1000000000,  # Convert to nanoseconds
        "timeout": health_config.timeout * 1000000000,
        "retries": health_config.retries,
        "start_period": health_config.start_period * 1000000000
    }
    
    await container.update(healthcheck=health_check)
```

## Multi-Stage Container Builds

### Build Configuration

```yaml
services:
  circle_of_experts:
    build:
      context: "../services/ai"
      dockerfile: "Dockerfile.production"
      args:
        RUST_VERSION: "1.75"
        PYTHON_VERSION: "3.11"
      target: "production"
      cache_from:
        - "code-platform:build-cache"
```

### Dockerfile Example

```dockerfile
# Multi-stage build for Circle of Experts
FROM rust:1.75-bullseye AS rust-builder
WORKDIR /app
COPY rust-core/ ./
RUN cargo build --release

FROM python:3.11-slim AS python-base
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

FROM python-base AS dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM dependencies AS production
COPY --from=rust-builder /app/target/release/circle_experts /usr/local/bin/
COPY src/ ./src/
COPY configs/ ./configs/

ENV PYTHONPATH=/app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

## Container Security

### Security Configuration

```yaml
security:
  docker:
    user: "1000:1000"  # Run as non-root user
    read_only_root_fs: true
    no_new_privileges: true
    security_opts:
      - "no-new-privileges:true"
      - "seccomp:unconfined"
    cap_drop:
      - "ALL"
    cap_add:
      - "NET_BIND_SERVICE"
    tmpfs:
      - "/tmp:rw,noexec,nosuid,size=100m"
```

### Runtime Security

```python
async def apply_security_config(self, container_config, security_config):
    """Apply security configuration to container"""
    
    # User configuration
    if security_config.user:
        container_config["user"] = security_config.user
    
    # Filesystem security
    if security_config.read_only_root_fs:
        container_config["read_only"] = True
    
    # Capabilities
    host_config = container_config.setdefault("host_config", {})
    if security_config.cap_drop:
        host_config["cap_drop"] = security_config.cap_drop
    if security_config.cap_add:
        host_config["cap_add"] = security_config.cap_add
    
    # Security options
    if security_config.security_opts:
        host_config["security_opt"] = security_config.security_opts
    
    return container_config
```

## Container Monitoring

### Resource Monitoring

```python
async def collect_container_metrics(self, container):
    """Collect metrics from Docker container"""
    stats = await container.stats(stream=False)
    
    # CPU usage
    cpu_usage = self.calculate_cpu_usage(stats["cpu_stats"], stats["precpu_stats"])
    
    # Memory usage
    memory_usage = stats["memory_stats"]["usage"] / stats["memory_stats"]["limit"] * 100
    
    # Network I/O
    network_rx = sum(iface["rx_bytes"] for iface in stats["networks"].values())
    network_tx = sum(iface["tx_bytes"] for iface in stats["networks"].values())
    
    # Disk I/O
    disk_read = sum(disk["value"] for disk in stats["blkio_stats"]["io_service_bytes_recursive"] if disk["op"] == "Read")
    disk_write = sum(disk["value"] for disk in stats["blkio_stats"]["io_service_bytes_recursive"] if disk["op"] == "Write")
    
    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "network_rx": network_rx,
        "network_tx": network_tx,
        "disk_read": disk_read,
        "disk_write": disk_write
    }
```

### Log Management

```yaml
logging:
  driver: "json-file"
  options:
    max_size: "100m"
    max_file: "5"
    labels: "service,version"
    env: "DEPLOY_CODE_SERVICE"
```

```python
async def setup_logging(self, service_name, log_config):
    """Configure container logging"""
    return {
        "log_config": {
            "type": log_config.driver,
            "config": {
                **log_config.options,
                "labels": f"{log_config.options.get('labels', '')},deploy-code.service={service_name}"
            }
        }
    }
```

## Container Registry Integration

### Registry Configuration

```yaml
registry:
  url: "registry.codeplatform.io"
  username: "${REGISTRY_USERNAME}"
  password: "${REGISTRY_PASSWORD}"
  
  push_on_build: true
  pull_policy: "IfNotPresent"  # Always, IfNotPresent, Never
  
  cache:
    enabled: true
    registry: "registry.codeplatform.io/cache"
    mode: "max"
```

### Image Management

```python
async def manage_container_images(self):
    """Manage container images lifecycle"""
    
    # Pull latest images
    for service_config in self.config.services.values():
        if service_config.image and service_config.pull_policy != "Never":
            await self.pull_image_if_needed(service_config.image, service_config.pull_policy)
    
    # Clean up unused images
    if self.config.cleanup.enable_image_cleanup:
        unused_images = await self.docker_client.images.prune(
            filters={"until": "24h", "label!": "deploy-code.keep=true"}
        )
        logger.info(f"Cleaned up {len(unused_images)} unused images")

async def pull_image_if_needed(self, image: str, pull_policy: str):
    """Pull image based on policy"""
    
    if pull_policy == "Always":
        await self.docker_client.images.pull(image)
    elif pull_policy == "IfNotPresent":
        try:
            await self.docker_client.images.get(image)
        except docker.errors.ImageNotFound:
            await self.docker_client.images.pull(image)
```

## Docker Compose Integration

### Generated Compose File

Deploy-Code can generate Docker Compose files for external tooling:

```python
async def generate_docker_compose(self) -> dict:
    """Generate Docker Compose configuration"""
    
    compose_config = {
        "version": "3.8",
        "services": {},
        "networks": {
            "code-platform": {
                "driver": "bridge",
                "ipam": {
                    "config": [{"subnet": self.config.network.cidr}]
                }
            }
        },
        "volumes": {}
    }
    
    for service_name, service_config in self.config.services.items():
        compose_config["services"][service_name] = {
            "image": service_config.image,
            "container_name": f"code-{service_name}",
            "ports": [f"{p.host_port}:{p.container_port}" for p in service_config.ports],
            "environment": service_config.env,
            "networks": ["code-platform"],
            "restart": "unless-stopped",
            "depends_on": service_config.dependencies,
            "labels": {
                "deploy-code.service": service_name,
                "deploy-code.managed": "true"
            }
        }
        
        # Add volumes if configured
        if service_config.volumes:
            compose_config["services"][service_name]["volumes"] = [
                f"{v.host_path}:{v.mount_path}{'ro' if v.read_only else ''}"
                for v in service_config.volumes
            ]
    
    return compose_config
```

## Performance Optimization

### Container Optimization

```yaml
optimization:
  docker:
    # Use multi-stage builds
    multi_stage_builds: true
    
    # Layer caching
    buildkit: true
    
    # Resource limits
    default_limits:
      memory: "1g"
      cpus: "1.0"
      pids: 1024
    
    # Filesystem optimizations
    storage_driver: "overlay2"
    
    # Network optimizations
    userland_proxy: false
```

### Resource Allocation

```python
async def optimize_container_resources(self, service_config):
    """Optimize container resource allocation"""
    
    resources = {}
    
    # CPU allocation
    if service_config.resources.cpu_cores:
        resources["cpu_period"] = 100000
        resources["cpu_quota"] = int(service_config.resources.cpu_cores * 100000)
    
    # Memory allocation
    if service_config.resources.memory_mb:
        resources["memory"] = service_config.resources.memory_mb * 1024 * 1024
        resources["memswap_limit"] = resources["memory"]  # Disable swap
    
    # I/O optimization
    resources["blkio_weight"] = 500  # Default I/O weight
    
    return resources
```

## Troubleshooting Docker Issues

### Common Docker Problems

```bash
# Container fails to start
docker logs code-mcp-filesystem
deploy-code debug --service mcp_filesystem --container-logs

# Port conflicts
docker port code-mcp-filesystem
netstat -tlnp | grep 3001

# Volume mount issues
docker exec -it code-mcp-filesystem ls -la /data
deploy-code debug --service mcp_filesystem --volumes

# Network connectivity
docker network inspect code-platform
docker exec -it code-mcp-filesystem ping code-redis

# Resource constraints
docker stats code-mcp-filesystem
deploy-code resources --container mcp_filesystem
```

### Debug Commands

```python
async def debug_container(self, service_name: str):
    """Debug container issues"""
    
    container = await self.get_container(service_name)
    
    # Container info
    info = await container.show()
    logger.info(f"Container state: {info['State']}")
    logger.info(f"Container config: {info['Config']}")
    
    # Logs
    logs = await container.logs(tail=100)
    logger.info(f"Recent logs: {logs}")
    
    # Resource usage
    stats = await container.stats(stream=False)
    logger.info(f"Resource usage: {stats}")
    
    # Network info
    networks = info.get("NetworkSettings", {}).get("Networks", {})
    logger.info(f"Network configuration: {networks}")
```

This Docker integration guide provides comprehensive coverage of how Deploy-Code manages containerized deployments across the CODE platform.