# Deploy-Code Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting information for Deploy-Code integration issues, common deployment problems, and their solutions.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Common Integration Issues](#common-integration-issues)
3. [Service-Specific Problems](#service-specific-problems)
4. [Performance Issues](#performance-issues)
5. [Network and Connectivity](#network-and-connectivity)
6. [Security and Authentication](#security-and-authentication)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Recovery Procedures](#recovery-procedures)

## Quick Diagnostics

### Health Check Commands

```bash
# Overall platform status
deploy-code status --detailed

# Service-specific health check
deploy-code health --service mcp_filesystem

# Network connectivity test
deploy-code network --test-connectivity

# Resource usage check
deploy-code resources --usage

# Configuration validation
deploy-code validate --verbose
```

### Log Analysis

```bash
# View deploy-code logs
tail -f /var/log/deploy-code/orchestrator.log

# Service-specific logs
docker logs code-mcp-filesystem
docker logs code-circle-of-experts

# System-wide logs
journalctl -f -u deploy-code
```

## Common Integration Issues

### 1. Service Registry Connection Failures

**Symptoms:**
- Services fail to register
- Health checks return "unknown" status
- Service discovery not working

**Diagnosis:**
```bash
# Check service registry status
curl http://localhost:8500/v1/agent/self  # If using Consul
docker ps | grep registry

# Verify registry configuration
deploy-code config --show-registry
```

**Solutions:**
```bash
# Restart service registry
docker restart code-service-registry

# Reset registry data
deploy-code registry --reset

# Manual service registration
deploy-code register --service mcp_filesystem --endpoint http://localhost:3001
```

### 2. Resource Allocation Failures

**Symptoms:**
- "Insufficient resources" errors
- Services crash with OOM errors
- High CPU utilization alerts

**Diagnosis:**
```bash
# Check resource availability
deploy-code resources --available

# View resource allocations
deploy-code resources --allocated

# System resource usage
htop
df -h
```

**Solutions:**
```yaml
# Adjust resource limits in deploy-code.yaml
services:
  circle_of_experts:
    resources:
      cpu_cores: 2.0  # Reduced from 4.0
      memory_mb: 4096 # Reduced from 8192
```

```bash
# Free up resources
deploy-code stop --service non-essential-service
docker system prune -f

# Scale down replicas
deploy-code scale --service mcp_filesystem --replicas 1
```

### 3. Dependency Resolution Issues

**Symptoms:**
- Services start in wrong order
- Dependency timeout errors
- Circular dependency warnings

**Diagnosis:**
```bash
# View dependency graph
deploy-code dependencies --graph

# Check dependency order
deploy-code dependencies --order
```

**Solutions:**
```yaml
# Fix circular dependencies in deploy-code.yaml
services:
  service_a:
    dependencies: ["service_b"]
  service_b:
    dependencies: []  # Remove circular reference
```

```bash
# Force deployment order
deploy-code deploy --phases "phase1,phase2,phase3"

# Skip dependency checks (use with caution)
deploy-code deploy --force --skip-deps
```

## Service-Specific Problems

### MCP Server Issues

#### Filesystem MCP Server

**Problem: Permission denied errors**
```bash
# Solution: Fix volume permissions
docker exec -it code-mcp-filesystem chown -R node:node /data
sudo chmod 755 /var/lib/deploy-code/mcp-data
```

**Problem: Port conflicts**
```bash
# Solution: Check port usage and reallocate
netstat -tlnp | grep 3001
deploy-code network --allocate-port mcp_filesystem
```

#### GitHub MCP Server

**Problem: API rate limiting**
```bash
# Solution: Check rate limits and rotate tokens
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit

# Configure multiple tokens for rotation
export GITHUB_TOKEN_1="token1"
export GITHUB_TOKEN_2="token2"
```

**Problem: Authentication failures**
```bash
# Solution: Verify token permissions
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Update token in configuration
deploy-code config --update-env GITHUB_TOKEN=new_token
```

#### Memory MCP Server

**Problem: Redis connection failures**
```bash
# Solution: Check Redis connectivity
redis-cli ping
docker logs code-redis

# Restart Redis with proper configuration
deploy-code restart --service redis
```

#### BashGod MCP Server

**Problem: Command execution failures**
```bash
# Solution: Check sandbox configuration
docker exec -it code-mcp-bashgod ps aux
docker exec -it code-mcp-bashgod ls -la /tmp

# Verify security policies
deploy-code security --check-policies bashgod
```

### Circle of Experts Issues

**Problem: AI API failures**
```bash
# Solution: Check API keys and quotas
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# Rotate API keys
deploy-code config --update-env OPENAI_API_KEY=new_key
deploy-code restart --service circle_of_experts
```

**Problem: High memory usage**
```bash
# Solution: Adjust model loading strategy
export CIRCLE_LAZY_LOADING=true
export CIRCLE_MODEL_CACHE_SIZE=2GB

# Scale down expert replicas
deploy-code scale --service circle_of_experts --replicas 2
```

### Database Integration Issues

**Problem: PostgreSQL connection failures**
```bash
# Solution: Check database status
docker exec -it code-postgres pg_isready -U postgres

# Reset database connections
deploy-code db --reset-connections

# Recreate database with proper configuration
deploy-code db --recreate --backup-first
```

**Problem: Migration failures**
```bash
# Solution: Run migrations manually
docker exec -it code-postgres psql -U postgres -d code_platform -f /migrations/latest.sql

# Reset migration state
deploy-code db --reset-migrations
```

## Performance Issues

### Slow Deployment Times

**Diagnosis:**
```bash
# Profile deployment performance
deploy-code deploy --profile --timing

# Check resource bottlenecks
iotop
iostat 1
```

**Solutions:**
```yaml
# Optimize deployment configuration
deployment:
  strategy: Parallel  # Instead of Sequential
  max_parallel: 5     # Increase parallelism
  timeout_seconds: 120 # Reduce timeout
```

```bash
# Use faster deployment strategy
deploy-code deploy --fast --skip-health-checks

# Parallel service starts
deploy-code deploy --parallel-start
```

### High Resource Usage

**Diagnosis:**
```bash
# Monitor resource usage
deploy-code monitor --real-time

# Get resource usage by service
deploy-code resources --by-service
```

**Solutions:**
```bash
# Enable resource limits
deploy-code config --enable-limits

# Optimize garbage collection
export RUST_GC_FREQUENCY=1000
export DEPLOY_CODE_GC_AGGRESSIVE=true
```

## Network and Connectivity

### Port Conflicts

**Problem: Address already in use**
```bash
# Diagnosis: Find port conflicts
ss -tlnp | grep 8080
lsof -i :8080

# Solution: Automatic port allocation
deploy-code network --auto-allocate

# Manual port reassignment
deploy-code config --update-port circle_of_experts 8081
```

### Service Mesh Issues

**Problem: Service-to-service communication failures**
```bash
# Diagnosis: Test service connectivity
deploy-code network --test-mesh

# Solution: Reset service mesh
deploy-code network --reset-mesh
deploy-code deploy --services mesh-gateway
```

### DNS Resolution Issues

**Problem: Service discovery failures**
```bash
# Diagnosis: Test DNS resolution
nslookup mcp-filesystem.code.local
dig @127.0.0.1 mcp-filesystem.code.local

# Solution: Reset DNS configuration
deploy-code network --reset-dns
systemctl restart systemd-resolved
```

## Security and Authentication

### Authentication Failures

**Problem: JWT token validation errors**
```bash
# Diagnosis: Verify token validity
jwt-cli decode $JWT_TOKEN

# Solution: Regenerate tokens
deploy-code auth --regenerate-tokens
deploy-code restart --service auth_service
```

### Certificate Issues

**Problem: TLS handshake failures**
```bash
# Diagnosis: Check certificate validity
openssl x509 -in /etc/deploy-code/certs/server.crt -text -noout

# Solution: Regenerate certificates
deploy-code certs --regenerate
deploy-code restart --all
```

### RBAC Failures

**Problem: Permission denied errors**
```bash
# Diagnosis: Check user permissions
deploy-code auth --check-permissions $USER

# Solution: Update role assignments
deploy-code auth --assign-role operator $USER
```

## Monitoring and Observability

### Prometheus Issues

**Problem: Metrics not being collected**
```bash
# Diagnosis: Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Solution: Restart metrics collection
deploy-code restart --service prometheus
deploy-code config --reload-metrics
```

### Grafana Dashboard Issues

**Problem: No data in dashboards**
```bash
# Diagnosis: Test data source connectivity
curl http://localhost:3000/api/datasources/proxy/1/api/v1/query?query=up

# Solution: Reset Grafana configuration
deploy-code monitoring --reset-grafana
deploy-code monitoring --import-dashboards
```

### Log Aggregation Issues

**Problem: Missing logs**
```bash
# Diagnosis: Check log collectors
docker logs code-log-collector

# Solution: Restart log aggregation
deploy-code logs --restart-collectors
deploy-code logs --reindex
```

## Recovery Procedures

### Emergency Shutdown

```bash
# Graceful shutdown
deploy-code stop --all --graceful --timeout 60

# Force shutdown (if graceful fails)
deploy-code stop --all --force

# Emergency stop (immediate)
deploy-code emergency-stop
```

### State Recovery

```bash
# Restore from backup
deploy-code restore --from-backup /var/backups/deploy-code/latest

# Reset to known good state
deploy-code reset --to-checkpoint checkpoint-20231201

# Partial recovery (specific services)
deploy-code recover --services "mcp_filesystem,auth_service"
```

### Database Recovery

```bash
# Database backup
deploy-code db --backup --timestamp

# Database restore
deploy-code db --restore /var/backups/postgres/latest.sql

# Database repair
deploy-code db --repair --check-integrity
```

### Configuration Reset

```bash
# Reset to default configuration
deploy-code config --reset-to-defaults

# Backup current configuration
deploy-code config --backup /etc/deploy-code/backup/

# Restore configuration
deploy-code config --restore /etc/deploy-code/backup/deploy-code.yaml
```

## Debug Mode Operations

### Enable Debug Logging

```bash
# Environment variables
export RUST_LOG=debug
export DEPLOY_CODE_DEBUG=true
export DEPLOY_CODE_TRACE=true

# Configuration file
debug:
  level: trace
  enable_request_logging: true
  enable_performance_metrics: true
```

### Debug Commands

```bash
# Verbose deployment
deploy-code deploy --debug --verbose --dry-run

# Service debugging
deploy-code debug --service mcp_filesystem --logs --metrics

# Network debugging
deploy-code debug --network --trace-connections

# Resource debugging
deploy-code debug --resources --show-allocations
```

## Advanced Troubleshooting

### Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited
echo '/var/crash/core.%e.%p.%t' > /proc/sys/kernel/core_pattern

# Analyze core dump
gdb deploy-code /var/crash/core.deploy-code.12345.1638360000
```

### Performance Profiling

```bash
# CPU profiling
perf record -g deploy-code deploy
perf report

# Memory profiling
valgrind --tool=massif deploy-code deploy
```

### Container Debugging

```bash
# Enter container for debugging
docker exec -it code-mcp-filesystem /bin/bash

# Debug container startup
docker run --rm -it --entrypoint /bin/bash code-mcp-filesystem

# Container resource limits
docker stats code-mcp-filesystem
```

## Preventive Measures

### Regular Maintenance

```bash
# Weekly health checks
deploy-code health --comprehensive

# Monthly configuration validation
deploy-code validate --deep-check

# Quarterly disaster recovery tests
deploy-code dr-test --simulate-failures
```

### Monitoring Alerts

```yaml
# Setup proactive alerts
alerts:
  service_down:
    condition: "up == 0"
    for: "30s"
    action: "restart_service"
  
  high_memory:
    condition: "memory_usage > 90"
    for: "5m"
    action: "scale_down"
```

### Backup Strategy

```bash
# Automated daily backups
crontab -e
0 2 * * * /usr/local/bin/deploy-code backup --full

# Backup verification
deploy-code backup --verify /var/backups/deploy-code/latest
```

This troubleshooting guide should help you quickly identify and resolve common Deploy-Code integration issues. Always refer to the logs first, and use the debug mode for complex problems.