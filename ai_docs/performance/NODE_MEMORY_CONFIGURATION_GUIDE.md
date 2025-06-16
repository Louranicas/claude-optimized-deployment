# Node.js Memory Configuration Implementation Guide

## Overview

This guide documents the comprehensive Node.js memory configuration implementation across all environments to prevent heap exhaustion and optimize performance.

## Implementation Summary

### 🎯 **Critical Configuration Applied**
- **Heap Size**: 6GB (`--max-old-space-size=6144`)
- **Container Memory Limit**: 8GB (1.5x heap for overhead)
- **GC Optimization**: `--gc-interval=100 --optimize-for-size`

## Files Modified

### 1. Package.json Scripts
**Location**: `/home/louranicas/projects/claude-optimized-deployment/package.json`

All npm scripts now include:
```bash
NODE_OPTIONS="--max-old-space-size=6144 --gc-interval=100 --optimize-for-size"
```

**Scripts Updated**:
- `start`, `dev`, `test`, `build`, `build:prod`, `lint`, `serve`, `worker`, `monitor`

### 2. Docker Compose Configuration

#### Main Monitoring Stack
**Location**: `/home/louranicas/projects/claude-optimized-deployment/docker-compose.monitoring.yml`

**Services Updated**:
- **Prometheus**: Added NODE_OPTIONS and 8G memory limit
- **Grafana**: Added NODE_OPTIONS and 8G memory limit

**Configuration Applied**:
```yaml
environment:
  - NODE_OPTIONS=--max-old-space-size=6144 --gc-interval=100 --optimize-for-size
deploy:
  resources:
    limits:
      memory: 8G
      cpus: '4.0'
    reservations:
      memory: 2G
      cpus: '1.0'
```

#### Secondary Monitoring Stack
**Location**: `/home/louranicas/projects/claude-optimized-deployment/src/monitoring/docker-compose.monitoring.yml`

**Services Updated**:
- **Grafana**: Added NODE_OPTIONS and resource limits

### 3. Kubernetes Deployments
**Location**: `/home/louranicas/projects/claude-optimized-deployment/k8s/deployments.yaml`

**Deployments Updated**:
- **claude-deployment-api**
- **claude-deployment-worker**

**Configuration Applied**:
```yaml
env:
- name: NODE_OPTIONS
  value: "--max-old-space-size=6144 --gc-interval=100 --optimize-for-size"
resources:
  requests:
    memory: "2Gi"
    cpu: "500m"
  limits:
    memory: "8Gi"
    cpu: "2000m-3000m"
```

### 4. Environment Files

#### Production Environment
**Location**: `/home/louranicas/projects/claude-optimized-deployment/.env.production`

**New Environment Variables**:
```bash
NODE_OPTIONS=--max-old-space-size=6144 --gc-interval=100 --optimize-for-size
NODE_HEAP_SIZE_MB=6144
GC_INTERVAL=100
OPTIMIZE_FOR_SIZE=true
CONTAINER_MEMORY_LIMIT=8G
CONTAINER_CPU_LIMIT=4000m
```

#### Development Environment
**Location**: `/home/louranicas/projects/claude-optimized-deployment/.env.development`

**Added Configuration**:
```bash
NODE_OPTIONS=--max-old-space-size=6144 --gc-interval=100 --optimize-for-size
NODE_HEAP_SIZE_MB=6144
GC_INTERVAL=100
OPTIMIZE_FOR_SIZE=true
```

#### Example Environment
**Location**: `/home/louranicas/projects/claude-optimized-deployment/.env.example`

**Added Section**:
```bash
# Node.js Memory Configuration
NODE_OPTIONS=--max-old-space-size=6144 --gc-interval=100 --optimize-for-size
NODE_HEAP_SIZE_MB=6144
GC_INTERVAL=100
OPTIMIZE_FOR_SIZE=true
```

### 5. Startup Script
**Location**: `/home/louranicas/projects/claude-optimized-deployment/start_nodejs_with_memory_config.sh`

**Features**:
- Automatic environment detection
- Memory configuration validation
- Node.js installation verification
- Automatic dependency installation
- Script parameter support

**Usage**:
```bash
./start_nodejs_with_memory_config.sh [script_name]
# Examples:
./start_nodejs_with_memory_config.sh start
./start_nodejs_with_memory_config.sh dev
./start_nodejs_with_memory_config.sh worker
```

## Memory Configuration Details

### Node.js Flags Explained

| Flag | Value | Purpose |
|------|-------|---------|
| `--max-old-space-size` | 6144 | Sets heap size to 6GB |
| `--gc-interval` | 100 | Optimizes garbage collection frequency |
| `--optimize-for-size` | - | Prioritizes memory efficiency over speed |

### Resource Allocation Strategy

| Environment | Heap Size | Container Limit | Ratio | CPU Limit |
|-------------|-----------|----------------|-------|-----------|
| Development | 6GB | 8GB | 1.33x | 2 cores |
| Production API | 6GB | 8GB | 1.33x | 2 cores |
| Production Worker | 6GB | 8GB | 1.33x | 3 cores |
| Monitoring Services | 6GB | 8GB | 1.33x | 4 cores |

## Environment-Specific Configuration

### Development
- Lower resource requests for cost efficiency
- Enhanced debugging capabilities
- Profiling enabled (optional)

### Production
- High availability with resource redundancy
- Strict security settings
- Performance monitoring enabled
- Auto-scaling ready

### Container Orchestration
- **Docker Compose**: Resource limits via deploy section
- **Kubernetes**: Resource requests and limits in pod specs
- **Monitoring**: Dedicated memory configuration for observability stack

## Verification Commands

### Check Node.js Memory Configuration
```bash
# Verify NODE_OPTIONS
echo $NODE_OPTIONS

# Check heap size in running process
node -e "console.log('Heap:', process.memoryUsage())"

# Verify package.json scripts
npm run start --dry-run
```

### Monitor Memory Usage
```bash
# Docker container memory
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Kubernetes pod memory
kubectl top pods -n claude-deployment

# System memory
htop
```

## Best Practices

### 1. Memory Monitoring
- Set up alerts for >80% heap usage
- Monitor GC frequency and duration
- Track memory leak patterns

### 2. Environment Consistency
- Use same memory settings across environments
- Validate configuration in CI/CD
- Document any environment-specific variations

### 3. Scaling Considerations
- Container limits allow for memory spikes
- Horizontal scaling preferred over vertical
- Load balancing with memory-aware routing

## Troubleshooting

### Common Issues

#### Out of Memory Errors
```bash
# Symptoms
FATAL ERROR: Ineffective mark-compacts near heap limit
JavaScript heap out of memory

# Solutions
1. Verify NODE_OPTIONS is set correctly
2. Check container memory limits
3. Monitor for memory leaks
4. Increase heap size if necessary
```

#### Container Killed (OOMKilled)
```bash
# Check container logs
docker logs container_name

# Kubernetes events
kubectl describe pod pod_name

# Solution: Increase container memory limit
```

#### Performance Degradation
```bash
# Check GC overhead
node --trace-gc app.js

# Profile memory usage
node --inspect app.js

# Solution: Tune GC parameters
```

## Security Considerations

### Memory Limits as Security Boundaries
- Prevents resource exhaustion attacks
- Limits blast radius of memory leaks
- Enables predictable resource allocation

### Configuration Security
- Environment variables properly scoped
- No sensitive data in memory configuration
- Secure defaults for all environments

## Maintenance

### Regular Tasks
1. **Weekly**: Review memory usage patterns
2. **Monthly**: Analyze GC performance metrics
3. **Quarterly**: Evaluate memory configuration effectiveness
4. **Annually**: Update Node.js version and re-tune settings

### Update Procedures
1. Test memory configuration changes in development
2. Validate in staging environment
3. Deploy with blue-green strategy
4. Monitor post-deployment metrics

## Success Metrics

### Performance Indicators
- **Zero** out-of-memory errors
- **<2%** GC overhead
- **<500ms** GC pause times
- **>95%** memory efficiency

### Operational Metrics
- Container restart rate: <0.1%
- Memory utilization: 60-80%
- Response time consistency: <±5%
- Throughput stability: >99%

## Configuration Validation

Run this checklist to verify implementation:

- [ ] package.json scripts include NODE_OPTIONS
- [ ] Docker Compose files have memory limits
- [ ] Kubernetes deployments include resource limits
- [ ] Environment files contain memory configuration
- [ ] Startup script is executable and functional
- [ ] All environments use consistent settings
- [ ] Monitoring captures memory metrics
- [ ] Alerts configured for memory thresholds

## Support

For issues with this configuration:
1. Check application logs for memory-related errors
2. Verify environment variable settings
3. Monitor resource usage patterns
4. Consult Node.js memory management documentation
5. Review container orchestration platform logs

---

**Implementation Status**: ✅ COMPLETE  
**Last Updated**: 2025-06-06  
**Next Review**: 2025-09-06