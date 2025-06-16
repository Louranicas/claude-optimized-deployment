# MCP Servers Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying MCP (Model Context Protocol) servers to production environments. The deployment includes containerized services, Kubernetes orchestration, monitoring, and security configurations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Pre-deployment Checklist](#pre-deployment-checklist)
4. [Containerization](#containerization)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [CI/CD Pipeline](#cicd-pipeline)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Security Configuration](#security-configuration)
9. [Performance Optimization](#performance-optimization)
10. [Disaster Recovery](#disaster-recovery)
11. [Troubleshooting](#troubleshooting)

## Prerequisites

### Infrastructure Requirements

- **Kubernetes Cluster**: v1.28+ with RBAC enabled
- **Node Requirements**: 
  - Minimum 3 nodes (high availability)
  - 16GB RAM per node (32GB recommended for ML workloads)
  - 4 CPU cores per node (8 cores recommended)
  - 100GB SSD storage per node
- **Container Registry**: Docker Hub, AWS ECR, or GitHub Container Registry
- **Load Balancer**: AWS ALB, NGINX Ingress Controller, or similar
- **Database**: PostgreSQL 15+ (managed service recommended)
- **Cache**: Redis 7+ (managed service recommended)

### Software Requirements

- **Docker**: v20.10+
- **kubectl**: v1.28+
- **Helm**: v3.10+ (optional but recommended)
- **Node.js**: v20+ (for TypeScript services)
- **Python**: v3.12+ (for ML services)
- **Rust**: v1.75+ (for high-performance services)

### Security Requirements

- **TLS Certificates**: Valid SSL certificates for all endpoints
- **Service Accounts**: Kubernetes service accounts with minimal privileges
- **Secrets Management**: External secrets operator or similar
- **Network Policies**: Kubernetes network policies configured
- **Pod Security Standards**: Restricted security context enforced

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer / Ingress                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┼───────────────────────────────────────┐
│                Kubernetes Cluster                          │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   TypeScript │  │   Python     │  │   Rust       │      │
│  │   API Server │  │   Learning   │  │   Compute    │      │
│  │              │  │   System     │  │   Server     │      │
│  │   Port: 3000 │  │   Port: 8001 │  │   Port: 8002 │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│          │                  │                  │           │
│  ┌──────────────────────────┼──────────────────┼───────┐   │
│  │                     Data Layer                      │   │
│  │                                                     │   │
│  │  ┌──────────────┐         ┌──────────────┐          │   │
│  │  │  PostgreSQL  │         │    Redis     │          │   │
│  │  │   Database   │         │    Cache     │          │   │
│  │  └──────────────┘         └──────────────┘          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                Monitoring Stack                     │   │
│  │                                                     │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │   │
│  │  │ Prometheus   │  │   Grafana    │  │ AlertMgr │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Pre-deployment Checklist

### Environment Preparation

- [ ] Kubernetes cluster is available and accessible
- [ ] Container registry is configured and accessible
- [ ] DNS records are configured for service endpoints
- [ ] SSL certificates are obtained and configured
- [ ] Database and cache services are provisioned
- [ ] Monitoring infrastructure is deployed
- [ ] Security scanning tools are configured

### Code Preparation

- [ ] All unit tests are passing
- [ ] Integration tests are passing
- [ ] Security scans show no critical vulnerabilities
- [ ] Performance benchmarks meet SLA requirements
- [ ] Container images are built and pushed to registry
- [ ] Kubernetes manifests are validated
- [ ] Configuration secrets are created

### Team Preparation

- [ ] Deployment runbook is reviewed
- [ ] Rollback procedures are documented
- [ ] On-call rotation is established
- [ ] Incident response procedures are tested
- [ ] Communication channels are configured

## Containerization

### Building Docker Images

#### TypeScript API Server

```bash
# Build TypeScript API server
cd mcp_servers
docker build -f Dockerfile.mcp-typescript -t mcp-typescript-server:latest .

# Tag for registry
docker tag mcp-typescript-server:latest ghcr.io/your-org/mcp-typescript-server:v1.0.0

# Push to registry
docker push ghcr.io/your-org/mcp-typescript-server:v1.0.0
```

#### Python Learning System

```bash
# Build Python learning system
cd mcp_learning_system
docker build -f Dockerfile.learning-python -t mcp-learning-system:latest .

# Tag and push
docker tag mcp-learning-system:latest ghcr.io/your-org/mcp-learning-system:v1.0.0
docker push ghcr.io/your-org/mcp-learning-system:v1.0.0
```

#### Rust High-Performance Server

```bash
# Build Rust server
cd mcp_learning_system/servers
docker build -f Dockerfile.rust-server -t mcp-rust-server:latest .

# Tag and push
docker tag mcp-rust-server:latest ghcr.io/your-org/mcp-rust-server:v1.0.0
docker push ghcr.io/your-org/mcp-rust-server:v1.0.0
```

### Security Scanning

```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image mcp-typescript-server:latest

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image mcp-learning-system:latest

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image mcp-rust-server:latest
```

### Size Optimization

The multi-stage Dockerfiles implement several optimization techniques:

- **Multi-stage builds**: Separate build and runtime stages
- **Minimal base images**: Alpine Linux for smaller footprint
- **Security updates**: Latest security patches applied
- **Non-root users**: All containers run as non-privileged users
- **Read-only filesystems**: Enhanced security posture
- **Health checks**: Built-in container health monitoring

## Kubernetes Deployment

### Namespace Creation

```bash
# Create production namespace
kubectl create namespace mcp-production

# Label namespace for monitoring
kubectl label namespace mcp-production monitoring=enabled
kubectl label namespace mcp-production environment=production
```

### Secrets Configuration

```bash
# Create database secret
kubectl create secret generic mcp-secrets \
  --from-literal=database-url="postgresql://mcp_user:secure_password@postgres:5432/mcp_db" \
  --from-literal=redis-url="redis://redis:6379" \
  --from-literal=jwt-secret="your-secure-jwt-secret-here" \
  --from-literal=grafana-password="secure-grafana-password" \
  -n mcp-production

# Create image pull secret (if using private registry)
kubectl create secret docker-registry regcred \
  --docker-server=ghcr.io \
  --docker-username=your-username \
  --docker-password=your-token \
  -n mcp-production
```

### Service Account Configuration

```bash
# Create service accounts with minimal privileges
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-api-sa
  namespace: mcp-production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-ml-sa
  namespace: mcp-production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-compute-sa
  namespace: mcp-production
EOF
```

### Storage Configuration

```bash
# Create persistent volumes for data storage
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: mcp-data-pv
spec:
  capacity:
    storage: 50Gi
  accessModes:
    - ReadWriteMany
  persistentVolumeReclaimPolicy: Retain
  storageClassName: fast-ssd
  nfs:
    path: /exports/mcp-data
    server: nfs-server.example.com
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: mcp-models-pv
spec:
  capacity:
    storage: 100Gi
  accessModes:
    - ReadWriteMany
  persistentVolumeReclaimPolicy: Retain
  storageClassName: fast-ssd
  nfs:
    path: /exports/mcp-models
    server: nfs-server.example.com
EOF
```

### Main Deployment

```bash
# Deploy all MCP services
kubectl apply -f k8s/mcp-deployment.yaml

# Verify deployment status
kubectl get deployments -n mcp-production
kubectl get pods -n mcp-production
kubectl get services -n mcp-production

# Check pod logs
kubectl logs -l app=mcp-typescript-api -n mcp-production
kubectl logs -l app=mcp-learning-system -n mcp-production
kubectl logs -l app=mcp-rust-server -n mcp-production
```

### Ingress Configuration

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcp-ingress
  namespace: mcp-production
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/rate-limit-requests-per-second: "100"
spec:
  tls:
  - hosts:
    - api.mcp-production.com
    secretName: mcp-tls-secret
  rules:
  - host: api.mcp-production.com
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: mcp-typescript-api-service
            port:
              number: 3000
      - path: /ml
        pathType: Prefix
        backend:
          service:
            name: mcp-learning-system-service
            port:
              number: 8001
      - path: /compute
        pathType: Prefix
        backend:
          service:
            name: mcp-rust-server-service
            port:
              number: 8002
```

## CI/CD Pipeline

### GitHub Actions Setup

The CI/CD pipeline is configured in `.github/workflows/mcp-production-deployment.yml` and includes:

1. **Security Scanning**: Vulnerability assessment of code and dependencies
2. **Build and Test**: Multi-architecture container builds and comprehensive testing
3. **Blue-Green Deployment**: Zero-downtime production deployments
4. **Performance Testing**: Load testing and SLA validation
5. **Compliance Validation**: SOC2 and GDPR compliance checks

### Pipeline Stages

```mermaid
graph TD
    A[Code Push] --> B[Security Scan]
    B --> C[Build & Test]
    C --> D[Container Security Scan]
    D --> E[Comprehensive Testing]
    E --> F[Blue-Green Deploy]
    F --> G[Health Check]
    G --> H[Performance Test]
    H --> I[Compliance Check]
    I --> J[Production Ready]
```

### Manual Deployment

For manual deployments, use the following commands:

```bash
# Deploy to staging
./scripts/deploy.sh --environment staging --version v1.0.0

# Run production tests
python tests/production_testing_suite.py --config config/production.json

# Deploy to production (after validation)
./scripts/deploy.sh --environment production --version v1.0.0 --confirm
```

## Monitoring and Observability

### Prometheus Configuration

Metrics collection is configured for all services:

- **API Metrics**: Request rates, response times, error rates
- **ML Metrics**: Model accuracy, inference time, resource usage
- **System Metrics**: CPU, memory, disk, network utilization
- **Business Metrics**: User activity, feature usage, performance SLAs

### Grafana Dashboards

Pre-configured dashboards include:

1. **System Overview**: High-level system health and performance
2. **Service Performance**: Detailed service metrics and SLAs
3. **Infrastructure**: Kubernetes cluster and node metrics
4. **Security**: Security events and compliance status
5. **Business**: User activity and business KPIs

### Alerting Rules

Critical alerts are configured for:

- **High Error Rate**: >5% error rate for 5 minutes
- **High Response Time**: P95 >2s for 5 minutes
- **Resource Exhaustion**: >80% CPU/memory for 10 minutes
- **Service Unavailability**: Service down for 1 minute
- **Security Events**: Failed authentication attempts, suspicious activity

### Log Aggregation

Centralized logging is configured with:

- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Structured Logging**: JSON format with consistent fields
- **Log Retention**: 90 days for audit and compliance
- **Security Logs**: Separate index for security events

## Security Configuration

### Pod Security Standards

All pods run with restricted security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault
```

### Network Policies

Network segmentation is enforced:

- **API Tier**: Accepts external traffic, communicates with ML tier
- **ML Tier**: Internal only, communicates with data tier
- **Data Tier**: Restricted access from application tiers only

### Secrets Management

Secrets are managed using:

- **External Secrets Operator**: Integration with cloud key management
- **Encryption at Rest**: All secrets encrypted in etcd
- **Rotation**: Automatic secret rotation every 90 days
- **Audit**: All secret access logged and monitored

### RBAC Configuration

Role-based access control includes:

- **Service Accounts**: Minimal privileges for each service
- **User Roles**: Developer, operator, admin roles
- **Namespace Isolation**: Production namespace restricted access
- **API Access**: Fine-grained API permissions

## Performance Optimization

### Resource Allocation

Optimized resource requests and limits:

```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

### Horizontal Pod Autoscaler

Auto-scaling based on metrics:

```yaml
metrics:
- type: Resource
  resource:
    name: cpu
    target:
      type: Utilization
      averageUtilization: 70
- type: Resource
  resource:
    name: memory
    target:
      type: Utilization
      averageUtilization: 80
```

### Vertical Pod Autoscaler

Automatic resource recommendation and adjustment:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: mcp-typescript-api-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-typescript-api
  updatePolicy:
    updateMode: "Auto"
```

### Database Optimization

- **Connection Pooling**: Optimized connection pool sizes
- **Query Optimization**: Indexed queries and query analysis
- **Read Replicas**: Read-only replicas for scaling reads
- **Caching**: Redis caching for frequently accessed data

## Disaster Recovery

### Backup Strategy

- **Database Backups**: Daily full backups, hourly incremental
- **Configuration Backups**: Kubernetes manifests and secrets
- **Application Data**: ML models and user data
- **Cross-Region Replication**: Backup stored in different region

### Recovery Procedures

#### Database Recovery

```bash
# Restore from backup
kubectl exec -it postgres-primary-0 -n mcp-production -- \
  pg_restore -U mcp_user -d mcp_db /backups/latest.dump

# Verify data integrity
kubectl exec -it postgres-primary-0 -n mcp-production -- \
  psql -U mcp_user -d mcp_db -c "SELECT COUNT(*) FROM users;"
```

#### Application Recovery

```bash
# Scale down services
kubectl scale deployment --replicas=0 -n mcp-production --all

# Restore configurations
kubectl apply -f k8s/mcp-deployment.yaml

# Scale up services
kubectl scale deployment mcp-typescript-api --replicas=3 -n mcp-production
kubectl scale deployment mcp-learning-system --replicas=2 -n mcp-production
kubectl scale deployment mcp-rust-server --replicas=3 -n mcp-production
```

### RTO and RPO Targets

- **Recovery Time Objective (RTO)**: 30 minutes
- **Recovery Point Objective (RPO)**: 1 hour
- **Mean Time to Recovery (MTTR)**: 15 minutes

## Troubleshooting

### Common Issues

#### Pod Startup Failures

```bash
# Check pod status and events
kubectl describe pod <pod-name> -n mcp-production

# Check logs
kubectl logs <pod-name> -n mcp-production --previous

# Common causes:
# - Image pull failures: Check registry credentials
# - Resource limits: Check node resources
# - Configuration errors: Validate ConfigMaps and Secrets
```

#### High Response Times

```bash
# Check resource utilization
kubectl top pods -n mcp-production

# Check HPA status
kubectl get hpa -n mcp-production

# Scale manually if needed
kubectl scale deployment mcp-typescript-api --replicas=5 -n mcp-production
```

#### Database Connection Issues

```bash
# Check database pod status
kubectl get pods -l app=postgres -n mcp-production

# Test connectivity
kubectl exec -it mcp-typescript-api-xxx -n mcp-production -- \
  nc -zv postgres 5432

# Check connection pool
kubectl logs -l app=mcp-typescript-api -n mcp-production | grep "connection"
```

### Performance Debugging

#### CPU Analysis

```bash
# Get CPU usage
kubectl top pods -n mcp-production

# Profile application (if profiling enabled)
kubectl port-forward svc/mcp-typescript-api-service 3000:3000 -n mcp-production
curl http://localhost:3000/debug/pprof/profile?seconds=30
```

#### Memory Analysis

```bash
# Check memory usage
kubectl top pods -n mcp-production

# Check for memory leaks
kubectl logs -l app=mcp-learning-system -n mcp-production | grep "memory"

# Generate heap dump (if supported)
kubectl exec -it mcp-learning-system-xxx -n mcp-production -- \
  python -c "import gc; gc.collect(); print('Memory cleaned')"
```

### Emergency Procedures

#### Service Outage

1. **Immediate Response**:
   ```bash
   # Check overall system status
   kubectl get pods -n mcp-production
   kubectl get services -n mcp-production
   
   # Check ingress status
   kubectl get ingress -n mcp-production
   ```

2. **Rollback if needed**:
   ```bash
   # Rollback to previous version
   kubectl rollout undo deployment/mcp-typescript-api -n mcp-production
   kubectl rollout undo deployment/mcp-learning-system -n mcp-production
   kubectl rollout undo deployment/mcp-rust-server -n mcp-production
   ```

3. **Scale up if needed**:
   ```bash
   # Emergency scaling
   kubectl scale deployment mcp-typescript-api --replicas=10 -n mcp-production
   ```

#### Database Outage

1. **Check database status**:
   ```bash
   kubectl get pods -l app=postgres -n mcp-production
   kubectl logs postgres-primary-0 -n mcp-production
   ```

2. **Failover to replica** (if configured):
   ```bash
   # Promote replica to primary
   kubectl patch statefulset postgres-replica -n mcp-production \
     -p '{"spec":{"serviceName":"postgres-primary"}}'
   ```

3. **Update application configuration**:
   ```bash
   # Update database URL in secret
   kubectl patch secret mcp-secrets -n mcp-production \
     --patch='{"data":{"database-url":"<new-database-url-base64>"}}'
   
   # Restart applications
   kubectl rollout restart deployment -n mcp-production
   ```

### Health Checks

#### Service Health

```bash
# Check all service health endpoints
curl -f https://api.mcp-production.com/health
curl -f https://api.mcp-production.com/ml/health
curl -f https://api.mcp-production.com/compute/health
```

#### Database Health

```bash
# Check database connectivity
kubectl exec -it postgres-primary-0 -n mcp-production -- \
  pg_isready -U mcp_user -d mcp_db
```

#### Cache Health

```bash
# Check Redis connectivity
kubectl exec -it redis-0 -n mcp-production -- redis-cli ping
```

### Log Analysis

#### Application Logs

```bash
# Stream logs from all services
kubectl logs -f -l tier=api -n mcp-production
kubectl logs -f -l tier=ml -n mcp-production
kubectl logs -f -l tier=compute -n mcp-production

# Search for errors
kubectl logs -l app=mcp-typescript-api -n mcp-production | grep ERROR
```

#### System Logs

```bash
# Check node logs
kubectl describe nodes

# Check cluster events
kubectl get events -n mcp-production --sort-by='.lastTimestamp'
```

## Contact Information

### On-Call Rotation

- **Primary**: DevOps Team (+1-555-0001)
- **Secondary**: Platform Team (+1-555-0002)
- **Escalation**: Engineering Manager (+1-555-0003)

### Communication Channels

- **Slack**: #mcp-production-alerts
- **Email**: mcp-alerts@company.com
- **PagerDuty**: MCP Production Service

### Support Resources

- **Runbooks**: `/docs/runbooks/`
- **Architecture Docs**: `/docs/architecture/`
- **API Documentation**: `https://api.mcp-production.com/docs`
- **Monitoring**: `https://grafana.mcp-production.com`

---

**Document Version**: v1.0.0  
**Last Updated**: 2025-01-08  
**Next Review**: 2025-04-08