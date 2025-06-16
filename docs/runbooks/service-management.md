# Service Management Runbook

## Table of Contents

1. [Overview](#overview)
2. [Service Lifecycle Management](#service-lifecycle-management)
3. [Startup Procedures](#startup-procedures)
4. [Shutdown Procedures](#shutdown-procedures)
5. [Restart Procedures](#restart-procedures)
6. [Health Checks and Validation](#health-checks-and-validation)
7. [Configuration Management](#configuration-management)
8. [Environment-Specific Procedures](#environment-specific-procedures)
9. [Emergency Procedures](#emergency-procedures)
10. [Maintenance Mode](#maintenance-mode)

## Overview

This runbook provides comprehensive procedures for managing the lifecycle of CODE project services. It covers startup, shutdown, restart, and configuration management across all environments.

### Service Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Load Balancer (ALB)                     │
├─────────────────────────────────────────────────────────────┤
│  API Gateway / Ingress Controller                          │
├─────────────────────────────────────────────────────────────┤
│                    Application Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   API Server    │  │   Worker Pods   │  │  Auth Service││
│  │   (6 replicas)  │  │   (3 replicas)  │  │  (2 replicas)││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
├─────────────────────────────────────────────────────────────┤
│                      Data Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   PostgreSQL    │  │     Redis       │  │  Message     ││
│  │   (Multi-AZ)    │  │   (Cluster)     │  │   Queue      ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Service Dependencies

```
API Server → Database + Redis + Auth Service
Worker → Database + Redis + Message Queue
Auth Service → Database + Redis
```

### Key Services

| Service | Namespace | Type | Replicas | Dependencies |
|---------|-----------|------|----------|--------------|
| claude-deployment-api | claude-deployment-prod | Deployment | 6 | Database, Redis, Auth |
| claude-deployment-worker | claude-deployment-prod | Deployment | 3 | Database, Redis, Queue |
| claude-deployment-auth | claude-deployment-prod | Deployment | 2 | Database, Redis |
| postgres | external | RDS | 1 (Multi-AZ) | - |
| redis | claude-deployment-prod | StatefulSet | 3 | - |

## Service Lifecycle Management

### Service States

1. **Starting**: Service is initializing
2. **Running**: Service is operational and healthy
3. **Degraded**: Service is running but with issues
4. **Stopping**: Service is gracefully shutting down
5. **Stopped**: Service is not running
6. **Failed**: Service has crashed or failed to start

### State Transitions

```
Stopped → Starting → Running
Running → Degraded → Running (with intervention)
Running → Stopping → Stopped
Failed → Starting → Running (after troubleshooting)
```

## Startup Procedures

### Pre-Startup Checklist

```markdown
- [ ] Verify infrastructure is healthy
- [ ] Check database connectivity
- [ ] Validate configuration files
- [ ] Ensure secrets are available
- [ ] Verify resource availability
- [ ] Check dependencies are running
```

### Full System Startup

#### Step 1: Infrastructure Validation

```bash
# Check cluster health
kubectl cluster-info
kubectl get nodes

# Verify storage classes
kubectl get storageclass

# Check networking
kubectl get svc -n kube-system

# Validate ingress controller
kubectl get pods -n ingress-nginx
```

#### Step 2: Start Data Layer Services

```bash
# Start Redis cluster
kubectl apply -f k8s/production/redis/

# Wait for Redis to be ready
kubectl wait --for=condition=ready pod -l app=redis -n claude-deployment-prod --timeout=300s

# Verify Redis connectivity
kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL ping

# Verify database connectivity (RDS should already be running)
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;"
```

#### Step 3: Start Support Services

```bash
# Start monitoring services
kubectl apply -f k8s/production/monitoring/

# Start authentication service
kubectl apply -f k8s/production/auth/

# Wait for auth service to be ready
kubectl wait --for=condition=available deployment/claude-deployment-auth \
  -n claude-deployment-prod --timeout=300s

# Verify auth service
curl -f https://api.claude-deployment.com/auth/health
```

#### Step 4: Start Core Application Services

```bash
# Deploy configmaps and secrets first
kubectl apply -f k8s/production/configmaps.yaml
kubectl apply -f k8s/production/secrets.yaml

# Start API server
kubectl apply -f k8s/production/api/

# Wait for API pods to be ready
kubectl wait --for=condition=available deployment/claude-deployment-api \
  -n claude-deployment-prod --timeout=600s

# Start worker services
kubectl apply -f k8s/production/worker/

# Wait for workers to be ready
kubectl wait --for=condition=available deployment/claude-deployment-worker \
  -n claude-deployment-prod --timeout=300s
```

#### Step 5: Start External-Facing Services

```bash
# Apply ingress configuration
kubectl apply -f k8s/production/ingress.yaml

# Verify load balancer is provisioned
kubectl get ingress -n claude-deployment-prod

# Check ALB target group health
aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN
```

#### Step 6: Validation and Testing

```bash
# Run health checks
curl -f https://api.claude-deployment.com/health

# Run smoke tests
./scripts/smoke-tests.sh

# Verify metrics collection
curl -s https://api.claude-deployment.com/metrics | head -10

# Check logs for errors
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --tail=50 | grep ERROR
```

### Individual Service Startup

#### API Server Startup

```bash
# Check prerequisites
kubectl get configmap claude-deployment-config -n claude-deployment-prod
kubectl get secret claude-deployment-secrets -n claude-deployment-prod

# Deploy API server
kubectl apply -f k8s/production/api-deployment.yaml

# Monitor startup
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod

# Verify startup
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --tail=20
```

#### Worker Service Startup

```bash
# Deploy worker
kubectl apply -f k8s/production/worker-deployment.yaml

# Monitor startup
kubectl rollout status deployment/claude-deployment-worker -n claude-deployment-prod

# Check worker logs
kubectl logs deployment/claude-deployment-worker -n claude-deployment-prod --tail=20

# Verify job processing
kubectl exec -it deployment/claude-deployment-worker -n claude-deployment-prod -- \
  python -c "from app.worker import check_queue_health; print(check_queue_health())"
```

### Service Startup Scripts

#### API Server Startup Script

```bash
#!/bin/bash
# start-api.sh

set -e

echo "Starting API Server..."

# Set variables
NAMESPACE="claude-deployment-prod"
DEPLOYMENT="claude-deployment-api"
TIMEOUT="600s"

# Validate prerequisites
echo "Checking prerequisites..."
kubectl get configmap claude-deployment-config -n $NAMESPACE > /dev/null
kubectl get secret claude-deployment-secrets -n $NAMESPACE > /dev/null

# Check database connectivity
echo "Testing database connectivity..."
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;" > /dev/null

# Start service
echo "Deploying API server..."
kubectl apply -f k8s/production/api-deployment.yaml

# Wait for readiness
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=$TIMEOUT

# Verify health
echo "Running health checks..."
sleep 30  # Allow load balancer to detect healthy targets
curl -f https://api.claude-deployment.com/health

echo "API Server startup completed successfully!"
```

#### Worker Startup Script

```bash
#!/bin/bash
# start-worker.sh

set -e

echo "Starting Worker Services..."

NAMESPACE="claude-deployment-prod"
DEPLOYMENT="claude-deployment-worker"

# Check Redis connectivity
echo "Testing Redis connectivity..."
kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL ping > /dev/null

# Start workers
echo "Deploying workers..."
kubectl apply -f k8s/production/worker-deployment.yaml

# Wait for readiness
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=300s

# Verify workers are processing
echo "Verifying worker functionality..."
kubectl logs deployment/$DEPLOYMENT -n $NAMESPACE --tail=10 | grep -q "Worker started" || \
  echo "Warning: Worker may not have started correctly"

echo "Worker services startup completed!"
```

## Shutdown Procedures

### Graceful Shutdown Order

1. Stop accepting new requests (maintenance mode)
2. Complete ongoing requests
3. Stop API servers
4. Stop worker processes
5. Stop support services
6. Stop data services (if required)

### Full System Shutdown

#### Step 1: Enable Maintenance Mode

```bash
# Deploy maintenance page
kubectl apply -f k8s/maintenance-page.yaml

# Verify maintenance page is active
curl -I https://api.claude-deployment.com | grep "503 Service Temporarily Unavailable"

# Update status page
curl -X POST https://api.statuspage.io/v1/pages/${PAGE_ID}/incidents \
  -H "Authorization: OAuth ${STATUS_PAGE_TOKEN}" \
  -d '{
    "incident": {
      "name": "Scheduled Maintenance",
      "status": "investigating",
      "impact_override": "maintenance"
    }
  }'
```

#### Step 2: Drain API Traffic

```bash
# Scale down API servers gradually
kubectl scale deployment claude-deployment-api --replicas=3 -n claude-deployment-prod
sleep 60

kubectl scale deployment claude-deployment-api --replicas=1 -n claude-deployment-prod
sleep 60

# Allow existing connections to complete
echo "Waiting for connections to drain..."
sleep 120
```

#### Step 3: Stop Application Services

```bash
# Stop workers first (they don't handle user requests)
kubectl scale deployment claude-deployment-worker --replicas=0 -n claude-deployment-prod

# Wait for workers to finish current jobs
kubectl wait --for=condition=available=false deployment/claude-deployment-worker \
  -n claude-deployment-prod --timeout=300s

# Stop API servers
kubectl scale deployment claude-deployment-api --replicas=0 -n claude-deployment-prod

# Stop auth service
kubectl scale deployment claude-deployment-auth --replicas=0 -n claude-deployment-prod
```

#### Step 4: Stop Support Services (if needed)

```bash
# Stop monitoring (optional)
kubectl scale deployment prometheus --replicas=0 -n monitoring
kubectl scale deployment grafana --replicas=0 -n monitoring

# Stop Redis (only if required for maintenance)
kubectl scale statefulset redis --replicas=0 -n claude-deployment-prod
```

### Individual Service Shutdown

#### Graceful API Server Shutdown

```bash
# Get current replica count
CURRENT_REPLICAS=$(kubectl get deployment claude-deployment-api -n claude-deployment-prod -o jsonpath='{.spec.replicas}')

# Scale down gradually
for ((i=$CURRENT_REPLICAS; i>0; i--)); do
  kubectl scale deployment claude-deployment-api --replicas=$((i-1)) -n claude-deployment-prod
  echo "Scaled to $((i-1)) replicas, waiting 30 seconds..."
  sleep 30
done

# Verify all pods are terminated
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api
```

#### Force Shutdown (Emergency)

```bash
# Immediate shutdown (use only in emergencies)
kubectl delete deployment claude-deployment-api -n claude-deployment-prod --grace-period=0 --force

# Or delete specific pods
kubectl delete pods -l app=claude-deployment-api -n claude-deployment-prod --grace-period=10
```

### Shutdown Scripts

#### Complete System Shutdown Script

```bash
#!/bin/bash
# shutdown-system.sh

set -e

echo "Starting graceful system shutdown..."

NAMESPACE="claude-deployment-prod"

# Enable maintenance mode
echo "Enabling maintenance mode..."
kubectl apply -f k8s/maintenance-page.yaml
sleep 30

# Stop workers first
echo "Stopping worker services..."
kubectl scale deployment claude-deployment-worker --replicas=0 -n $NAMESPACE
kubectl wait --for=condition=available=false deployment/claude-deployment-worker \
  -n $NAMESPACE --timeout=300s

# Gradually scale down API
echo "Scaling down API servers..."
CURRENT_REPLICAS=$(kubectl get deployment claude-deployment-api -n $NAMESPACE -o jsonpath='{.spec.replicas}')

for ((i=$CURRENT_REPLICAS; i>0; i--)); do
  kubectl scale deployment claude-deployment-api --replicas=$((i-1)) -n $NAMESPACE
  echo "Scaled API to $((i-1)) replicas, waiting..."
  sleep 45
done

# Stop auth service
echo "Stopping auth service..."
kubectl scale deployment claude-deployment-auth --replicas=0 -n $NAMESPACE

# Optional: Stop support services
read -p "Stop monitoring services? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  kubectl scale deployment prometheus --replicas=0 -n monitoring
  kubectl scale deployment grafana --replicas=0 -n monitoring
fi

echo "System shutdown completed successfully!"
echo "To restart, run: ./scripts/startup-system.sh"
```

## Restart Procedures

### Rolling Restart (Zero Downtime)

#### API Server Rolling Restart

```bash
# Trigger rolling restart
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

# Monitor progress
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod

# Verify all pods are updated
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api \
  -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready,RESTARTS:.status.containerStatuses[0].restartCount
```

#### Forced Restart with Annotation

```bash
# Force restart by updating annotation
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"'$(date +%Y-%m-%dT%H:%M:%S%z)'"}}}}}'

# Monitor restart
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod
```

### Blue-Green Restart

```bash
# Create blue-green deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: claude-deployment-api-blue
  namespace: claude-deployment-prod
spec:
  replicas: 6
  selector:
    matchLabels:
      app: claude-deployment-api
      version: blue
  template:
    metadata:
      labels:
        app: claude-deployment-api
        version: blue
    spec:
      containers:
      - name: api
        image: your-registry/claude-deployment-api:latest
        # ... rest of container spec
EOF

# Wait for blue deployment to be ready
kubectl rollout status deployment/claude-deployment-api-blue -n claude-deployment-prod

# Update service to point to blue deployment
kubectl patch service claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"selector":{"version":"blue"}}}'

# Scale down original deployment
kubectl scale deployment claude-deployment-api --replicas=0 -n claude-deployment-prod

# Clean up after verification
kubectl delete deployment claude-deployment-api-blue -n claude-deployment-prod
```

### Service-Specific Restart Procedures

#### Database Connection Reset

```bash
# Restart all services that connect to database
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
kubectl rollout restart deployment/claude-deployment-worker -n claude-deployment-prod
kubectl rollout restart deployment/claude-deployment-auth -n claude-deployment-prod

# Monitor all restarts
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod &
kubectl rollout status deployment/claude-deployment-worker -n claude-deployment-prod &
kubectl rollout status deployment/claude-deployment-auth -n claude-deployment-prod &
wait

echo "All services restarted successfully"
```

#### Redis Cluster Restart

```bash
# Restart Redis nodes one by one
for i in {0..2}; do
  echo "Restarting redis-$i..."
  kubectl delete pod redis-$i -n claude-deployment-prod
  kubectl wait --for=condition=ready pod/redis-$i -n claude-deployment-prod --timeout=300s
  sleep 30
done

# Verify cluster health
kubectl exec -it redis-0 -n claude-deployment-prod -- redis-cli cluster info
```

## Health Checks and Validation

### Health Check Endpoints

```bash
# API Server Health
curl -f https://api.claude-deployment.com/health

# Auth Service Health
curl -f https://api.claude-deployment.com/auth/health

# Detailed Health Check
curl -s https://api.claude-deployment.com/health/detailed | jq .
```

### Kubernetes Health Checks

```bash
# Pod readiness and liveness
kubectl get pods -n claude-deployment-prod -o wide

# Service endpoints
kubectl get endpoints -n claude-deployment-prod

# Ingress status
kubectl get ingress -n claude-deployment-prod
kubectl describe ingress claude-deployment-ingress -n claude-deployment-prod
```

### Database Health Checks

```bash
# Basic connectivity
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;"

# Connection count
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Database size and performance
psql $DATABASE_URL -c "
SELECT 
  pg_size_pretty(pg_database_size('claude_deployment')) as db_size,
  (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') as active_connections;
"
```

### Cache Health Checks

```bash
# Redis connectivity
kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL ping

# Redis cluster status
kubectl exec -it redis-0 -n claude-deployment-prod -- redis-cli cluster info

# Redis memory usage
kubectl exec -it redis-0 -n claude-deployment-prod -- redis-cli info memory
```

### Load Balancer Health Checks

```bash
# ALB target group health
aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN

# Check individual targets
aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN \
  --query 'TargetHealthDescriptions[?TargetHealth.State!=`healthy`]'
```

### Comprehensive Health Check Script

```bash
#!/bin/bash
# health-check.sh

echo "=== Comprehensive Health Check ==="

# Kubernetes cluster health
echo "Checking cluster health..."
kubectl cluster-info > /dev/null && echo "✅ Cluster: Healthy" || echo "❌ Cluster: Unhealthy"

# Node health
echo "Checking node health..."
READY_NODES=$(kubectl get nodes --no-headers | grep " Ready " | wc -l)
TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l)
echo "✅ Nodes: $READY_NODES/$TOTAL_NODES Ready"

# Pod health
echo "Checking pod health..."
RUNNING_PODS=$(kubectl get pods -n claude-deployment-prod --no-headers | grep "Running" | wc -l)
TOTAL_PODS=$(kubectl get pods -n claude-deployment-prod --no-headers | wc -l)
echo "✅ Pods: $RUNNING_PODS/$TOTAL_PODS Running"

# Service health
echo "Checking service health..."
curl -sf https://api.claude-deployment.com/health > /dev/null && \
  echo "✅ API: Healthy" || echo "❌ API: Unhealthy"

curl -sf https://api.claude-deployment.com/auth/health > /dev/null && \
  echo "✅ Auth: Healthy" || echo "❌ Auth: Unhealthy"

# Database health
echo "Checking database health..."
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;" > /dev/null 2>&1 && \
  echo "✅ Database: Healthy" || echo "❌ Database: Unhealthy"

# Redis health
echo "Checking Redis health..."
kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL ping > /dev/null 2>&1 && \
  echo "✅ Redis: Healthy" || echo "❌ Redis: Unhealthy"

echo "=== Health Check Complete ==="
```

## Configuration Management

### ConfigMap Management

#### View Current Configuration

```bash
# List all configmaps
kubectl get configmaps -n claude-deployment-prod

# View specific configmap
kubectl get configmap claude-deployment-config -n claude-deployment-prod -o yaml

# Extract specific values
kubectl get configmap claude-deployment-config -n claude-deployment-prod \
  -o jsonpath='{.data.database-pool-size}'
```

#### Update Configuration

```bash
# Update single value
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"feature-flag-new-ui":"true"}}'

# Update multiple values
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"database-pool-size":"50","redis-timeout":"5000"}}'

# Replace entire configmap
kubectl apply -f k8s/production/configmaps.yaml

# Restart services to pick up changes
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

### Secret Management

#### View Secrets (safely)

```bash
# List secrets
kubectl get secrets -n claude-deployment-prod

# View secret structure (without values)
kubectl get secret claude-deployment-secrets -n claude-deployment-prod -o yaml | \
  grep -v "^\s*[^:]*:\s*[A-Za-z0-9+/]"

# Decode specific secret value
kubectl get secret claude-deployment-secrets -n claude-deployment-prod \
  -o jsonpath='{.data.database-password}' | base64 -d
```

#### Update Secrets

```bash
# Update database password
kubectl create secret generic claude-deployment-secrets \
  --from-literal=database-password="new-password" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Update multiple secrets
kubectl create secret generic claude-deployment-secrets \
  --from-literal=database-password="new-db-pass" \
  --from-literal=redis-password="new-redis-pass" \
  --from-literal=jwt-secret="new-jwt-secret" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart services to use new secrets
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
kubectl rollout restart deployment/claude-deployment-auth -n claude-deployment-prod
```

### Environment Variables

#### Runtime Configuration Updates

```bash
# Update environment variable
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","env":[{"name":"LOG_LEVEL","value":"DEBUG"}]}]}}}}'

# Add new environment variable
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","env":[{"name":"NEW_FEATURE_ENABLED","value":"true"}]}]}}}}'
```

## Environment-Specific Procedures

### Production Environment

#### Production Startup Checklist

```markdown
- [ ] Verify backup systems are operational
- [ ] Check monitoring and alerting systems
- [ ] Validate SSL certificates
- [ ] Confirm disaster recovery readiness
- [ ] Review capacity planning
- [ ] Ensure compliance requirements met
- [ ] Validate security configurations
- [ ] Check external dependency status
```

#### Production-Specific Commands

```bash
# Enable production logging
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"log-level":"INFO","log-format":"json"}}'

# Set production resource limits
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"4Gi","cpu":"2000m"},"requests":{"memory":"2Gi","cpu":"1000m"}}}]}}}}'

# Enable horizontal pod autoscaler
kubectl apply -f k8s/production/hpa.yaml
```

### Staging Environment

#### Staging-Specific Configuration

```bash
# Use reduced resource allocations
kubectl patch deployment claude-deployment-api -n claude-deployment-staging \
  -p '{"spec":{"replicas":2,"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"2Gi","cpu":"1000m"},"requests":{"memory":"1Gi","cpu":"500m"}}}]}}}}'

# Enable debug logging
kubectl patch configmap claude-deployment-config -n claude-deployment-staging \
  -p '{"data":{"log-level":"DEBUG","debug-mode":"true"}}'
```

### Development Environment

#### Development Quick Start

```bash
# Minimal deployment for development
kubectl create namespace claude-deployment-dev

# Deploy with minimal resources
helm install claude-deployment ./helm/claude-deployment \
  --namespace claude-deployment-dev \
  --set replicaCount=1 \
  --set resources.limits.memory=1Gi \
  --set resources.limits.cpu=500m
```

## Emergency Procedures

### Emergency Stop

```bash
#!/bin/bash
# emergency-stop.sh

echo "EMERGENCY STOP initiated..."

# Immediate maintenance page
kubectl apply -f k8s/emergency-maintenance.yaml

# Stop all application services immediately
kubectl scale deployment claude-deployment-api --replicas=0 -n claude-deployment-prod --grace-period=10
kubectl scale deployment claude-deployment-worker --replicas=0 -n claude-deployment-prod --grace-period=10
kubectl scale deployment claude-deployment-auth --replicas=0 -n claude-deployment-prod --grace-period=10

# Update status page
curl -X POST https://api.statuspage.io/v1/pages/${PAGE_ID}/incidents \
  -H "Authorization: OAuth ${STATUS_PAGE_TOKEN}" \
  -d '{
    "incident": {
      "name": "Emergency Maintenance",
      "status": "investigating",
      "impact_override": "major_outage"
    }
  }'

echo "Emergency stop completed. All services stopped."
```

### Emergency Restart

```bash
#!/bin/bash
# emergency-restart.sh

echo "EMERGENCY RESTART initiated..."

# Scale up services
kubectl scale deployment claude-deployment-auth --replicas=2 -n claude-deployment-prod
kubectl scale deployment claude-deployment-api --replicas=6 -n claude-deployment-prod
kubectl scale deployment claude-deployment-worker --replicas=3 -n claude-deployment-prod

# Wait for services to be ready
kubectl wait --for=condition=available deployment/claude-deployment-auth -n claude-deployment-prod --timeout=300s
kubectl wait --for=condition=available deployment/claude-deployment-api -n claude-deployment-prod --timeout=300s
kubectl wait --for=condition=available deployment/claude-deployment-worker -n claude-deployment-prod --timeout=300s

# Remove maintenance page
kubectl delete -f k8s/emergency-maintenance.yaml

# Verify health
sleep 30
curl -f https://api.claude-deployment.com/health || echo "Health check failed!"

echo "Emergency restart completed."
```

### Circuit Breaker Activation

```bash
# Enable circuit breaker for external APIs
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"circuit-breaker-enabled":"true","circuit-breaker-failure-threshold":"5","circuit-breaker-timeout":"30000"}}'

# Restart API to activate circuit breaker
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

echo "Circuit breaker activated for external dependencies."
```

## Maintenance Mode

### Enable Maintenance Mode

```bash
# Deploy maintenance page
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: maintenance-page
  namespace: claude-deployment-prod
data:
  index.html: |
    <!DOCTYPE html>
    <html>
    <head>
        <title>Maintenance</title>
        <style>
            body { font-family: Arial; text-align: center; padding: 50px; }
            h1 { color: #333; }
        </style>
    </head>
    <body>
        <h1>Service Temporarily Unavailable</h1>
        <p>We are performing scheduled maintenance. Please try again later.</p>
        <p>Estimated completion: $(date -d '+2 hours' +'%Y-%m-%d %H:%M UTC')</p>
    </body>
    </html>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maintenance-page
  namespace: claude-deployment-prod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: maintenance-page
  template:
    metadata:
      labels:
        app: maintenance-page
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: maintenance-content
          mountPath: /usr/share/nginx/html
      volumes:
      - name: maintenance-content
        configMap:
          name: maintenance-page
---
apiVersion: v1
kind: Service
metadata:
  name: maintenance-page
  namespace: claude-deployment-prod
spec:
  selector:
    app: maintenance-page
  ports:
  - port: 80
    targetPort: 80
EOF

# Update ingress to point to maintenance page
kubectl patch ingress claude-deployment-ingress -n claude-deployment-prod \
  -p '{"spec":{"rules":[{"host":"api.claude-deployment.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"maintenance-page","port":{"number":80}}}}]}}]}}'
```

### Disable Maintenance Mode

```bash
# Restore normal ingress
kubectl apply -f k8s/production/ingress.yaml

# Remove maintenance page
kubectl delete deployment,service,configmap maintenance-page -n claude-deployment-prod

# Verify normal operation
curl -f https://api.claude-deployment.com/health
```

---

## Quick Reference

### Essential Commands

```bash
# Start all services
./scripts/startup-system.sh

# Stop all services
./scripts/shutdown-system.sh

# Restart API server
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

# Emergency stop
kubectl scale deployment claude-deployment-api --replicas=0 -n claude-deployment-prod

# Health check
curl -f https://api.claude-deployment.com/health
```

### Service URLs

- **Production API**: https://api.claude-deployment.com
- **Health Check**: https://api.claude-deployment.com/health
- **Metrics**: https://api.claude-deployment.com/metrics
- **Auth Service**: https://api.claude-deployment.com/auth/health

### Emergency Contacts

- **Primary On-Call**: +1-555-0123
- **Infrastructure Team**: +1-555-0128
- **Manager**: +1-555-0125

Remember: Always follow the principle of "safety first" - when in doubt, enable maintenance mode and investigate thoroughly.