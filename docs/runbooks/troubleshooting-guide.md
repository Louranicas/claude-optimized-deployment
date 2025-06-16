# Troubleshooting Guide

## Table of Contents

1. [General Troubleshooting Approach](#general-troubleshooting-approach)
2. [Application Issues](#application-issues)
3. [Database Issues](#database-issues)
4. [Infrastructure Issues](#infrastructure-issues)
5. [Network and Connectivity Issues](#network-and-connectivity-issues)
6. [Performance Issues](#performance-issues)
7. [Security Issues](#security-issues)
8. [Monitoring and Alerting Issues](#monitoring-and-alerting-issues)
9. [External Dependencies](#external-dependencies)
10. [Recovery Procedures](#recovery-procedures)

## General Troubleshooting Approach

### Systematic Investigation Process

1. **Define the Problem**
   - What is broken?
   - When did it start?
   - What changed recently?
   - What is the impact?

2. **Gather Information**
   - Check monitoring dashboards
   - Review recent logs
   - Examine metrics
   - Check recent deployments

3. **Form Hypothesis**
   - Based on symptoms and data
   - Consider recent changes
   - Review similar past incidents

4. **Test Hypothesis**
   - Use non-destructive tests first
   - Document all tests performed
   - Validate results

5. **Implement Solution**
   - Apply minimal viable fix
   - Monitor impact
   - Document changes

6. **Verify Resolution**
   - Confirm issue is resolved
   - Monitor for side effects
   - Update documentation

### Essential Troubleshooting Commands

```bash
# System overview
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods -n claude-deployment-prod -o wide

# Resource usage
kubectl top nodes
kubectl top pods -n claude-deployment-prod

# Recent events
kubectl get events -n claude-deployment-prod --sort-by='.lastTimestamp'

# Service status
kubectl get svc,ingress -n claude-deployment-prod
kubectl describe svc claude-deployment-api -n claude-deployment-prod

# Log examination
kubectl logs -f deployment/claude-deployment-api -n claude-deployment-prod --tail=100
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | grep ERROR
```

## Application Issues

### API Server Not Responding

#### Symptoms
- Health check endpoint returns 5xx errors
- High response times or timeouts
- Customers unable to access service
- Load balancer showing unhealthy targets

#### Investigation Steps

1. **Check Pod Status**:
   ```bash
   kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api
   kubectl describe pod <pod-name> -n claude-deployment-prod
   ```

2. **Check Application Logs**:
   ```bash
   kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --tail=50
   kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=30m | grep -E "(ERROR|FATAL|Exception)"
   ```

3. **Verify Resource Limits**:
   ```bash
   kubectl describe pod <pod-name> -n claude-deployment-prod | grep -A 10 "Containers:"
   kubectl top pods -n claude-deployment-prod --sort-by=memory
   ```

#### Common Solutions

**Solution 1: Resource Exhaustion**
```bash
# Scale up pods
kubectl scale deployment claude-deployment-api --replicas=8 -n claude-deployment-prod

# Or increase resource limits
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"4Gi","cpu":"2000m"}}}]}}}}'
```

**Solution 2: Application Error**
```bash
# Restart pods
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

# Or rollback to previous version
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod
```

**Solution 3: Configuration Issue**
```bash
# Check configuration
kubectl get configmap claude-deployment-config -n claude-deployment-prod -o yaml

# Restore from backup if needed
kubectl apply -f k8s/production/configmaps.yaml
```

### High Error Rates

#### Symptoms
- Increased 4xx/5xx HTTP responses
- Application throwing exceptions
- Customers reporting functionality broken
- Monitoring alerts for error rates

#### Investigation Steps

1. **Identify Error Patterns**:
   ```bash
   # Check error distribution
   kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | \
     grep ERROR | awk '{print $1, $2}' | sort | uniq -c | sort -nr

   # Check specific error types
   kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | \
     grep -E "(500|502|503|504)" | tail -20
   ```

2. **Check External Dependencies**:
   ```bash
   # Test database connectivity
   kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
     psql $DATABASE_URL -c "SELECT 1;"

   # Test Redis connectivity
   kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
     redis-cli -u $REDIS_URL ping

   # Test external APIs
   curl -I https://api.openai.com/v1/models
   ```

3. **Review Recent Changes**:
   ```bash
   kubectl rollout history deployment/claude-deployment-api -n claude-deployment-prod
   git log --oneline --since="2 hours ago"
   ```

#### Common Solutions

**Solution 1: Database Connection Issues**
```bash
# Check connection pool settings
kubectl get configmap claude-deployment-config -n claude-deployment-prod -o yaml | grep -i pool

# Restart application to reset connections
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

# Scale down temporarily to reduce connection pressure
kubectl scale deployment claude-deployment-api --replicas=4 -n claude-deployment-prod
```

**Solution 2: External API Failures**
```bash
# Enable circuit breaker
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"circuit-breaker-enabled":"true","circuit-breaker-failure-threshold":"5"}}'

# Restart to apply config
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

**Solution 3: Bad Deployment**
```bash
# Rollback to previous version
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod

# Monitor rollback
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod
```

### Memory Leaks

#### Symptoms
- Pods restarting due to OOMKilled
- Gradually increasing memory usage
- Performance degradation over time
- Out of memory errors in logs

#### Investigation Steps

1. **Check Memory Usage Trends**:
   ```bash
   # Current memory usage
   kubectl top pods -n claude-deployment-prod --sort-by=memory

   # Check pod restart history
   kubectl get pods -n claude-deployment-prod -o json | \
     jq '.items[] | {name: .metadata.name, restarts: .status.containerStatuses[0].restartCount}'

   # Check for OOMKilled events
   kubectl get events -n claude-deployment-prod | grep OOMKilled
   ```

2. **Memory Profiling**:
   ```bash
   # Enable memory profiling endpoint (if available)
   kubectl port-forward deployment/claude-deployment-api 6060:6060 -n claude-deployment-prod

   # Or check application-specific memory metrics
   curl -s http://localhost:6060/debug/pprof/heap > heap.profile
   ```

#### Common Solutions

**Solution 1: Increase Memory Limits**
```bash
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"8Gi"},"requests":{"memory":"4Gi"}}}]}}}}'
```

**Solution 2: Restart Pods Periodically**
```bash
# Set up pod disruption budget first
kubectl apply -f - <<EOF
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: claude-deployment-api-pdb
  namespace: claude-deployment-prod
spec:
  minAvailable: 4
  selector:
    matchLabels:
      app: claude-deployment-api
EOF

# Rolling restart
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

**Solution 3: Code Fix Required**
```bash
# Emergency mitigation: scale up and rotate pods
kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod

# Create script to periodically restart pods
cat > restart-pods.sh << 'EOF'
#!/bin/bash
while true; do
  sleep 3600  # Wait 1 hour
  kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
  kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod
done
EOF
```

## Database Issues

### Connection Pool Exhaustion

#### Symptoms
- "Too many connections" errors
- Application timeouts when accessing database
- High connection count in database metrics
- Connection pool exhausted alerts

#### Investigation Steps

1. **Check Current Connections**:
   ```bash
   # Connect to database and check connections
   psql $DATABASE_URL -c "
   SELECT 
     count(*) as total_connections,
     count(*) FILTER (WHERE state = 'active') as active_connections,
     count(*) FILTER (WHERE state = 'idle') as idle_connections
   FROM pg_stat_activity;
   "

   # Check connections by source
   psql $DATABASE_URL -c "
   SELECT 
     client_addr, 
     count(*) 
   FROM pg_stat_activity 
   WHERE client_addr IS NOT NULL 
   GROUP BY client_addr 
   ORDER BY count(*) DESC;
   "
   ```

2. **Check Pool Configuration**:
   ```bash
   kubectl get configmap claude-deployment-config -n claude-deployment-prod -o yaml | grep -i pool
   ```

#### Common Solutions

**Solution 1: Kill Idle Connections**
```bash
psql $DATABASE_URL -c "
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'idle' 
  AND state_change < current_timestamp - INTERVAL '5 minutes'
  AND pid <> pg_backend_pid();
"
```

**Solution 2: Increase Pool Size**
```bash
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"db-pool-max":"150","db-pool-min":"20"}}'

kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

**Solution 3: Scale Down Applications Temporarily**
```bash
kubectl scale deployment claude-deployment-api --replicas=3 -n claude-deployment-prod
kubectl scale deployment claude-deployment-worker --replicas=1 -n claude-deployment-prod
```

### Slow Queries

#### Symptoms
- High database CPU usage
- Slow application response times
- Query timeout errors
- Database performance alerts

#### Investigation Steps

1. **Identify Slow Queries**:
   ```bash
   psql $DATABASE_URL -c "
   SELECT 
     query,
     calls,
     total_time,
     mean_time,
     (total_time / calls) as avg_time_ms
   FROM pg_stat_statements 
   ORDER BY total_time DESC 
   LIMIT 10;
   "
   ```

2. **Check for Locks**:
   ```bash
   psql $DATABASE_URL -c "
   SELECT 
     l.pid,
     l.mode,
     l.granted,
     a.query,
     a.state,
     a.query_start
   FROM pg_locks l
   JOIN pg_stat_activity a ON l.pid = a.pid
   WHERE NOT l.granted
   ORDER BY a.query_start;
   "
   ```

3. **Check Index Usage**:
   ```bash
   psql $DATABASE_URL -c "
   SELECT 
     schemaname,
     tablename,
     idx_tup_read,
     idx_tup_fetch,
     seq_tup_read
   FROM pg_stat_user_tables
   WHERE seq_tup_read > 100000
   ORDER BY seq_tup_read DESC;
   "
   ```

#### Common Solutions

**Solution 1: Kill Long-Running Queries**
```bash
psql $DATABASE_URL -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity 
WHERE query_start < current_timestamp - INTERVAL '5 minutes'
  AND state = 'active'
  AND pid <> pg_backend_pid();
"
```

**Solution 2: Add Missing Indexes**
```bash
# Example: Add index for frequently queried columns
psql $DATABASE_URL -c "
CREATE INDEX CONCURRENTLY idx_users_email_created_at 
ON users(email, created_at) 
WHERE active = true;
"
```

**Solution 3: Scale Database Resources**
```bash
# Scale up RDS instance
aws rds modify-db-instance \
  --db-instance-identifier claude-deployment-primary \
  --db-instance-class db.r6g.2xlarge \
  --apply-immediately
```

### Database Connectivity Issues

#### Symptoms
- "Connection refused" errors
- Intermittent database timeouts
- Application unable to connect to database
- Database health checks failing

#### Investigation Steps

1. **Test Basic Connectivity**:
   ```bash
   # Test from application pod
   kubectl exec -it deployment/claude-deployment-api -n claude-deployment-prod -- \
     nc -zv $DB_HOST $DB_PORT

   # Test with psql
   kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
     psql $DATABASE_URL -c "SELECT 1;"
   ```

2. **Check Database Status**:
   ```bash
   # Check RDS instance status
   aws rds describe-db-instances \
     --db-instance-identifier claude-deployment-primary \
     --query 'DBInstances[0].DBInstanceStatus'

   # Check security groups
   aws ec2 describe-security-groups \
     --group-ids $DB_SECURITY_GROUP_ID
   ```

#### Common Solutions

**Solution 1: DNS Resolution Issues**
```bash
# Test DNS resolution
kubectl run dns-test --image=busybox --rm -i --restart=Never -- \
  nslookup $DB_HOST

# Restart CoreDNS if needed
kubectl rollout restart deployment/coredns -n kube-system
```

**Solution 2: Security Group Issues**
```bash
# Allow traffic from application subnets
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SECURITY_GROUP_ID \
  --protocol tcp \
  --port 5432 \
  --source-group $APP_SECURITY_GROUP_ID
```

**Solution 3: Connection String Issues**
```bash
# Verify and update connection string
kubectl get secret claude-deployment-db-secret -n claude-deployment-prod -o yaml

# Update if needed
kubectl create secret generic claude-deployment-db-secret \
  --from-literal=database-url="postgresql://user:pass@host:5432/db" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Infrastructure Issues

### Node Issues

#### Node Not Ready

**Symptoms**: Node shows as NotReady in kubectl get nodes

**Investigation**:
```bash
# Check node status
kubectl get nodes -o wide
kubectl describe node <node-name>

# Check node conditions
kubectl get node <node-name> -o json | jq '.status.conditions'

# SSH to node and check
ssh ec2-user@<node-ip>
sudo journalctl -u kubelet -n 50
```

**Solutions**:
```bash
# Restart kubelet
ssh ec2-user@<node-ip>
sudo systemctl restart kubelet

# Or drain and replace node
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
# Then terminate EC2 instance - ASG will replace it
```

#### Node Disk Space Issues

**Symptoms**: Pods can't be scheduled, disk space alerts

**Investigation**:
```bash
# Check disk usage on nodes
kubectl top nodes
kubectl describe node <node-name> | grep -A 5 "System Info"

# SSH to node and check
ssh ec2-user@<node-ip>
df -h
sudo du -sh /var/lib/docker/
sudo du -sh /var/lib/kubelet/
```

**Solutions**:
```bash
# Clean up Docker images
ssh ec2-user@<node-ip>
sudo docker system prune -f

# Clean up old log files
sudo find /var/log -name "*.log" -mtime +7 -delete

# Or drain and replace node
kubectl drain <node-name> --ignore-daemonsets
```

### Storage Issues

#### Persistent Volume Issues

**Symptoms**: Pods stuck in Pending with volume mount errors

**Investigation**:
```bash
# Check PV and PVC status
kubectl get pv,pvc -n claude-deployment-prod
kubectl describe pvc <pvc-name> -n claude-deployment-prod

# Check storage class
kubectl get storageclass
kubectl describe storageclass gp3

# Check EBS volume status
aws ec2 describe-volumes --volume-ids <volume-id>
```

**Solutions**:
```bash
# Delete and recreate PVC if needed
kubectl delete pvc <pvc-name> -n claude-deployment-prod
kubectl apply -f k8s/production/persistent-volumes.yaml

# Or expand existing volume
kubectl patch pvc <pvc-name> -n claude-deployment-prod \
  -p '{"spec":{"resources":{"requests":{"storage":"200Gi"}}}}'
```

### Cluster Scaling Issues

#### Pods Not Scheduling

**Symptoms**: Pods stuck in Pending state

**Investigation**:
```bash
# Check pod events
kubectl describe pod <pod-name> -n claude-deployment-prod

# Check node resources
kubectl top nodes
kubectl describe nodes | grep -A 5 "Allocated resources"

# Check cluster autoscaler
kubectl logs -f deployment/cluster-autoscaler -n kube-system
```

**Solutions**:
```bash
# Manually scale node group
aws eks update-nodegroup-config \
  --cluster-name claude-deployment-prod \
  --nodegroup-name primary \
  --scaling-config minSize=3,maxSize=20,desiredSize=8

# Or adjust pod resource requests
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"requests":{"memory":"2Gi","cpu":"500m"}}}]}}}}'
```

## Network and Connectivity Issues

### Service Discovery Issues

#### Symptoms
- Pods can't communicate with each other
- DNS resolution failures
- Service endpoints not working

#### Investigation Steps

1. **Test DNS Resolution**:
   ```bash
   # Test internal DNS
   kubectl run dns-test --image=busybox --rm -i --restart=Never -- \
     nslookup claude-deployment-api.claude-deployment-prod.svc.cluster.local

   # Test external DNS
   kubectl run dns-test --image=busybox --rm -i --restart=Never -- \
     nslookup google.com
   ```

2. **Check Service Configuration**:
   ```bash
   kubectl get svc -n claude-deployment-prod
   kubectl describe svc claude-deployment-api -n claude-deployment-prod
   kubectl get endpoints claude-deployment-api -n claude-deployment-prod
   ```

#### Common Solutions

**Solution 1: CoreDNS Issues**
```bash
# Restart CoreDNS
kubectl rollout restart deployment/coredns -n kube-system

# Check CoreDNS logs
kubectl logs -f deployment/coredns -n kube-system

# Check CoreDNS configuration
kubectl get configmap coredns -n kube-system -o yaml
```

**Solution 2: Service Endpoint Issues**
```bash
# Check if pods are selected by service
kubectl get pods -n claude-deployment-prod --show-labels
kubectl get svc claude-deployment-api -n claude-deployment-prod -o yaml

# Fix label selector if needed
kubectl patch svc claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"selector":{"app":"claude-deployment-api","version":"v1"}}}'
```

### Load Balancer Issues

#### Symptoms
- External traffic not reaching services
- Load balancer health checks failing
- SSL/TLS certificate issues

#### Investigation Steps

1. **Check Load Balancer Status**:
   ```bash
   # Check ALB status
   aws elbv2 describe-load-balancers --names claude-deployment-prod-alb

   # Check target group health
   aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN

   # Check Kubernetes ingress
   kubectl get ingress -n claude-deployment-prod
   kubectl describe ingress claude-deployment-ingress -n claude-deployment-prod
   ```

2. **Test Connectivity**:
   ```bash
   # Test internal service
   kubectl run test-pod --image=alpine --rm -i --restart=Never -- \
     wget -qO- http://claude-deployment-api.claude-deployment-prod.svc.cluster.local/health

   # Test external endpoint
   curl -I https://api.claude-deployment.com/health
   ```

#### Common Solutions

**Solution 1: Target Registration Issues**
```bash
# Check node security groups
aws ec2 describe-security-groups --group-ids $NODE_SECURITY_GROUP_ID

# Allow ALB to reach nodes
aws ec2 authorize-security-group-ingress \
  --group-id $NODE_SECURITY_GROUP_ID \
  --protocol tcp \
  --port 30000-32767 \
  --source-group $ALB_SECURITY_GROUP_ID
```

**Solution 2: SSL Certificate Issues**
```bash
# Check certificate status
kubectl get certificate -n claude-deployment-prod
kubectl describe certificate claude-deployment-tls -n claude-deployment-prod

# Renew certificate if needed
kubectl delete certificate claude-deployment-tls -n claude-deployment-prod
kubectl apply -f k8s/production/certificates.yaml
```

### Network Policy Issues

#### Symptoms
- Pods can't communicate despite correct service configuration
- Traffic blocked between namespaces
- External connectivity issues

#### Investigation Steps
```bash
# Check network policies
kubectl get networkpolicies -A
kubectl describe networkpolicy <policy-name> -n claude-deployment-prod

# Test pod-to-pod connectivity
kubectl run test-source --image=alpine --rm -i --restart=Never -- \
  nc -zv <target-pod-ip> <port>
```

#### Common Solutions
```bash
# Temporarily disable network policies for testing
kubectl delete networkpolicy --all -n claude-deployment-prod

# Or create allow-all policy for debugging
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-debug
  namespace: claude-deployment-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - {}
  egress:
  - {}
EOF
```

## Performance Issues

### High CPU Usage

#### Symptoms
- Application response times degraded
- CPU throttling alerts
- Pods restarting due to resource limits

#### Investigation Steps
```bash
# Check CPU usage
kubectl top nodes
kubectl top pods -n claude-deployment-prod --sort-by=cpu

# Check resource limits
kubectl describe pod <pod-name> -n claude-deployment-prod | grep -A 10 "Limits:"

# Check for CPU throttling
kubectl get --raw /api/v1/nodes/<node-name>/proxy/stats/summary | \
  jq '.pods[].containers[] | select(.name=="api") | .cpu'
```

#### Common Solutions
```bash
# Scale horizontally
kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod

# Scale vertically
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"cpu":"2000m"},"requests":{"cpu":"1000m"}}}]}}}}'

# Enable HPA
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: claude-deployment-api-hpa
  namespace: claude-deployment-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: claude-deployment-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
EOF
```

### High Memory Usage

#### Investigation and Solutions
```bash
# Check memory usage
kubectl top pods -n claude-deployment-prod --sort-by=memory

# Check for memory leaks
kubectl exec -it <pod-name> -n claude-deployment-prod -- \
  cat /proc/meminfo

# Increase memory limits
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"8Gi"},"requests":{"memory":"4Gi"}}}]}}}}'
```

### Database Performance Issues

#### Investigation
```bash
# Check slow queries
psql $DATABASE_URL -c "
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;
"

# Check connection pool
psql $DATABASE_URL -c "
SELECT count(*), state 
FROM pg_stat_activity 
GROUP BY state;
"

# Check for locks
psql $DATABASE_URL -c "
SELECT pid, mode, granted, query 
FROM pg_locks 
JOIN pg_stat_activity USING (pid) 
WHERE NOT granted;
"
```

#### Solutions
```bash
# Kill problematic queries
psql $DATABASE_URL -c "SELECT pg_terminate_backend(<pid>);"

# Add read replicas for read queries
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"read-db-url":"postgresql://user:pass@read-replica:5432/db"}}'

# Scale database instance
aws rds modify-db-instance \
  --db-instance-identifier claude-deployment-primary \
  --db-instance-class db.r6g.2xlarge \
  --apply-immediately
```

## Security Issues

### Authentication Failures

#### Symptoms
- Users unable to login
- JWT token validation errors
- Authentication service errors

#### Investigation Steps
```bash
# Check auth service status
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-auth
kubectl logs deployment/claude-deployment-auth -n claude-deployment-prod --tail=50

# Test auth endpoints
curl -X POST https://api.claude-deployment.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Check JWT secret
kubectl get secret claude-deployment-jwt-secret -n claude-deployment-prod -o yaml
```

#### Common Solutions
```bash
# Restart auth service
kubectl rollout restart deployment/claude-deployment-auth -n claude-deployment-prod

# Rotate JWT secret
kubectl create secret generic claude-deployment-jwt-secret \
  --from-literal=jwt-secret="$(openssl rand -base64 32)" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Update session expiration
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"session-timeout":"86400"}}'
```

### SSL/TLS Issues

#### Symptoms
- Certificate validation errors
- HTTPS connection failures
- Browser security warnings

#### Investigation
```bash
# Check certificate expiry
kubectl get certificate -n claude-deployment-prod
kubectl describe certificate claude-deployment-tls -n claude-deployment-prod

# Test SSL endpoint
openssl s_client -connect api.claude-deployment.com:443 -servername api.claude-deployment.com

# Check certificate details
curl -vI https://api.claude-deployment.com 2>&1 | grep -E "(certificate|SSL|TLS)"
```

#### Solutions
```bash
# Renew certificate
kubectl delete certificate claude-deployment-tls -n claude-deployment-prod
kubectl apply -f k8s/production/certificates.yaml

# Update certificate manually
kubectl create secret tls claude-deployment-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  --namespace=claude-deployment-prod
```

### Rate Limiting Issues

#### Symptoms
- 429 Too Many Requests responses
- Legitimate users blocked
- API abuse detected

#### Investigation
```bash
# Check rate limiting metrics
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod | grep "rate limit"

# Check Redis for rate limit data
kubectl run redis-cli --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL --scan --pattern "rate_limit:*"

# Check source IPs
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | \
  grep "429" | awk '{print $1}' | sort | uniq -c | sort -nr
```

#### Solutions
```bash
# Adjust rate limits
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"rate-limit-rpm":"120","rate-limit-burst":"20"}}'

# Whitelist specific IPs
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"rate-limit-whitelist":"192.168.1.0/24,10.0.0.0/8"}}'

# Clear rate limit data
kubectl run redis-cli --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL FLUSHDB
```

## Monitoring and Alerting Issues

### Prometheus Not Scraping Metrics

#### Symptoms
- Missing metrics in Grafana
- Prometheus targets down
- Monitoring alerts not firing

#### Investigation
```bash
# Check Prometheus targets
kubectl port-forward svc/prometheus 9090:9090 -n monitoring
# Open http://localhost:9090/targets

# Check service discovery
kubectl get servicemonitor -n claude-deployment-prod
kubectl describe servicemonitor claude-deployment-api -n claude-deployment-prod

# Check pod metrics endpoint
kubectl exec -it <pod-name> -n claude-deployment-prod -- \
  curl localhost:8080/metrics
```

#### Solutions
```bash
# Fix service discovery labels
kubectl patch svc claude-deployment-api -n claude-deployment-prod \
  -p '{"metadata":{"labels":{"monitoring":"enabled"}}}'

# Restart Prometheus
kubectl rollout restart deployment/prometheus -n monitoring

# Update ServiceMonitor
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: claude-deployment-api
  namespace: claude-deployment-prod
spec:
  selector:
    matchLabels:
      app: claude-deployment-api
  endpoints:
  - port: metrics
    path: /metrics
EOF
```

### Grafana Dashboard Issues

#### Investigation
```bash
# Check Grafana pod status
kubectl get pods -n monitoring -l app=grafana
kubectl logs deployment/grafana -n monitoring --tail=50

# Test database connectivity
kubectl exec -it deployment/grafana -n monitoring -- \
  sqlite3 /var/lib/grafana/grafana.db ".tables"
```

#### Solutions
```bash
# Restart Grafana
kubectl rollout restart deployment/grafana -n monitoring

# Import dashboards
kubectl create configmap grafana-dashboards \
  --from-file=monitoring/dashboards/ \
  --namespace=monitoring

# Reset admin password
kubectl exec -it deployment/grafana -n monitoring -- \
  grafana-cli admin reset-admin-password newpassword
```

### Alert Manager Not Sending Alerts

#### Investigation
```bash
# Check AlertManager status
kubectl get pods -n monitoring -l app=alertmanager
kubectl logs deployment/alertmanager -n monitoring --tail=50

# Check alert rules
kubectl get prometheusrule -n monitoring
kubectl describe prometheusrule claude-deployment-alerts -n monitoring

# Test webhook
curl -X POST https://hooks.slack.com/services/... \
  -H "Content-Type: application/json" \
  -d '{"text":"Test alert"}'
```

#### Solutions
```bash
# Update AlertManager config
kubectl create secret generic alertmanager-config \
  --from-file=monitoring/alertmanager.yml \
  --namespace=monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart AlertManager
kubectl rollout restart deployment/alertmanager -n monitoring

# Silence false alerts
kubectl exec -it deployment/alertmanager -n monitoring -- \
  amtool silence add alertname="HighErrorRate" --duration="1h"
```

## External Dependencies

### Third-party API Issues

#### Investigation
```bash
# Test API connectivity
curl -I https://api.openai.com/v1/models
curl -I https://api.stripe.com/v1/ping

# Check API key validity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models

# Check rate limits
curl -I -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/endpoint | grep -i rate
```

#### Solutions
```bash
# Enable circuit breaker
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"circuit-breaker-enabled":"true"}}'

# Add fallback endpoints
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"openai-fallback-endpoint":"https://api.openai-proxy.com"}}'

# Implement retry logic
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"api-retry-attempts":"3","api-retry-delay":"1000"}}'
```

### DNS Resolution Issues

#### Investigation
```bash
# Test DNS from pods
kubectl run dns-test --image=busybox --rm -i --restart=Never -- \
  nslookup api.openai.com

# Check CoreDNS status
kubectl get pods -n kube-system -l k8s-app=kube-dns

# Check DNS configuration
kubectl get configmap coredns -n kube-system -o yaml
```

#### Solutions
```bash
# Restart CoreDNS
kubectl rollout restart deployment/coredns -n kube-system

# Update DNS servers
kubectl patch configmap coredns -n kube-system \
  --patch='{"data":{"Corefile":".:53 {\n    errors\n    health\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n        pods insecure\n        fallthrough in-addr.arpa ip6.arpa\n    }\n    prometheus :9153\n    forward . 8.8.8.8 8.8.4.4\n    cache 30\n    loop\n    reload\n    loadbalance\n}\n"}}'
```

## Recovery Procedures

### Emergency Rollback

```bash
# Quick rollback
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod

# Rollback to specific version
kubectl rollout undo deployment/claude-deployment-api \
  --to-revision=5 -n claude-deployment-prod

# Monitor rollback
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod
```

### Service Restart Procedures

```bash
# Graceful restart
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod

# Force restart all pods
kubectl delete pods -l app=claude-deployment-api -n claude-deployment-prod

# Restart with zero downtime
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"'$(date +%Y-%m-%dT%H:%M:%S%z)'"}}}}}'
```

### Database Recovery

```bash
# Restore from backup
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier claude-deployment-restored \
  --db-snapshot-identifier <snapshot-id>

# Point-in-time recovery
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier claude-deployment-primary \
  --target-db-instance-identifier claude-deployment-recovered \
  --restore-time $(date -d '2 hours ago' -u +%Y-%m-%dT%H:%M:%S.000Z)
```

### Cache Recovery

```bash
# Clear Redis cache
kubectl run redis-cli --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL FLUSHALL

# Restart Redis cluster
kubectl rollout restart statefulset/redis -n claude-deployment-prod

# Warm up cache
curl -X POST https://api.claude-deployment.com/admin/cache/warmup
```

---

## Quick Reference

### Emergency Commands
```bash
# Scale up immediately
kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod

# Emergency rollback
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod

# Check system health
kubectl get nodes && kubectl get pods -n claude-deployment-prod

# Enable maintenance mode
kubectl apply -f k8s/maintenance-page.yaml
```

### Diagnostic Commands
```bash
# System overview
kubectl cluster-info && kubectl get nodes

# Application status
kubectl get pods,svc,ingress -n claude-deployment-prod

# Resource usage
kubectl top nodes && kubectl top pods -n claude-deployment-prod

# Recent events
kubectl get events -n claude-deployment-prod --sort-by='.lastTimestamp' | tail -10
```

### Contact Information
- **Primary On-Call**: +1-555-0123
- **Infrastructure Team**: +1-555-0128
- **Database Team**: +1-555-0127
- **Security Team**: security@company.com

### Important URLs
- **Status Page**: https://status.claude-deployment.com
- **Grafana**: https://grafana.claude-deployment.com
- **Production Health**: https://api.claude-deployment.com/health
- **AWS Console**: https://console.aws.amazon.com