# Production Operations Runbook

## Table of Contents

1. [System Overview](#system-overview)
2. [Emergency Response](#emergency-response)
3. [Incident Response Procedures](#incident-response-procedures)
4. [Common Issues and Solutions](#common-issues-and-solutions)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Deployment Procedures](#deployment-procedures)
7. [Database Operations](#database-operations)
8. [Performance Tuning](#performance-tuning)
9. [Security Procedures](#security-procedures)
10. [Disaster Recovery](#disaster-recovery)

## System Overview

### Architecture Components

- **EKS Cluster**: `claude-deployment-prod` in `us-west-2`
- **RDS Database**: PostgreSQL 15 Multi-AZ
- **ElastiCache**: Redis 7 with replication
- **Load Balancer**: Application Load Balancer with WAF
- **Monitoring**: Prometheus, Grafana, AlertManager
- **Logging**: ELK Stack with Fluent Bit

### Critical Services

| Service | Namespace | Replicas | Health Check |
|---------|-----------|----------|--------------|
| API Server | claude-deployment-prod | 6 | `/health` |
| Worker | claude-deployment-prod | 2 | Custom script |
| Database | External RDS | 1 (Multi-AZ) | PostgreSQL ping |
| Cache | External ElastiCache | 3 nodes | Redis ping |

### Key Metrics

- **SLA**: 99.9% uptime (8.76 hours downtime/year)
- **Response Time**: P95 < 500ms, P99 < 1s
- **Error Rate**: < 0.1%
- **Throughput**: 1000+ RPS sustained

## Emergency Response

### Severity Levels

#### SEV1 - Critical (Response: Immediate)
- Complete system outage
- Data loss or corruption
- Security breach
- Customer-facing functionality completely broken

#### SEV2 - High (Response: 30 minutes)
- Significant performance degradation
- Partial functionality broken
- High error rates (>5%)
- Database issues affecting functionality

#### SEV3 - Medium (Response: 2 hours)
- Minor performance issues
- Non-critical features broken
- Elevated error rates (1-5%)
- Monitoring/alerting issues

#### SEV4 - Low (Response: Next business day)
- Cosmetic issues
- Documentation needs
- Non-urgent feature requests

### Emergency Contacts

```
Primary On-Call: +1-555-0123 (Slack: @oncall-primary)
Secondary On-Call: +1-555-0124 (Slack: @oncall-secondary)
Manager: +1-555-0125 (Slack: @eng-manager)
Security Team: security@company.com
AWS Support: Case Portal or Premium Support phone
```

### War Room Procedures

1. **Incident Declaration**:
   ```bash
   # Create incident channel
   /incident declare "Brief description"
   
   # Join war room
   /join #incident-YYYY-MM-DD-HHMMSS
   ```

2. **Roles Assignment**:
   - **Incident Commander**: Coordinates response
   - **Technical Lead**: Diagnoses and fixes issues
   - **Communications Lead**: Updates stakeholders
   - **Scribe**: Documents timeline and actions

3. **Status Updates**:
   - Update every 15 minutes during SEV1
   - Update every 30 minutes during SEV2
   - Use status page: https://status.claude-deployment.com

## Incident Response Procedures

### Initial Response Checklist

```markdown
- [ ] Acknowledge alert within 5 minutes
- [ ] Assess severity level
- [ ] Create incident channel if SEV1/SEV2
- [ ] Notify stakeholders
- [ ] Begin investigation
- [ ] Document all actions
```

### Investigation Steps

1. **Check System Health**:
   ```bash
   # Check cluster status
   kubectl cluster-info
   kubectl get nodes
   kubectl get pods -n claude-deployment-prod
   
   # Check service status
   kubectl get svc -n claude-deployment-prod
   kubectl describe svc claude-deployment-api -n claude-deployment-prod
   ```

2. **Review Metrics**:
   - Grafana: https://grafana.claude-deployment.com
   - AWS CloudWatch: Console or CLI
   - Application logs: Kibana dashboard

3. **Check Recent Changes**:
   ```bash
   # Check recent deployments
   kubectl rollout history deployment/claude-deployment-api -n claude-deployment-prod
   
   # Check Git commits
   git log --oneline --since="1 hour ago"
   ```

### Common Investigation Commands

```bash
# Pod status and logs
kubectl get pods -n claude-deployment-prod -o wide
kubectl logs -f deployment/claude-deployment-api -n claude-deployment-prod
kubectl describe pod <pod-name> -n claude-deployment-prod

# Resource usage
kubectl top nodes
kubectl top pods -n claude-deployment-prod

# Database connectivity
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;"

# Redis connectivity
kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
  redis-cli -u $REDIS_URL ping

# Load balancer status
aws elbv2 describe-load-balancers --names claude-deployment-prod-alb
aws elbv2 describe-target-health --target-group-arn <target-group-arn>
```

## Common Issues and Solutions

### API Server Issues

#### High Response Times

**Symptoms**: P95 response time > 1s
**Investigation**:
```bash
# Check CPU/memory usage
kubectl top pods -n claude-deployment-prod

# Check database performance
# Access RDS Performance Insights
aws rds describe-db-instances --db-instance-identifier claude-deployment-primary

# Check slow queries
kubectl exec -it <api-pod> -n claude-deployment-prod -- \
  psql $DATABASE_URL -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

**Solutions**:
1. Scale up pods: `kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod`
2. Check for database locks
3. Review recent code changes
4. Enable connection pooling
5. Add database read replicas

#### High Error Rate

**Symptoms**: Error rate > 1%
**Investigation**:
```bash
# Check application logs
kubectl logs -f deployment/claude-deployment-api -n claude-deployment-prod | grep ERROR

# Check Prometheus metrics
curl -s 'http://prometheus:9090/api/v1/query?query=claude_deployment:api_error_rate_5m'

# Check external dependencies
curl -I https://api.openai.com/v1/models
```

**Solutions**:
1. Check external API status
2. Review error logs for patterns
3. Implement circuit breakers
4. Add retry logic
5. Rollback if recent deployment

### Database Issues

#### High Connection Count

**Symptoms**: Connection alerts, timeouts
**Investigation**:
```bash
# Check current connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Check connection sources
psql $DATABASE_URL -c "SELECT client_addr, count(*) FROM pg_stat_activity GROUP BY client_addr;"
```

**Solutions**:
1. Increase connection pool limits
2. Kill idle connections
3. Scale down unnecessary services
4. Add read replicas for read-only queries

#### Slow Queries

**Symptoms**: High database CPU, slow response times
**Investigation**:
```bash
# Find slow queries
psql $DATABASE_URL -c "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"

# Check for locks
psql $DATABASE_URL -c "SELECT * FROM pg_locks JOIN pg_stat_activity ON pg_locks.pid = pg_stat_activity.pid;"
```

**Solutions**:
1. Add missing indexes
2. Optimize query plans
3. Kill long-running queries
4. Increase database resources

### Infrastructure Issues

#### Node Issues

**Symptoms**: Pods not scheduling, node not ready
**Investigation**:
```bash
# Check node status
kubectl get nodes
kubectl describe node <node-name>

# Check node resources
kubectl top nodes
kubectl describe node <node-name> | grep -A 10 "Allocated resources"
```

**Solutions**:
1. Drain and replace node: `kubectl drain <node-name> --ignore-daemonsets`
2. Scale cluster: Update ASG desired capacity
3. Check disk space: SSH to node and check `/`
4. Restart kubelet: `sudo systemctl restart kubelet`

#### Network Issues

**Symptoms**: Connectivity problems, DNS failures
**Investigation**:
```bash
# Test DNS resolution
kubectl run dns-test --image=busybox --rm -i --restart=Never -- nslookup kubernetes.default.svc.cluster.local

# Check network policies
kubectl get networkpolicies -n claude-deployment-prod

# Test pod-to-pod connectivity
kubectl run test-pod --image=alpine --rm -i --restart=Never -- ping <target-pod-ip>
```

**Solutions**:
1. Restart CoreDNS: `kubectl rollout restart deployment/coredns -n kube-system`
2. Check security groups and NACLs
3. Review network policies
4. Check CNI plugin status

## Monitoring and Alerting

### Key Dashboards

1. **System Overview**: https://grafana.claude-deployment.com/d/system-overview
2. **API Performance**: https://grafana.claude-deployment.com/d/api-performance
3. **Database Metrics**: https://grafana.claude-deployment.com/d/database-metrics
4. **Infrastructure**: https://grafana.claude-deployment.com/d/infrastructure

### Alert Response

#### APIDown Alert
```bash
# Check pod status
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api

# Check service endpoints
kubectl get endpoints claude-deployment-api -n claude-deployment-prod

# Check load balancer health
aws elbv2 describe-target-health --target-group-arn <arn>
```

#### HighErrorRate Alert
```bash
# Check recent deployments
kubectl rollout history deployment/claude-deployment-api -n claude-deployment-prod

# Review error patterns
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | grep ERROR | head -20

# Consider rollback
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod
```

#### HighMemoryUsage Alert
```bash
# Check memory usage by pod
kubectl top pods -n claude-deployment-prod --sort-by=memory

# Scale up if needed
kubectl scale deployment claude-deployment-api --replicas=8 -n claude-deployment-prod

# Check for memory leaks
kubectl exec -it <pod-name> -n claude-deployment-prod -- /app/memory-profile.sh
```

## Deployment Procedures

### Emergency Rollback

```bash
# Quick rollback to previous version
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod

# Rollback to specific revision
kubectl rollout undo deployment/claude-deployment-api --to-revision=<revision> -n claude-deployment-prod

# Check rollback status
kubectl rollout status deployment/claude-deployment-api -n claude-deployment-prod
```

### Feature Flag Emergency Disable

```bash
# Disable feature flag
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"feature-flag-name":"false"}}'

# Restart pods to pick up config changes
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

### Traffic Diversion

```bash
# Reduce traffic to problematic pods (if using Istio)
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: claude-api-traffic
  namespace: claude-deployment-prod
spec:
  http:
  - match:
    - uri:
        prefix: "/"
    fault:
      abort:
        percentage:
          value: 50.0
        httpStatus: 503
  - route:
    - destination:
        host: claude-deployment-api
EOF
```

## Database Operations

### Backup and Restore

```bash
# Create manual backup
aws rds create-db-snapshot \
  --db-instance-identifier claude-deployment-primary \
  --db-snapshot-identifier manual-snapshot-$(date +%Y%m%d-%H%M%S)

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier claude-deployment-restored \
  --db-snapshot-identifier <snapshot-id>
```

### Database Maintenance

```bash
# Check database size
psql $DATABASE_URL -c "SELECT pg_size_pretty(pg_database_size('claude_deployment'));"

# Vacuum and analyze
psql $DATABASE_URL -c "VACUUM ANALYZE;"

# Reindex
psql $DATABASE_URL -c "REINDEX DATABASE claude_deployment;"

# Check for bloat
psql $DATABASE_URL -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size FROM pg_tables ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"
```

### Connection Management

```bash
# Kill specific connection
psql $DATABASE_URL -c "SELECT pg_terminate_backend(<pid>);"

# Kill all idle connections
psql $DATABASE_URL -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND state_change < current_timestamp - INTERVAL '5 minutes';"
```

## Performance Tuning

### Horizontal Pod Autoscaling

```bash
# Check HPA status
kubectl get hpa -n claude-deployment-prod

# Update HPA settings
kubectl patch hpa claude-deployment-api-hpa -n claude-deployment-prod \
  -p '{"spec":{"maxReplicas":20,"targetCPUUtilizationPercentage":60}}'
```

### Vertical Pod Autoscaling

```bash
# Check VPA recommendations
kubectl describe vpa claude-deployment-api-vpa -n claude-deployment-prod

# Apply VPA recommendations manually
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"requests":{"memory":"4Gi","cpu":"1000m"},"limits":{"memory":"8Gi","cpu":"2000m"}}}]}}}}'
```

### Database Performance

```bash
# Update connection pool settings
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"db-pool-max":"100","db-pool-min":"20"}}'

# Add read replica endpoint
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"read-db-url":"postgresql://user:pass@read-replica-endpoint:5432/db"}}'
```

## Security Procedures

### Security Incident Response

1. **Immediate Actions**:
   ```bash
   # Isolate affected pods
   kubectl label pod <pod-name> security=quarantine -n claude-deployment-prod
   
   # Block malicious IPs (if using AWS WAF)
   aws wafv2 create-ip-set --name malicious-ips --scope REGIONAL \
     --addresses <malicious-ip>/32
   ```

2. **Investigation**:
   ```bash
   # Check access logs
   aws logs filter-log-events --log-group-name /aws/eks/claude-deployment-prod/cluster \
     --start-time $(date -d '1 hour ago' +%s)000
   
   # Review authentication logs
   kubectl logs -n kube-system -l k8s-app=aws-iam-authenticator
   ```

### Certificate Management

```bash
# Check certificate expiration
kubectl get certificates -n claude-deployment-prod
kubectl describe certificate claude-deployment-tls -n claude-deployment-prod

# Renew certificate manually
kubectl delete certificate claude-deployment-tls -n claude-deployment-prod
kubectl apply -f k8s/production/certificates.yaml
```

### Secret Rotation

```bash
# Rotate database password
aws secretsmanager update-secret --secret-id claude-deployment/database \
  --secret-string '{"password":"new-password"}'

# Update Kubernetes secret
kubectl create secret generic claude-deployment-db-secret \
  --from-literal=database-url="postgresql://user:new-password@host:5432/db" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods to pick up new secret
kubectl rollout restart deployment/claude-deployment-api -n claude-deployment-prod
```

## Disaster Recovery

### Multi-Region Failover

1. **Activate Secondary Region**:
   ```bash
   # Switch DNS to secondary region
   aws route53 change-resource-record-sets --hosted-zone-id <zone-id> \
     --change-batch file://failover-changeset.json
   
   # Scale up secondary region
   aws eks update-nodegroup-config --cluster-name claude-deployment-dr \
     --nodegroup-name primary --scaling-config minSize=3,maxSize=20,desiredSize=6
   ```

2. **Database Failover**:
   ```bash
   # Promote read replica
   aws rds promote-read-replica --db-instance-identifier claude-deployment-replica
   
   # Update connection strings
   kubectl patch secret claude-deployment-db-secret -n claude-deployment-prod \
     -p '{"data":{"database-url":"<new-base64-encoded-url>"}}'
   ```

### Data Recovery

```bash
# Restore from point-in-time backup
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier claude-deployment-primary \
  --target-db-instance-identifier claude-deployment-recovered \
  --restore-time $(date -d '2 hours ago' -u +%Y-%m-%dT%H:%M:%S.000Z)

# Restore Redis from backup
aws elasticache create-replication-group \
  --replication-group-id claude-deployment-restored \
  --snapshot-name claude-deployment-backup-$(date +%Y%m%d)
```

### Communication Templates

#### Incident Start
```
🚨 INCIDENT DECLARED - SEV{X}

Summary: Brief description of the issue
Impact: Customer-facing impact description
Status: INVESTIGATING
ETA: Investigating, updates every 15 minutes

Incident Channel: #incident-YYYY-MM-DD-HHMMSS
Incident Commander: @username
```

#### Status Update
```
📊 INCIDENT UPDATE - SEV{X}

Summary: Current status and progress
Actions Taken: List of actions performed
Next Steps: What we're doing next
ETA: Updated timeline

Last Updated: HH:MM UTC
Next Update: HH:MM UTC
```

#### Resolution
```
✅ INCIDENT RESOLVED - SEV{X}

Summary: Final resolution description
Root Cause: Brief explanation
Duration: Total incident duration
Impact: Final impact assessment

Follow-up: Post-mortem scheduled for DATE
```

---

## Quick Reference

### Emergency Commands

```bash
# Scale up immediately
kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod

# Emergency rollback
kubectl rollout undo deployment/claude-deployment-api -n claude-deployment-prod

# Check cluster health
kubectl get nodes && kubectl get pods -n claude-deployment-prod

# Emergency maintenance page
kubectl apply -f maintenance-page.yaml

# Circuit breaker activation
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"circuit-breaker-enabled":"true"}}'
```

### Contact Information

- **Primary On-Call**: +1-555-0123
- **Incident Slack**: #incidents
- **Status Page**: https://status.claude-deployment.com
- **Grafana**: https://grafana.claude-deployment.com
- **AWS Console**: https://console.aws.amazon.com

### Important URLs

- **Production API**: https://api.claude-deployment.com
- **Health Check**: https://api.claude-deployment.com/health
- **Metrics**: https://api.claude-deployment.com/metrics
- **Admin Panel**: https://admin.claude-deployment.com