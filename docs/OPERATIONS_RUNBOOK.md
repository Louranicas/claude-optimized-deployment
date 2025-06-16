# MCP Servers Operations Runbook

## Emergency Response Procedures

### 🚨 Critical System Down (P0)

**Symptoms**: All services unavailable, 5xx errors across all endpoints

**Immediate Actions** (0-5 minutes):
1. Check overall cluster health:
   ```bash
   kubectl get nodes
   kubectl get pods -n mcp-production
   kubectl get services -n mcp-production
   ```

2. Check load balancer/ingress:
   ```bash
   kubectl get ingress -n mcp-production
   curl -I https://api.mcp-production.com/health
   ```

3. If cluster is down, contact cloud provider or escalate to infrastructure team

**Investigation** (5-15 minutes):
1. Check recent deployments:
   ```bash
   kubectl rollout history deployment -n mcp-production
   ```

2. Check cluster events:
   ```bash
   kubectl get events -n mcp-production --sort-by='.lastTimestamp' | tail -20
   ```

3. Check resource utilization:
   ```bash
   kubectl top nodes
   kubectl top pods -n mcp-production
   ```

**Resolution**:
- If recent deployment caused issue: `kubectl rollout undo deployment/<deployment-name> -n mcp-production`
- If resource exhaustion: Scale up nodes or pods
- If infrastructure issue: Follow infrastructure team procedures

---

### 🔥 High Error Rate (P1)

**Symptoms**: Error rate >5% for >5 minutes

**Investigation**:
1. Check service logs:
   ```bash
   kubectl logs -l app=mcp-typescript-api -n mcp-production --tail=100
   kubectl logs -l app=mcp-learning-system -n mcp-production --tail=100
   kubectl logs -l app=mcp-rust-server -n mcp-production --tail=100
   ```

2. Check database connectivity:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- pg_isready -U mcp_user -d mcp_db
   ```

3. Check Redis connectivity:
   ```bash
   kubectl exec -it redis-0 -n mcp-production -- redis-cli ping
   ```

**Common Causes & Solutions**:
- Database connection pool exhausted: Restart application pods
- Memory leaks: Check memory usage and restart if needed
- External service outage: Check dependencies and implement circuit breaker
- Configuration issues: Validate ConfigMaps and Secrets

---

### ⚡ High Response Times (P2)

**Symptoms**: P95 response time >2 seconds

**Investigation**:
1. Check resource utilization:
   ```bash
   kubectl top pods -n mcp-production
   ```

2. Check HPA status:
   ```bash
   kubectl get hpa -n mcp-production
   ```

3. Check database performance:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"
   ```

**Resolution**:
1. Scale services horizontally:
   ```bash
   kubectl scale deployment mcp-typescript-api --replicas=5 -n mcp-production
   ```

2. Check for slow queries:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "SELECT query, query_start, state FROM pg_stat_activity WHERE state = 'active' AND query_start < NOW() - INTERVAL '30 seconds';"
   ```

---

## Deployment Procedures

### 🚀 Standard Deployment

**Pre-deployment Checklist**:
- [ ] All tests passing in CI/CD
- [ ] Security scans clean
- [ ] Performance benchmarks meeting SLAs
- [ ] Backup verification completed
- [ ] Rollback plan prepared

**Deployment Steps**:
1. Create deployment branch:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b deploy/v1.0.1
   ```

2. Update image tags in manifests:
   ```bash
   sed -i 's/mcp-typescript-server:v1.0.0/mcp-typescript-server:v1.0.1/g' k8s/mcp-deployment.yaml
   ```

3. Apply blue-green deployment:
   ```bash
   kubectl apply -f k8s/mcp-deployment.yaml
   kubectl set image deployment/mcp-typescript-api mcp-typescript-api=ghcr.io/your-org/mcp-typescript-server:v1.0.1 -n mcp-production
   ```

4. Monitor rollout:
   ```bash
   kubectl rollout status deployment/mcp-typescript-api -n mcp-production --timeout=600s
   ```

5. Verify health:
   ```bash
   curl -f https://api.mcp-production.com/health
   ```

6. Run smoke tests:
   ```bash
   python tests/production_smoke_tests.py
   ```

**Post-deployment**:
1. Monitor metrics for 30 minutes
2. Update deployment documentation
3. Notify team of successful deployment

### 🔄 Emergency Rollback

**When to rollback**:
- Error rate >10%
- Response time >5 seconds
- Critical functionality broken
- Security vulnerability discovered

**Rollback procedure**:
1. Immediate rollback:
   ```bash
   kubectl rollout undo deployment/mcp-typescript-api -n mcp-production
   kubectl rollout undo deployment/mcp-learning-system -n mcp-production
   kubectl rollout undo deployment/mcp-rust-server -n mcp-production
   ```

2. Verify rollback:
   ```bash
   kubectl rollout status deployment -n mcp-production
   ```

3. Test system health:
   ```bash
   curl -f https://api.mcp-production.com/health
   python tests/production_smoke_tests.py
   ```

4. Document incident and root cause

---

## Scaling Procedures

### 📈 Horizontal Scaling

**Auto-scaling Configuration**:
```bash
# Check current HPA status
kubectl get hpa -n mcp-production

# Modify scaling parameters if needed
kubectl patch hpa mcp-typescript-api-hpa -n mcp-production \
  --patch='{"spec":{"maxReplicas":20}}'
```

**Manual Scaling**:
```bash
# Scale API service
kubectl scale deployment mcp-typescript-api --replicas=10 -n mcp-production

# Scale ML service
kubectl scale deployment mcp-learning-system --replicas=5 -n mcp-production

# Scale Rust service
kubectl scale deployment mcp-rust-server --replicas=8 -n mcp-production
```

### 📊 Vertical Scaling

**Check VPA recommendations**:
```bash
kubectl get vpa -n mcp-production
kubectl describe vpa mcp-typescript-api-vpa -n mcp-production
```

**Apply resource adjustments**:
```bash
kubectl patch deployment mcp-typescript-api -n mcp-production \
  --patch='{"spec":{"template":{"spec":{"containers":[{"name":"mcp-typescript-api","resources":{"requests":{"cpu":"500m","memory":"1Gi"},"limits":{"cpu":"2000m","memory":"4Gi"}}}]}}}}'
```

### 🏗️ Infrastructure Scaling

**Add cluster nodes**:
```bash
# AWS EKS example
eksctl scale nodegroup --cluster=mcp-production --name=worker-nodes --nodes=5
```

**Check node capacity**:
```bash
kubectl describe nodes | grep -A 5 "Allocated resources"
```

---

## Maintenance Procedures

### 🔧 Database Maintenance

**Scheduled Maintenance Window**: Every Sunday 2:00-4:00 AM UTC

**Pre-maintenance**:
1. Notify users of maintenance window
2. Scale down non-essential services
3. Create database backup:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     pg_dump -U mcp_user -d mcp_db > /tmp/pre-maintenance-backup.sql
   ```

**Maintenance Tasks**:
1. Update database statistics:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "ANALYZE;"
   ```

2. Vacuum database:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "VACUUM;"
   ```

3. Check index usage:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "SELECT schemaname, tablename, attname, n_distinct, correlation FROM pg_stats WHERE schemaname = 'public';"
   ```

**Post-maintenance**:
1. Verify database health
2. Scale services back up
3. Run performance tests
4. Update maintenance log

### 🧹 Log Cleanup

**Automated cleanup** (runs daily):
```bash
# Clean old logs (older than 30 days)
kubectl exec -it logging-cleanup-job -n mcp-production -- \
  find /var/log -name "*.log" -mtime +30 -delete

# Compress recent logs
kubectl exec -it logging-cleanup-job -n mcp-production -- \
  find /var/log -name "*.log" -mtime +7 -exec gzip {} \;
```

**Manual cleanup**:
```bash
# Check log disk usage
kubectl exec -it mcp-typescript-api-xxx -n mcp-production -- df -h /app/logs

# Clean specific service logs
kubectl exec -it mcp-typescript-api-xxx -n mcp-production -- \
  truncate -s 0 /app/logs/application.log
```

### 🔐 Security Updates

**Monthly Security Review**:
1. Update container base images
2. Scan for vulnerabilities:
   ```bash
   trivy image ghcr.io/your-org/mcp-typescript-server:latest
   ```
3. Update dependencies
4. Review access logs
5. Rotate secrets

**Emergency Security Updates**:
1. Build new images with security patches
2. Update deployment manifests
3. Deploy using standard procedures
4. Verify security posture

---

## Monitoring and Alerting

### 📊 Dashboard Access

**Grafana Dashboards**:
- System Overview: `https://grafana.mcp-production.com/d/system-overview`
- Service Performance: `https://grafana.mcp-production.com/d/service-performance`
- Infrastructure: `https://grafana.mcp-production.com/d/infrastructure`

**Prometheus Queries**:
```promql
# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])

# P95 response time
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Memory usage
container_memory_usage_bytes / container_spec_memory_limit_bytes
```

### 🚨 Alert Management

**View active alerts**:
```bash
curl -s http://alertmanager.mcp-production.com/api/v1/alerts | jq '.data[].labels'
```

**Silence alerts** (for maintenance):
```bash
# Silence specific alert
curl -X POST http://alertmanager.mcp-production.com/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{"matchers":[{"name":"alertname","value":"HighErrorRate"}],"startsAt":"2025-01-08T02:00:00Z","endsAt":"2025-01-08T04:00:00Z","createdBy":"ops-team","comment":"Maintenance window"}'
```

**Alert Escalation**:
1. **Level 1** (0-15 min): On-call engineer
2. **Level 2** (15-30 min): Team lead + Infrastructure team
3. **Level 3** (30+ min): Engineering manager + Executive team

---

## Backup and Recovery

### 💾 Backup Procedures

**Daily Automated Backups**:
```bash
# Database backup
kubectl create job backup-$(date +%Y%m%d) -n mcp-production \
  --from=cronjob/postgres-backup

# Application data backup
kubectl create job app-backup-$(date +%Y%m%d) -n mcp-production \
  --from=cronjob/app-data-backup

# Configuration backup
kubectl get all,configmaps,secrets -n mcp-production -o yaml > backup-$(date +%Y%m%d)-config.yaml
```

**Verify Backups**:
```bash
# Check backup completion
kubectl get jobs -n mcp-production | grep backup

# Verify backup integrity
kubectl logs job/backup-$(date +%Y%m%d) -n mcp-production
```

### 🔄 Recovery Procedures

**Database Recovery**:
1. Stop application services:
   ```bash
   kubectl scale deployment --replicas=0 -n mcp-production --all
   ```

2. Restore database:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db < /backups/backup-20250108.sql
   ```

3. Verify data integrity:
   ```bash
   kubectl exec -it postgres-primary-0 -n mcp-production -- \
     psql -U mcp_user -d mcp_db -c "SELECT COUNT(*) FROM users;"
   ```

4. Restart services:
   ```bash
   kubectl scale deployment mcp-typescript-api --replicas=3 -n mcp-production
   kubectl scale deployment mcp-learning-system --replicas=2 -n mcp-production
   kubectl scale deployment mcp-rust-server --replicas=3 -n mcp-production
   ```

**Configuration Recovery**:
```bash
# Restore from backup
kubectl apply -f backup-20250108-config.yaml
```

---

## Performance Tuning

### 🎯 Performance Optimization

**Database Optimization**:
```sql
-- Check slow queries
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Update table statistics
ANALYZE users;
ANALYZE sessions;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch 
FROM pg_stat_user_indexes 
ORDER BY idx_scan DESC;
```

**Application Optimization**:
```bash
# Check garbage collection metrics
kubectl exec -it mcp-learning-system-xxx -n mcp-production -- \
  python -c "import gc; print(gc.get_stats())"

# Monitor memory usage
kubectl top pods -n mcp-production --containers

# Check connection pool status
kubectl logs -l app=mcp-typescript-api -n mcp-production | grep "pool"
```

**Resource Optimization**:
```bash
# Check resource utilization
kubectl top nodes
kubectl top pods -n mcp-production

# Adjust resource limits based on usage
kubectl patch deployment mcp-typescript-api -n mcp-production \
  --patch='{"spec":{"template":{"spec":{"containers":[{"name":"mcp-typescript-api","resources":{"limits":{"memory":"3Gi"}}}]}}}}'
```

### 🔍 Performance Troubleshooting

**High CPU Usage**:
1. Identify high CPU pods:
   ```bash
   kubectl top pods -n mcp-production --sort-by=cpu
   ```

2. Profile application (if profiling enabled):
   ```bash
   kubectl port-forward svc/mcp-typescript-api-service 3000:3000 -n mcp-production
   curl http://localhost:3000/debug/pprof/profile?seconds=30 > cpu.prof
   ```

3. Scale horizontally or vertically based on analysis

**High Memory Usage**:
1. Check memory usage patterns:
   ```bash
   kubectl top pods -n mcp-production --sort-by=memory
   ```

2. Check for memory leaks:
   ```bash
   kubectl logs -l app=mcp-learning-system -n mcp-production | grep -i "memory\|leak\|oom"
   ```

3. Restart pods if memory leak suspected:
   ```bash
   kubectl rollout restart deployment/mcp-learning-system -n mcp-production
   ```

---

## Security Procedures

### 🔐 Security Incident Response

**Suspected Security Breach**:
1. **Immediate containment** (0-5 minutes):
   ```bash
   # Isolate affected pods
   kubectl label pod suspicious-pod-xxx security.breach=true -n mcp-production
   kubectl delete pod suspicious-pod-xxx -n mcp-production
   ```

2. **Investigation** (5-30 minutes):
   ```bash
   # Check access logs
   kubectl logs -l app=mcp-typescript-api -n mcp-production | grep -i "unauthorized\|failed\|error"
   
   # Check unusual network activity
   kubectl get networkpolicies -n mcp-production
   ```

3. **Communication**:
   - Notify security team immediately
   - Document all actions taken
   - Prepare incident report

**Security Hardening Checklist**:
- [ ] All pods run as non-root
- [ ] Read-only root filesystems enabled
- [ ] Network policies implemented
- [ ] RBAC configured with minimal privileges
- [ ] Secrets properly encrypted
- [ ] Security context constraints applied

### 🔑 Secret Rotation

**Monthly Secret Rotation**:
1. Generate new secrets:
   ```bash
   # Generate new JWT secret
   openssl rand -base64 32

   # Generate new database password
   openssl rand -base64 24
   ```

2. Update secrets:
   ```bash
   kubectl patch secret mcp-secrets -n mcp-production \
     --patch='{"data":{"jwt-secret":"<new-jwt-secret-base64>"}}'
   ```

3. Rolling restart applications:
   ```bash
   kubectl rollout restart deployment -n mcp-production
   ```

4. Verify functionality:
   ```bash
   curl -f https://api.mcp-production.com/health
   ```

---

## Communication Procedures

### 📢 Incident Communication

**Internal Communication**:
1. **Slack**: Post in #mcp-production-alerts
2. **PagerDuty**: Trigger incident for P0/P1 issues
3. **Email**: Send to mcp-alerts@company.com for P2+ issues

**External Communication** (for customer-facing issues):
1. **Status Page**: Update status.company.com
2. **Customer Support**: Notify support team
3. **Social Media**: Coordinate with marketing team if needed

**Communication Templates**:

**Incident Detection**:
```
🚨 INCIDENT DETECTED
Service: MCP Production
Severity: P1
Impact: High error rate (15%) on API endpoints
Started: 2025-01-08 14:30 UTC
Investigating: @ops-team
```

**Incident Update**:
```
📊 INCIDENT UPDATE
Root cause identified: Database connection pool exhaustion
Actions: Scaling database connections, restarting API pods
ETA: 15 minutes
```

**Incident Resolution**:
```
✅ INCIDENT RESOLVED
Duration: 23 minutes
Resolution: Scaled database connections from 20 to 50
Post-mortem: Will be published in 24 hours
```

### 📋 Change Management

**Change Approval Process**:
1. **Low Risk** (config changes): Team lead approval
2. **Medium Risk** (minor releases): Engineering manager approval
3. **High Risk** (major releases): Architecture review + manager approval

**Change Documentation**:
```markdown
## Change Request CR-2025-001

**Type**: Deployment
**Risk Level**: Medium
**Scheduled**: 2025-01-08 15:00 UTC
**Duration**: 30 minutes
**Rollback Plan**: kubectl rollout undo
**Approver**: @engineering-manager
**Change Description**: Deploy v1.0.1 with performance improvements
```

---

## Contact Information

### 🆘 Emergency Contacts

**On-Call Rotation**:
- **Primary**: DevOps Engineer (+1-555-0001)
- **Secondary**: Platform Engineer (+1-555-0002)
- **Escalation**: Engineering Manager (+1-555-0003)

**Team Contacts**:
- **DevOps Team**: devops@company.com
- **Platform Team**: platform@company.com
- **Security Team**: security@company.com

### 📚 Documentation Links

- **Architecture**: `/docs/architecture/ARCHITECTURE.md`
- **API Docs**: `https://api.mcp-production.com/docs`
- **Monitoring**: `https://grafana.mcp-production.com`
- **Logs**: `https://kibana.mcp-production.com`
- **Incident Management**: `https://company.pagerduty.com`

### 🔧 Tool Access

**Required Tools**:
- kubectl configured for production cluster
- VPN access to internal networks
- AWS CLI with appropriate permissions
- Docker CLI for image management

**Access Request Process**:
1. Submit IT ticket for tool access
2. Manager approval required
3. Security team review
4. Access granted with audit trail

---

**Document Version**: v1.0.0  
**Last Updated**: 2025-01-08  
**Next Review**: 2025-02-08  
**Owner**: DevOps Team