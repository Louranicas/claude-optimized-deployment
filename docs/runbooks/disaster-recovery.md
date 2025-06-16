# Disaster Recovery Runbook

## Table of Contents

1. [Overview](#overview)
2. [Disaster Scenarios](#disaster-scenarios)
3. [Recovery Procedures](#recovery-procedures)
4. [Data Recovery](#data-recovery)
5. [Testing and Validation](#testing-and-validation)
6. [Communication Plans](#communication-plans)

## Overview

### Recovery Objectives

- **Recovery Time Objective (RTO)**: 2 hours
- **Recovery Point Objective (RPO)**: 15 minutes
- **Maximum Tolerable Downtime (MTD)**: 4 hours

### Architecture Overview

```
Primary Region (us-west-2)     Secondary Region (us-east-1)
├── EKS Cluster                ├── EKS Cluster (Standby)
├── RDS Multi-AZ               ├── RDS Read Replica
├── ElastiCache                ├── ElastiCache (Standby)
├── S3 (Cross-Region Replica)  ├── S3 (Replica)
└── CloudFront (Global)        └── Route 53 Health Checks
```

### Key Components

| Component | Primary | Secondary | Backup Method |
|-----------|---------|-----------|---------------|
| EKS Cluster | us-west-2 | us-east-1 | Infrastructure as Code |
| RDS Database | Multi-AZ | Cross-Region Read Replica | Automated Snapshots + PITR |
| Redis Cache | us-west-2 | us-east-1 | Scheduled Snapshots |
| Object Storage | S3 us-west-2 | S3 us-east-1 | Cross-Region Replication |
| Container Images | ECR us-west-2 | ECR us-east-1 | Cross-Region Replication |
| DNS | Route 53 | Health Check Failover | Automatic Failover |

## Disaster Scenarios

### Scenario 1: Complete Region Failure

**Triggers**:
- AWS region unavailability
- Multiple AZ failures
- Network partitioning

**Impact**:
- Complete service unavailability
- Database inaccessible
- All application instances down

**Recovery Strategy**: Multi-region failover

### Scenario 2: Database Corruption/Loss

**Triggers**:
- Hardware failure
- Software bugs
- Human error
- Security incident

**Impact**:
- Data integrity issues
- Application errors
- Potential data loss

**Recovery Strategy**: Point-in-time recovery

### Scenario 3: Application-Level Failure

**Triggers**:
- Bad deployment
- Code bugs
- Configuration errors
- Security vulnerabilities

**Impact**:
- Service degradation
- Functional issues
- User experience problems

**Recovery Strategy**: Rollback and restore

### Scenario 4: Infrastructure Compromise

**Triggers**:
- Security breach
- Unauthorized access
- Malware/ransomware
- Credential compromise

**Impact**:
- Data confidentiality breach
- System integrity loss
- Service availability impact

**Recovery Strategy**: Isolation and rebuild

## Recovery Procedures

### Multi-Region Failover

#### Prerequisites Verification

```bash
#!/bin/bash

# Check secondary region readiness
export AWS_DEFAULT_REGION=us-east-1

# Verify EKS cluster status
aws eks describe-cluster --name claude-deployment-dr --query 'cluster.status'

# Check RDS read replica status
aws rds describe-db-instances --db-instance-identifier claude-deployment-replica \
  --query 'DBInstances[0].DBInstanceStatus'

# Verify ECR images availability
aws ecr describe-images --repository-name claude-deployment \
  --query 'imageDetails[0].imageTags'

# Check S3 replication status
aws s3api get-bucket-replication --bucket claude-deployment-dr-backup
```

#### Step 1: Declare Disaster

```bash
# Create incident channel
slack_notify "🚨 DISASTER DECLARED - Region Failover Initiated"

# Update status page
curl -X POST https://api.statuspage.io/v1/pages/${PAGE_ID}/incidents \
  -H "Authorization: OAuth ${STATUS_PAGE_TOKEN}" \
  -d '{
    "incident": {
      "name": "Region Failover in Progress",
      "status": "investigating",
      "impact_override": "major_outage",
      "component_ids": ["${COMPONENT_ID}"]
    }
  }'
```

#### Step 2: Promote Database

```bash
# Promote read replica to primary
aws rds promote-read-replica \
  --db-instance-identifier claude-deployment-replica \
  --backup-retention-period 7

# Wait for promotion to complete
aws rds wait db-instance-available \
  --db-instance-identifiers claude-deployment-replica

# Get new endpoint
NEW_DB_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier claude-deployment-replica \
  --query 'DBInstances[0].Endpoint.Address' --output text)

echo "New database endpoint: $NEW_DB_ENDPOINT"
```

#### Step 3: Update DNS Failover

```bash
# Create Route 53 change batch
cat > failover-changeset.json << EOF
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.claude-deployment.com",
        "Type": "CNAME",
        "SetIdentifier": "Primary",
        "Failover": "PRIMARY",
        "TTL": 60,
        "ResourceRecords": [
          {
            "Value": "claude-deployment-dr-alb.us-east-1.elb.amazonaws.com"
          }
        ]
      }
    }
  ]
}
EOF

# Apply DNS changes
aws route53 change-resource-record-sets \
  --hosted-zone-id ${HOSTED_ZONE_ID} \
  --change-batch file://failover-changeset.json
```

#### Step 4: Scale Up Secondary Region

```bash
# Switch to secondary region
export AWS_DEFAULT_REGION=us-east-1
aws eks update-kubeconfig --name claude-deployment-dr

# Update database connection in secrets
kubectl create secret generic claude-deployment-db-secret \
  --from-literal=database-url="postgresql://user:${DB_PASSWORD}@${NEW_DB_ENDPOINT}:5432/claude_deployment" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Scale up application
kubectl scale deployment claude-deployment-api \
  --replicas=6 --namespace=claude-deployment-prod

# Wait for pods to be ready
kubectl wait --for=condition=ready pod \
  -l app=claude-deployment-api \
  --namespace=claude-deployment-prod \
  --timeout=600s

# Scale up worker nodes if needed
aws eks update-nodegroup-config \
  --cluster-name claude-deployment-dr \
  --nodegroup-name primary \
  --scaling-config minSize=3,maxSize=20,desiredSize=6
```

#### Step 5: Verify Service Health

```bash
# Health check
curl -f https://api.claude-deployment.com/health

# Run smoke tests
cd /opt/claude-deployment
./scripts/smoke-tests.sh

# Check metrics
curl -s https://api.claude-deployment.com/metrics | grep -E "(http_requests_total|response_time)"

# Verify database connectivity
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql postgresql://user:${DB_PASSWORD}@${NEW_DB_ENDPOINT}:5432/claude_deployment -c "SELECT 1;"
```

#### Step 6: Communication and Monitoring

```bash
# Update status page
curl -X PATCH https://api.statuspage.io/v1/pages/${PAGE_ID}/incidents/${INCIDENT_ID} \
  -H "Authorization: OAuth ${STATUS_PAGE_TOKEN}" \
  -d '{
    "incident": {
      "status": "monitoring",
      "body": "Services have been restored via secondary region. Monitoring stability."
    }
  }'

# Notify team
slack_notify "✅ Failover Complete - Services restored in us-east-1"

# Set up enhanced monitoring
kubectl apply -f monitoring/disaster-recovery/
```

### Database Point-in-Time Recovery

#### Step 1: Assess Damage

```bash
# Connect to database and assess corruption
psql $DATABASE_URL << EOF
-- Check for table corruption
SELECT schemaname, tablename, 
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check for data inconsistencies
SELECT COUNT(*) FROM users WHERE created_at > updated_at;
SELECT COUNT(*) FROM orders WHERE total_amount < 0;

-- Check for missing critical data
SELECT COUNT(*) FROM users WHERE email IS NULL;
EOF
```

#### Step 2: Determine Recovery Point

```bash
# List available backups
aws rds describe-db-snapshots \
  --db-instance-identifier claude-deployment-primary \
  --snapshot-type automated \
  --query 'DBSnapshots[*].[DBSnapshotIdentifier,SnapshotCreateTime]' \
  --output table

# Determine the last known good point
RECOVERY_TIME="2024-01-15T14:30:00.000Z"  # Adjust based on investigation
echo "Recovery point determined: $RECOVERY_TIME"
```

#### Step 3: Create Recovery Instance

```bash
# Restore database to point in time
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier claude-deployment-primary \
  --target-db-instance-identifier claude-deployment-recovery \
  --restore-time $RECOVERY_TIME \
  --db-instance-class db.r6g.xlarge \
  --multi-az \
  --publicly-accessible false \
  --vpc-security-group-ids $DB_SECURITY_GROUP_ID \
  --db-subnet-group-name $DB_SUBNET_GROUP

# Wait for restore to complete
aws rds wait db-instance-available \
  --db-instance-identifiers claude-deployment-recovery

# Get recovery endpoint
RECOVERY_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier claude-deployment-recovery \
  --query 'DBInstances[0].Endpoint.Address' --output text)
```

#### Step 4: Validate Recovered Data

```bash
# Connect to recovered database
RECOVERY_URL="postgresql://user:${DB_PASSWORD}@${RECOVERY_ENDPOINT}:5432/claude_deployment"

# Validate data integrity
psql $RECOVERY_URL << EOF
-- Check record counts
SELECT 'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'orders' as table_name, COUNT(*) as count FROM orders
UNION ALL
SELECT 'products' as table_name, COUNT(*) as count FROM products;

-- Check recent data
SELECT COUNT(*) FROM orders WHERE created_at >= '$RECOVERY_TIME'::timestamp - interval '1 hour';

-- Verify critical data
SELECT COUNT(*) FROM users WHERE email IS NOT NULL AND email != '';
EOF
```

#### Step 5: Switch to Recovered Database

```bash
# Update application configuration
kubectl patch configmap claude-deployment-config \
  --namespace=claude-deployment-prod \
  --patch='{"data":{"database-url":"'$RECOVERY_URL'"}}'

# Update secret
kubectl create secret generic claude-deployment-db-secret \
  --from-literal=database-url="$RECOVERY_URL" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart application pods
kubectl rollout restart deployment/claude-deployment-api \
  --namespace=claude-deployment-prod

# Wait for rollout to complete
kubectl rollout status deployment/claude-deployment-api \
  --namespace=claude-deployment-prod --timeout=600s
```

### Application Rollback and Recovery

#### Immediate Rollback

```bash
# Check rollout history
kubectl rollout history deployment/claude-deployment-api \
  --namespace=claude-deployment-prod

# Rollback to previous version
kubectl rollout undo deployment/claude-deployment-api \
  --namespace=claude-deployment-prod

# Rollback to specific revision
kubectl rollout undo deployment/claude-deployment-api \
  --to-revision=5 \
  --namespace=claude-deployment-prod

# Monitor rollback
kubectl rollout status deployment/claude-deployment-api \
  --namespace=claude-deployment-prod --timeout=300s
```

#### Configuration Recovery

```bash
# Backup current configuration
kubectl get configmap claude-deployment-config \
  --namespace=claude-deployment-prod \
  -o yaml > config-backup-$(date +%Y%m%d-%H%M%S).yaml

# Restore from git
git checkout HEAD~1 -- k8s/production/configmaps.yaml
kubectl apply -f k8s/production/configmaps.yaml

# Restart pods to pick up changes
kubectl rollout restart deployment/claude-deployment-api \
  --namespace=claude-deployment-prod
```

### Infrastructure Rebuild

#### Step 1: Isolate Compromised Infrastructure

```bash
# Isolate affected nodes
kubectl cordon <compromised-node>
kubectl drain <compromised-node> --ignore-daemonsets --delete-emptydir-data

# Update security groups to block traffic
aws ec2 authorize-security-group-ingress \
  --group-id $SECURITY_GROUP_ID \
  --protocol tcp \
  --port 22 \
  --source-group $ADMIN_SECURITY_GROUP

# Terminate compromised instances
aws ec2 terminate-instances --instance-ids <compromised-instance-id>
```

#### Step 2: Deploy Clean Infrastructure

```bash
# Deploy to clean region/environment
cd infrastructure/terraform
terraform workspace select disaster-recovery

# Update variable files for DR environment
terraform plan -var-file="disaster-recovery.tfvars"
terraform apply -auto-approve

# Deploy application to clean infrastructure
export KUBECONFIG=~/.kube/config-dr
./scripts/deploy-production.sh rolling latest
```

#### Step 3: Data Migration

```bash
# Restore data from clean backups
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier claude-deployment-clean \
  --db-snapshot-identifier <trusted-snapshot-id>

# Migrate object storage
aws s3 sync s3://claude-deployment-backup s3://claude-deployment-clean \
  --exclude "*/temp/*" \
  --exclude "*/cache/*"

# Restore secrets from backup
kubectl apply -f secrets-backup/
```

## Data Recovery

### File System Recovery

```bash
# Mount EBS snapshot to recovery instance
aws ec2 create-volume --snapshot-id <snapshot-id> \
  --availability-zone us-west-2a \
  --volume-type gp3

aws ec2 attach-volume --volume-id <volume-id> \
  --instance-id <recovery-instance-id> \
  --device /dev/sdf

# Mount and extract data
sudo mkdir -p /mnt/recovery
sudo mount /dev/xvdf1 /mnt/recovery

# Copy critical files
sudo cp -r /mnt/recovery/app/logs/* /recovery/logs/
sudo cp -r /mnt/recovery/app/data/* /recovery/data/
```

### Object Storage Recovery

```bash
# List available versions (if versioning enabled)
aws s3api list-object-versions --bucket claude-deployment-prod

# Restore specific version
aws s3api get-object \
  --bucket claude-deployment-prod \
  --key important-file.json \
  --version-id <version-id> \
  important-file-restored.json

# Bulk restore from cross-region replica
aws s3 sync s3://claude-deployment-backup s3://claude-deployment-prod \
  --delete \
  --exclude "*/cache/*"
```

### Database Specific Recovery

#### Table-Level Recovery

```bash
# Export specific table from backup database
pg_dump -h $BACKUP_DB_HOST -U $DB_USER -d claude_deployment \
  -t users \
  --data-only > users_data.sql

# Import to production database
psql $DATABASE_URL < users_data.sql
```

#### Transaction Log Recovery

```bash
# Apply WAL files for precise recovery
# (This requires setting up WAL-E or similar backup solution)
wal-e backup-fetch /var/lib/postgresql/base_backup LATEST
wal-e wal-fetch 000000010000000000000001 /var/lib/postgresql/pg_wal/
```

## Testing and Validation

### Disaster Recovery Testing Schedule

| Test Type | Frequency | Scope | Duration |
|-----------|-----------|-------|----------|
| Backup Verification | Daily | Automated | 30 minutes |
| Database Recovery | Weekly | Staging | 2 hours |
| Region Failover | Monthly | Staging | 4 hours |
| Full DR Exercise | Quarterly | Production-like | 8 hours |

### Automated Testing

```bash
#!/bin/bash
# automated-dr-test.sh

# Test 1: Backup integrity
echo "Testing backup integrity..."
aws rds create-db-snapshot \
  --db-instance-identifier claude-deployment-primary \
  --db-snapshot-identifier test-snapshot-$(date +%Y%m%d-%H%M%S)

# Test 2: Cross-region replication lag
echo "Checking replication lag..."
REPLICATION_LAG=$(aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name ReplicaLag \
  --dimensions Name=DBInstanceIdentifier,Value=claude-deployment-replica \
  --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --query 'Datapoints[0].Average')

if (( $(echo "$REPLICATION_LAG > 300" | bc -l) )); then
  echo "⚠️ High replication lag: ${REPLICATION_LAG}s"
  exit 1
fi

# Test 3: Health check endpoints
echo "Testing health endpoints..."
curl -f https://api.claude-deployment.com/health || exit 1

# Test 4: DNS failover simulation
echo "Testing DNS failover..."
# This would involve testing Route 53 health checks

echo "✅ All DR tests passed"
```

### Manual Testing Checklist

```markdown
## Pre-Test Checklist
- [ ] Backup all critical data
- [ ] Notify stakeholders about testing window
- [ ] Prepare rollback procedures
- [ ] Set up monitoring for test environment

## During Test
- [ ] Document all steps and timings
- [ ] Test all critical functionalities
- [ ] Validate data integrity
- [ ] Check monitoring and alerting
- [ ] Test communication procedures

## Post-Test
- [ ] Compare actual vs target RTOs/RPOs
- [ ] Document lessons learned
- [ ] Update procedures based on findings
- [ ] Schedule remediation for any issues found
```

## Communication Plans

### Stakeholder Notification Matrix

| Stakeholder | Notification Method | Timeline |
|-------------|-------------------|----------|
| Engineering Team | Slack, Email | Immediate |
| Management | Email, Phone | 15 minutes |
| Customer Support | Slack, Phone | 15 minutes |
| Customers | Status Page, Email | 30 minutes |
| Partners | Email | 1 hour |
| Legal/Compliance | Email | 2 hours |

### Communication Templates

#### Initial Disaster Declaration

```
Subject: [URGENT] Disaster Recovery Activated - Claude Deployment

We have activated our disaster recovery procedures due to [brief description].

Current Status: DR procedures in progress
Estimated Recovery Time: [X] hours
Customer Impact: [description]
Next Update: [time]

Incident Channel: #disaster-recovery-YYYYMMDD
Incident Commander: [name]
```

#### Progress Updates

```
Subject: [UPDATE] Disaster Recovery Progress - Hour [X]

Progress Update:
✅ Completed: [list of completed steps]
🔄 In Progress: [current actions]
⏳ Next Steps: [upcoming actions]

Current ETA: [updated estimate]
Next Update: [time]
```

#### Recovery Completion

```
Subject: [RESOLVED] Services Restored - Post-Recovery Monitoring

All services have been successfully restored.

Final Status:
- Total Downtime: [duration]
- Services Affected: [list]
- Data Loss: [none/minimal/description]
- Root Cause: [brief explanation]

Post-Mortem: Scheduled for [date/time]
```

---

## Contact Information

### Emergency Contacts

- **Disaster Recovery Lead**: +1-555-0126
- **Database Administrator**: +1-555-0127
- **Infrastructure Lead**: +1-555-0128
- **Security Team**: +1-555-0129
- **Executive Sponsor**: +1-555-0130

### External Contacts

- **AWS Enterprise Support**: 1-800-xxx-xxxx
- **DNS Provider Support**: support@dnsprovider.com
- **CDN Provider Support**: support@cdnprovider.com

### Important Resources

- **Status Page**: https://status.claude-deployment.com
- **DR Documentation**: https://docs.claude-deployment.com/dr
- **Incident Response**: https://docs.claude-deployment.com/incidents
- **AWS Console**: https://console.aws.amazon.com