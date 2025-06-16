# Security Incident Response Plan

## Table of Contents

1. [Overview](#overview)
2. [Incident Classification](#incident-classification)
3. [Response Team Structure](#response-team-structure)
4. [Detection and Initial Response](#detection-and-initial-response)
5. [Containment Procedures](#containment-procedures)
6. [Investigation and Analysis](#investigation-and-analysis)
7. [Eradication and Recovery](#eradication-and-recovery)
8. [Communication and Reporting](#communication-and-reporting)
9. [Specific Incident Types](#specific-incident-types)
10. [Post-Incident Activities](#post-incident-activities)

## Overview

This runbook defines the comprehensive security incident response procedures for the CODE project. It ensures rapid detection, containment, and remediation of security threats while maintaining evidence integrity and meeting compliance requirements.

### Security Objectives

- **Rapid Response**: Minimize time to detection and containment
- **Evidence Preservation**: Maintain forensic evidence for investigation
- **Business Continuity**: Minimize impact on operations
- **Regulatory Compliance**: Meet all legal and regulatory requirements
- **Continuous Improvement**: Learn from incidents to strengthen security

### Incident Response Phases

```
Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned
```

## Incident Classification

### Severity Levels

#### SEV1 - Critical Security Incident
**Response Time**: Immediate (within 15 minutes)
**Escalation**: Immediate to CISO and executive team

**Criteria**:
- Active data breach with confirmed data exfiltration
- Ransomware or malware affecting production systems
- Privileged account compromise (admin, service accounts)
- Critical infrastructure compromise
- Public disclosure of sensitive data

**Examples**:
- Customer database accessed by unauthorized parties
- Production systems encrypted by ransomware
- Admin credentials compromised and used maliciously
- Customer PII exposed publicly

#### SEV2 - High Security Incident
**Response Time**: 30 minutes
**Escalation**: Security team lead and management within 1 hour

**Criteria**:
- Suspected data breach under investigation
- Non-privileged account compromise
- Malware detection on non-critical systems
- Significant security control failure
- Attempted unauthorized access to sensitive systems

**Examples**:
- Suspicious database queries detected
- User account showing signs of compromise
- Malware detected in development environment
- Failed authentication attempts exceeding thresholds

#### SEV3 - Medium Security Incident
**Response Time**: 4 hours
**Escalation**: Security team handles with regular reporting

**Criteria**:
- Minor security policy violations
- Low-impact security tool alerts
- Suspicious activity requiring investigation
- Minor configuration security issues

**Examples**:
- Employee accessing unauthorized resources
- Misconfigured security settings
- Suspicious network traffic patterns
- Minor compliance violations

#### SEV4 - Low Security Incident
**Response Time**: Next business day
**Escalation**: Security team triage

**Criteria**:
- Security awareness violations
- Minor policy infractions
- Low-risk vulnerability discoveries
- Security training requirements

## Response Team Structure

### Core Security Response Team

#### Incident Commander (Security)
**Responsibilities**:
- Overall incident coordination and decision-making
- Communication with executive leadership
- Resource allocation and prioritization
- Legal and regulatory compliance oversight

**Selection Criteria**:
- Senior security professional or CISO
- Authority to make business-critical decisions
- Experience with incident management
- Available for incident duration

#### Security Analyst
**Responsibilities**:
- Technical investigation and analysis
- Evidence collection and preservation
- Threat hunting and IOC development
- Security tool operation and monitoring

#### IT Operations Lead
**Responsibilities**:
- System isolation and containment
- Infrastructure changes and modifications
- Service restoration and recovery
- Technical remediation implementation

#### Legal Counsel
**Responsibilities**:
- Legal compliance and regulatory requirements
- Law enforcement coordination
- Customer and partner notifications
- Documentation review and approval

#### Communications Lead
**Responsibilities**:
- Internal stakeholder communication
- Customer and public communications
- Media relations coordination
- Regulatory body notifications

### Extended Team Members
- **Forensics Specialist**: External expert for complex investigations
- **HR Representative**: For insider threat incidents
- **Compliance Officer**: For regulatory requirements
- **External Counsel**: For legal guidance
- **Law Enforcement Liaison**: When criminal activity suspected

## Detection and Initial Response

### Detection Sources

#### Automated Detection
- Security Information and Event Management (SIEM)
- Intrusion Detection/Prevention Systems (IDS/IPS)
- Endpoint Detection and Response (EDR)
- Application security monitoring
- Network traffic analysis
- Vulnerability scanners

#### Manual Detection
- Security team monitoring
- Employee reports
- Customer reports
- Third-party notifications
- Audit findings
- Penetration testing results

### Initial Response Checklist

```markdown
- [ ] Acknowledge detection within 15 minutes (SEV1) or 30 minutes (SEV2)
- [ ] Create security incident ticket
- [ ] Assign Incident Commander
- [ ] Perform initial assessment and classification
- [ ] Activate response team
- [ ] Begin evidence preservation
- [ ] Initiate communication protocols
- [ ] Document all actions taken
```

### Initial Assessment Procedures

#### Step 1: Verify the Incident

```bash
# Check SIEM for related alerts
# Access SIEM dashboard and search for related events

# Verify suspicious activity
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=1h | grep -E "(ERROR|UNAUTHORIZED|FAILED_LOGIN)"

# Check access logs
aws logs filter-log-events \
  --log-group-name /aws/eks/claude-deployment-prod/cluster \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --filter-pattern "ERROR"

# Review network traffic
# Check firewall logs and network monitoring tools
```

#### Step 2: Initial Scope Assessment

```bash
# Identify affected systems
kubectl get pods -n claude-deployment-prod -o wide
kubectl get nodes -o wide

# Check database access logs
psql $DATABASE_URL -c "
SELECT 
  usename,
  client_addr,
  application_name,
  state,
  query_start,
  query
FROM pg_stat_activity 
WHERE state != 'idle' 
ORDER BY query_start DESC;
"

# Review authentication logs
kubectl logs deployment/claude-deployment-auth -n claude-deployment-prod --since=1h | grep -E "(LOGIN|AUTHENTICATION|TOKEN)"
```

#### Step 3: Evidence Preservation

```bash
# Create forensic snapshots
aws ec2 create-snapshot \
  --volume-id $AFFECTED_VOLUME_ID \
  --description "Security incident forensic snapshot $(date)"

# Preserve log files
kubectl create configmap incident-logs-$(date +%Y%m%d-%H%M%S) \
  --from-literal=timestamp="$(date)" \
  --from-literal=incident-id="INC-$(date +%Y%m%d-%H%M%S)" \
  --namespace=security-incidents

# Export container logs
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=24h > /tmp/incident-api-logs.txt

# Capture network traffic (if still active)
# Use tcpdump or wireshark on affected nodes
```

## Containment Procedures

### Immediate Containment (0-30 minutes)

#### Network Isolation

```bash
# Isolate affected pods
kubectl label pod <affected-pod> quarantine=true -n claude-deployment-prod

# Apply network policy to block traffic
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-policy
  namespace: claude-deployment-prod
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
  - Ingress
  - Egress
  egress: []
  ingress: []
EOF
```

#### Account Isolation

```bash
# Disable compromised user accounts
kubectl patch serviceaccount <compromised-sa> -n claude-deployment-prod \
  -p '{"secrets": []}'

# Revoke AWS IAM access
aws iam attach-user-policy \
  --user-name <compromised-user> \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# Reset passwords for affected accounts
kubectl create secret generic user-password-reset \
  --from-literal=user="<username>" \
  --from-literal=reset-required="true" \
  --namespace=security-incidents
```

#### System Isolation

```bash
# Isolate affected nodes
kubectl cordon <affected-node>
kubectl drain <affected-node> --ignore-daemonsets --delete-emptydir-data

# Stop affected services
kubectl scale deployment <affected-deployment> --replicas=0 -n claude-deployment-prod

# Block external access
aws ec2 authorize-security-group-ingress \
  --group-id $SECURITY_GROUP_ID \
  --protocol tcp \
  --port 22 \
  --source-group $INCIDENT_RESPONSE_SG
```

### Extended Containment (30 minutes - 2 hours)

#### Database Protection

```bash
# Create database backup before investigation
aws rds create-db-snapshot \
  --db-instance-identifier claude-deployment-primary \
  --db-snapshot-identifier incident-backup-$(date +%Y%m%d-%H%M%S)

# Rotate database credentials
aws secretsmanager update-secret \
  --secret-id claude-deployment/database \
  --secret-string '{"password":"'$(openssl rand -base64 32)'"}'

# Restrict database access
psql $DATABASE_URL -c "
REVOKE ALL ON SCHEMA public FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
"
```

#### Certificate and Key Rotation

```bash
# Rotate JWT secrets
kubectl create secret generic claude-deployment-jwt-secret \
  --from-literal=jwt-secret="$(openssl rand -base64 64)" \
  --namespace=claude-deployment-prod \
  --dry-run=client -o yaml | kubectl apply -f -

# Regenerate API keys
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"api-key-rotation-required":"true"}}'

# Update SSL certificates if compromised
kubectl delete secret claude-deployment-tls -n claude-deployment-prod
kubectl apply -f k8s/production/certificates.yaml
```

## Investigation and Analysis

### Forensic Investigation

#### Evidence Collection

```bash
# Collect system information
kubectl get pods,services,configmaps,secrets -n claude-deployment-prod -o yaml > incident-k8s-state.yaml

# Export database activity logs
psql $DATABASE_URL -c "
COPY (
  SELECT 
    usename,
    client_addr,
    query_start,
    query
  FROM pg_stat_activity 
  WHERE query_start > NOW() - INTERVAL '24 hours'
) TO STDOUT WITH CSV HEADER;
" > incident-db-activity.csv

# Collect application metrics
curl -s http://prometheus:9090/api/v1/query_range \
  -d 'query=sum(rate(http_requests_total[5m])) by (status_code)' \
  -d 'start='$(date -d '24 hours ago' +%s) \
  -d 'end='$(date +%s) \
  -d 'step=300' > incident-metrics.json
```

#### Log Analysis

```bash
# Search for suspicious patterns
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=24h | \
  grep -E "(sql injection|xss|unauthorized|privilege|escalation|admin|root)" > suspicious-logs.txt

# Analyze authentication patterns
kubectl logs deployment/claude-deployment-auth -n claude-deployment-prod --since=24h | \
  grep -E "(failed|success|login|logout)" | \
  awk '{print $1, $2, $NF}' | sort | uniq -c | sort -nr > auth-patterns.txt

# Check for unusual network activity
# Analyze firewall logs, VPC flow logs, etc.
aws logs filter-log-events \
  --log-group-name /aws/vpc/flowlogs \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --filter-pattern "{ $.action = \"REJECT\" }" > network-blocks.json
```

#### Threat Intelligence

```bash
# Check IOCs against threat intelligence
cat suspicious-ips.txt | while read ip; do
  curl -s "https://api.virustotal.com/vtapi/v2/ip-address/report?apikey=$VT_API_KEY&ip=$ip" | \
    jq '.positives' >> ioc-analysis.txt
done

# Analyze file hashes
find /tmp/incident-files -type f -exec sha256sum {} \; | \
  while read hash file; do
    curl -s "https://api.virustotal.com/vtapi/v2/file/report?apikey=$VT_API_KEY&resource=$hash" | \
      jq '.positives' >> file-analysis.txt
  done
```

### Timeline Reconstruction

```bash
# Create incident timeline
cat > incident-timeline.md << EOF
# Security Incident Timeline

## Incident ID: INC-$(date +%Y%m%d-%H%M%S)

### Pre-Incident
- $(date -d '7 days ago' +'%Y-%m-%d %H:%M:%S'): Last security scan completed
- $(date -d '3 days ago' +'%Y-%m-%d %H:%M:%S'): System update applied

### Incident Detection
- $(date +'%Y-%m-%d %H:%M:%S'): Initial alert triggered
- [Add specific events as discovered]

### Response Actions
- [Document all response actions with timestamps]

EOF
```

## Eradication and Recovery

### Malware Eradication

```bash
# Rebuild affected containers
docker build -t claude-deployment-api:incident-clean -f Dockerfile.clean .
docker push $REGISTRY/claude-deployment-api:incident-clean

# Deploy clean images
kubectl set image deployment/claude-deployment-api \
  api=$REGISTRY/claude-deployment-api:incident-clean \
  -n claude-deployment-prod

# Scan for persistence mechanisms
kubectl exec -it <pod-name> -n claude-deployment-prod -- \
  find /etc /var /tmp -type f -newer /tmp/incident-start.marker
```

### System Hardening

```bash
# Apply security patches
kubectl apply -f security-patches/

# Update security policies
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: security-scan
spec:
  containers:
  - name: scanner
    image: aquasec/trivy:latest
    command: ["/bin/sh"]
    args: ["-c", "trivy image --exit-code 1 claude-deployment-api:latest"]
  restartPolicy: Never
EOF

# Implement additional monitoring
kubectl apply -f enhanced-monitoring/
```

### Data Integrity Verification

```bash
# Verify database integrity
psql $DATABASE_URL -c "
SELECT 
  tablename,
  pg_size_pretty(pg_total_relation_size(tablename::regclass)) as size,
  (SELECT count(*) FROM information_schema.columns WHERE table_name = tablename) as columns
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(tablename::regclass) DESC;
"

# Check for unauthorized data modifications
psql $DATABASE_URL -c "
SELECT 
  table_name,
  column_name,
  data_type
FROM information_schema.columns 
WHERE table_schema = 'public' 
  AND (column_name LIKE '%password%' OR column_name LIKE '%token%')
ORDER BY table_name;
"

# Verify file integrity
kubectl exec -it deployment/claude-deployment-api -n claude-deployment-prod -- \
  find /app -type f -exec sha256sum {} \; > current-checksums.txt

# Compare with known good checksums
diff known-good-checksums.txt current-checksums.txt > integrity-check.diff
```

### Recovery Procedures

```bash
# Restore from clean backup if needed
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier claude-deployment-recovered \
  --db-snapshot-identifier clean-backup-20240101

# Gradually restore services
kubectl scale deployment claude-deployment-auth --replicas=1 -n claude-deployment-prod
kubectl wait --for=condition=available deployment/claude-deployment-auth -n claude-deployment-prod

kubectl scale deployment claude-deployment-api --replicas=2 -n claude-deployment-prod
kubectl wait --for=condition=available deployment/claude-deployment-api -n claude-deployment-prod

# Verify service functionality
curl -f https://api.claude-deployment.com/health
./scripts/security-health-check.sh
```

## Communication and Reporting

### Internal Communication

#### Security Team Updates

```
Subject: [SEC-INC] Security Incident Status Update - Hour X

Incident ID: INC-YYYYMMDD-HHMMSS
Severity: SEV1
Status: CONTAINMENT

Summary:
- Current situation overview
- Actions taken in last hour
- Next planned actions
- Expected timeline

Impact Assessment:
- Systems affected
- Data exposure risk
- Business impact

Technical Details:
- Attack vectors identified
- IOCs discovered
- Containment measures

Next Update: [Time]
Incident Commander: [Name]
```

#### Executive Communication

```
Subject: URGENT: Security Incident Notification

We are responding to a security incident that was detected at [time].

Current Status:
- Incident contained/under investigation
- No evidence of data exfiltration (as of [time])
- Services remain operational/are being restored

Actions Taken:
- Immediate containment measures implemented
- Security response team activated
- Law enforcement contacted (if applicable)

Next Steps:
- Complete investigation
- Implement additional safeguards
- Full incident report within 48 hours

Point of Contact: [CISO Name and Number]
```

### External Communication

#### Customer Notification (if required)

```
Subject: Important Security Update

Dear [Customer Name],

We are writing to inform you of a security incident that may have affected your account information.

What Happened:
[Brief, clear description of the incident]

Information Involved:
[Specific data types that may have been accessed]

What We Are Doing:
- Immediately secured the affected systems
- Conducting thorough investigation
- Working with law enforcement (if applicable)
- Implementing additional security measures

What You Should Do:
- Change your password immediately
- Monitor your accounts for unusual activity
- Enable two-factor authentication

We sincerely apologize for this incident and any inconvenience it may cause.

Contact Information:
Security Team: security@claude-deployment.com
Support: +1-555-0199
```

#### Regulatory Reporting

```bash
# GDPR Breach Notification (if EU data involved)
# Must be reported within 72 hours to supervisory authority

# CCPA Notification (if California residents affected)
# Must notify California AG if >500 California residents affected

# SEC Disclosure (if material impact)
# Report on Form 8-K within 4 business days

# Industry-specific requirements
# Healthcare: HHS for HIPAA breaches
# Financial: Banking regulators for financial data
```

## Specific Incident Types

### Data Breach Response

#### Immediate Actions

```bash
# Stop data exfiltration
iptables -A OUTPUT -d <malicious-ip> -j DROP

# Identify compromised data
psql $DATABASE_URL -c "
SELECT 
  schemaname,
  tablename,
  n_tup_ins as inserts,
  n_tup_upd as updates,
  n_tup_del as deletes,
  last_vacuum,
  last_analyze
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY last_analyze DESC;
"

# Document accessed records
psql $DATABASE_URL -c "
CREATE TABLE incident_audit_trail AS
SELECT 
  table_name,
  count(*) as record_count,
  min(created_at) as earliest_record,
  max(updated_at) as latest_update
FROM information_schema.tables t
WHERE table_schema = 'public'
GROUP BY table_name;
"
```

### Ransomware Response

#### Immediate Actions

```bash
# Isolate all affected systems
kubectl delete networkpolicy --all -n claude-deployment-prod
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lockdown
  namespace: claude-deployment-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

# Check backup integrity
aws rds describe-db-snapshots \
  --db-instance-identifier claude-deployment-primary \
  --query 'DBSnapshots[?SnapshotCreateTime>=`2024-01-01`]'

# Do NOT pay ransom - contact law enforcement
echo "NEVER PAY RANSOM - CONTACT LAW ENFORCEMENT IMMEDIATELY"
```

### Insider Threat Response

#### Investigation Procedures

```bash
# Review user access patterns
kubectl get rolebindings,clusterrolebindings -A -o yaml | grep -B5 -A5 <suspect-user>

# Audit database access
psql $DATABASE_URL -c "
SELECT 
  usename,
  client_addr,
  application_name,
  query_start,
  state,
  query
FROM pg_stat_activity 
WHERE usename = '<suspect-user>'
ORDER BY query_start DESC;
"

# Check file access logs
kubectl exec -it deployment/claude-deployment-api -n claude-deployment-prod -- \
  find /app -name "*.log" -exec grep "<suspect-user>" {} \;
```

### DDoS Attack Response

#### Mitigation Steps

```bash
# Enable AWS Shield Advanced
aws shield subscribe-to-proactive-engagement

# Implement rate limiting
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: rate-limit
  namespace: claude-deployment-prod
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typed_config:
          "@type": type.googleapis.com/udpa.type.v1.TypedStruct
          type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          value:
            stat_prefix: local_rate_limiter
            token_bucket:
              max_tokens: 100
              tokens_per_fill: 100
              fill_interval: 60s
EOF

# Scale up infrastructure
kubectl scale deployment claude-deployment-api --replicas=20 -n claude-deployment-prod
```

## Post-Incident Activities

### Incident Report

```markdown
# Security Incident Report

## Executive Summary
- **Incident ID**: INC-YYYYMMDD-HHMMSS
- **Date/Time**: [Start] - [End]
- **Severity**: SEV1/SEV2/SEV3
- **Type**: Data Breach / Malware / DDoS / Other
- **Status**: Resolved / Ongoing
- **Impact**: [Brief description]

## Incident Details
### Detection
- **Detection Method**: [How was it detected]
- **Detection Time**: [When was it first detected]
- **Reporting Source**: [Who/what reported it]

### Attack Vector
- **Initial Access**: [How attackers gained access]
- **Persistence Mechanisms**: [How they maintained access]
- **Lateral Movement**: [How they moved through systems]
- **Data Exfiltration**: [What data was accessed/stolen]

### Timeline
[Detailed chronological timeline of events]

### Impact Assessment
- **Systems Affected**: [List of affected systems]
- **Data Compromised**: [Types and volume of data]
- **Business Impact**: [Operational and financial impact]
- **Regulatory Impact**: [Compliance violations]

## Response Actions
### Immediate Response
[List of immediate containment actions]

### Investigation
[Summary of investigation findings]

### Remediation
[Actions taken to remove threat and restore systems]

## Lessons Learned
### What Went Well
- [Positive aspects of response]

### Areas for Improvement
- [Areas that need enhancement]

### Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|---------|
| Implement additional monitoring | Security Team | 2024-02-01 | Open |
| Update incident response procedures | CISO | 2024-01-15 | Closed |

## Recommendations
1. [Specific security improvements]
2. [Process improvements]
3. [Technology enhancements]
4. [Training recommendations]
```

### Lessons Learned Session

#### Session Agenda

1. **Incident Review** (15 minutes)
   - Timeline review
   - Key decisions made
   - Resource utilization

2. **Response Evaluation** (20 minutes)
   - What worked well
   - What didn't work
   - Communication effectiveness

3. **Process Improvements** (15 minutes)
   - Procedural gaps
   - Tool limitations
   - Training needs

4. **Technical Improvements** (15 minutes)
   - Detection capabilities
   - Response tools
   - Infrastructure hardening

5. **Action Planning** (10 minutes)
   - Specific action items
   - Owners and timelines
   - Success metrics

### Improvement Implementation

```bash
# Example: Implement enhanced monitoring based on lessons learned
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-enhanced-alerts
  namespace: monitoring
spec:
  groups:
  - name: security
    rules:
    - alert: SuspiciousLoginPattern
      expr: increase(failed_login_attempts[5m]) > 10
      for: 1m
      labels:
        severity: warning
      annotations:
        summary: "Suspicious login pattern detected"
        
    - alert: UnauthorizedAPIAccess
      expr: increase(http_requests_total{status="401"}[5m]) > 50
      for: 2m
      labels:
        severity: critical
      annotations:
        summary: "Multiple unauthorized API access attempts"
EOF

# Update security policies
kubectl apply -f security-policies-v2/

# Implement additional security controls
kubectl apply -f enhanced-security-controls/
```

---

## Quick Reference

### Emergency Contacts

| Role | Primary | Secondary | Phone | Email |
|------|---------|-----------|-------|-------|
| CISO | [Name] | [Name] | +1-555-0100 | ciso@company.com |
| Security Team Lead | [Name] | [Name] | +1-555-0101 | security-lead@company.com |
| Legal Counsel | [Name] | [Name] | +1-555-0102 | legal@company.com |
| External Counsel | [Firm] | - | +1-555-0103 | external@lawfirm.com |
| Law Enforcement | FBI Cyber | Local FBI | +1-855-292-3937 | - |

### Critical Commands

```bash
# Emergency isolation
kubectl apply -f security/emergency-isolation.yaml

# Evidence preservation
kubectl create configmap incident-evidence-$(date +%Y%m%d-%H%M%S) --from-file=/tmp/evidence/

# Service lockdown
kubectl scale deployment --all --replicas=0 -n claude-deployment-prod

# Activate incident response
./scripts/activate-incident-response.sh SEV1
```

### Compliance Requirements

| Regulation | Notification Timeframe | Authority |
|------------|------------------------|-----------|
| GDPR | 72 hours | Data Protection Authority |
| CCPA | Without unreasonable delay | California AG |
| HIPAA | 60 days | HHS |
| SOX | 4 business days | SEC |
| PCI DSS | Immediately | Card brands |

### Important Resources

- **Security Incident Portal**: https://security.claude-deployment.com
- **SIEM Dashboard**: https://siem.claude-deployment.com
- **Threat Intelligence**: https://ti.claude-deployment.com
- **Legal Hotline**: +1-555-0199
- **FBI IC3**: https://ic3.gov

Remember: In a security incident, speed and accuracy are critical. When in doubt, escalate immediately and err on the side of caution.