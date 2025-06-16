# Monitoring and Alerting Runbook

## Table of Contents

1. [Overview](#overview)
2. [Monitoring Stack Architecture](#monitoring-stack-architecture)
3. [Key Metrics and Thresholds](#key-metrics-and-thresholds)
4. [Dashboard Management](#dashboard-management)
5. [Alert Configuration](#alert-configuration)
6. [Alert Response Procedures](#alert-response-procedures)
7. [Log Management](#log-management)
8. [Performance Monitoring](#performance-monitoring)
9. [Infrastructure Monitoring](#infrastructure-monitoring)
10. [Troubleshooting Monitoring Issues](#troubleshooting-monitoring-issues)

## Overview

This runbook provides comprehensive procedures for managing the monitoring and alerting infrastructure for the CODE project. It covers setup, configuration, alert response, and troubleshooting of the entire observability stack.

### Monitoring Objectives

- **Early Detection**: Identify issues before they impact customers
- **Root Cause Analysis**: Provide detailed metrics for troubleshooting
- **Capacity Planning**: Track resource usage trends
- **SLA Monitoring**: Ensure service level objectives are met
- **Security Monitoring**: Detect potential security incidents

### SLA Targets

| Metric | Target | Measurement Period |
|--------|--------|-------------------|
| Uptime | 99.9% | Monthly |
| API Response Time | P95 < 500ms | 5-minute windows |
| Error Rate | < 0.1% | 5-minute windows |
| Database Query Time | P95 < 100ms | 5-minute windows |

## Monitoring Stack Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Alerting Layer                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │  AlertManager   │  │    PagerDuty    │  │    Slack     ││
│  │   (Routing)     │  │  (Escalation)   │  │ (Notifications)││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
├─────────────────────────────────────────────────────────────┤
│                   Visualization Layer                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │     Grafana     │  │     Kibana      │  │   Status     ││
│  │  (Dashboards)   │  │   (Logs)        │  │    Page      ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
├─────────────────────────────────────────────────────────────┤
│                    Storage Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   Prometheus    │  │  Elasticsearch  │  │   S3 Logs    ││
│  │   (Metrics)     │  │   (Log Search)  │  │  (Archive)   ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
├─────────────────────────────────────────────────────────────┤
│                   Collection Layer                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   Node Exporter │  │   Fluent Bit    │  │  App Metrics ││
│  │  (Infrastructure)│  │    (Logs)       │  │ (Custom)     ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Purpose | Port | Namespace |
|-----------|---------|------|-----------|
| Prometheus | Metrics collection and storage | 9090 | monitoring |
| Grafana | Metrics visualization | 3000 | monitoring |
| AlertManager | Alert routing and grouping | 9093 | monitoring |
| Elasticsearch | Log storage and search | 9200 | logging |
| Kibana | Log visualization | 5601 | logging |
| Fluent Bit | Log collection | - | kube-system |

## Key Metrics and Thresholds

### Application Metrics

#### API Server Metrics

```prometheus
# Request Rate
sum(rate(http_requests_total[5m])) by (method, handler)

# Error Rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100

# Response Time
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))

# Active Connections
sum(http_requests_active) by (instance)
```

#### Database Metrics

```prometheus
# Connection Pool Usage
(postgresql_connections_active / postgresql_connections_max) * 100

# Query Duration
histogram_quantile(0.95, sum(rate(postgresql_query_duration_seconds_bucket[5m])) by (le))

# Database Size
postgresql_database_size_bytes

# Slow Queries
increase(postgresql_slow_queries_total[5m])
```

#### Redis Metrics

```prometheus
# Memory Usage
(redis_memory_used_bytes / redis_memory_max_bytes) * 100

# Hit Rate
(redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total)) * 100

# Connected Clients
redis_connected_clients

# Commands per Second
rate(redis_commands_processed_total[5m])
```

### Infrastructure Metrics

#### Node Metrics

```prometheus
# CPU Usage
100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory Usage
((node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes) * 100

# Disk Usage
((node_filesystem_size_bytes - node_filesystem_avail_bytes) / node_filesystem_size_bytes) * 100

# Network I/O
rate(node_network_receive_bytes_total[5m])
rate(node_network_transmit_bytes_total[5m])
```

#### Kubernetes Metrics

```prometheus
# Pod CPU Usage
sum(rate(container_cpu_usage_seconds_total[5m])) by (pod, namespace)

# Pod Memory Usage
sum(container_memory_working_set_bytes) by (pod, namespace)

# Pod Restart Count
increase(kube_pod_container_status_restarts_total[1h])

# Node Readiness
kube_node_status_condition{condition="Ready", status="true"}
```

### Alert Thresholds

| Alert | Warning | Critical | Duration |
|-------|---------|----------|----------|
| API Error Rate | > 1% | > 5% | 5 minutes |
| API Response Time | P95 > 1s | P95 > 2s | 5 minutes |
| CPU Usage | > 70% | > 90% | 10 minutes |
| Memory Usage | > 80% | > 95% | 5 minutes |
| Disk Usage | > 80% | > 90% | 5 minutes |
| Database Connections | > 70% | > 90% | 5 minutes |

## Dashboard Management

### Essential Dashboards

#### 1. System Overview Dashboard

```json
{
  "dashboard": {
    "title": "System Overview",
    "panels": [
      {
        "title": "Service Status",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"claude-deployment-api\"}",
            "legendFormat": "API Server"
          },
          {
            "expr": "up{job=\"postgresql\"}",
            "legendFormat": "Database"
          }
        ]
      },
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total[5m]))",
            "legendFormat": "Requests/sec"
          }
        ]
      }
    ]
  }
}
```

#### 2. API Performance Dashboard

Create API performance dashboard:
```bash
# Deploy API performance dashboard
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboard-api-performance
  namespace: monitoring
  labels:
    grafana_dashboard: "1"
data:
  api-performance.json: |
    {
      "dashboard": {
        "title": "API Performance",
        "panels": [
          {
            "title": "Response Time",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                "legendFormat": "P50"
              },
              {
                "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                "legendFormat": "P95"
              },
              {
                "expr": "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                "legendFormat": "P99"
              }
            ]
          },
          {
            "title": "Error Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m])) * 100",
                "legendFormat": "5xx Error Rate %"
              }
            ]
          }
        ]
      }
    }
EOF
```

#### 3. Infrastructure Dashboard

```bash
# Deploy infrastructure dashboard
kubectl apply -f monitoring/dashboards/infrastructure.yaml
```

### Dashboard Backup and Restore

#### Backup Dashboards

```bash
#!/bin/bash
# backup-dashboards.sh

GRAFANA_URL="https://grafana.claude-deployment.com"
API_KEY="your-grafana-api-key"
BACKUP_DIR="./grafana-backups/$(date +%Y%m%d)"

mkdir -p $BACKUP_DIR

# Get list of all dashboards
curl -H "Authorization: Bearer $API_KEY" \
  "$GRAFANA_URL/api/search?type=dash-db" | \
  jq -r '.[].uid' | \
  while read uid; do
    echo "Backing up dashboard: $uid"
    curl -H "Authorization: Bearer $API_KEY" \
      "$GRAFANA_URL/api/dashboards/uid/$uid" | \
      jq .dashboard > "$BACKUP_DIR/$uid.json"
  done

echo "Dashboard backup completed to $BACKUP_DIR"
```

#### Restore Dashboards

```bash
#!/bin/bash
# restore-dashboards.sh

GRAFANA_URL="https://grafana.claude-deployment.com"
API_KEY="your-grafana-api-key"
BACKUP_DIR="./grafana-backups/20240101"

for file in $BACKUP_DIR/*.json; do
  echo "Restoring dashboard: $(basename $file)"
  curl -X POST \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"dashboard\": $(cat $file), \"overwrite\": true}" \
    "$GRAFANA_URL/api/dashboards/db"
done
```

## Alert Configuration

### Prometheus Alert Rules

#### Critical Alerts

```yaml
# critical-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: claude-deployment-critical-alerts
  namespace: monitoring
spec:
  groups:
  - name: critical
    rules:
    - alert: APIServerDown
      expr: up{job="claude-deployment-api"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "API Server is down"
        description: "API Server has been down for more than 1 minute"
        
    - alert: HighErrorRate
      expr: sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100 > 5
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "High error rate detected"
        description: "Error rate is {{ $value }}% for the last 5 minutes"
        
    - alert: DatabaseDown
      expr: up{job="postgresql"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Database is down"
        description: "PostgreSQL database has been down for more than 1 minute"
        
    - alert: HighCPUUsage
      expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 90
      for: 10m
      labels:
        severity: critical
      annotations:
        summary: "High CPU usage on {{ $labels.instance }}"
        description: "CPU usage is {{ $value }}% for more than 10 minutes"
```

#### Warning Alerts

```yaml
# warning-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: claude-deployment-warning-alerts
  namespace: monitoring
spec:
  groups:
  - name: warning
    rules:
    - alert: HighResponseTime
      expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 1
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "High API response time"
        description: "95th percentile response time is {{ $value }}s"
        
    - alert: HighMemoryUsage
      expr: ((node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes) * 100 > 80
      for: 15m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage on {{ $labels.instance }}"
        description: "Memory usage is {{ $value }}%"
        
    - alert: DiskSpaceWarning
      expr: ((node_filesystem_size_bytes - node_filesystem_avail_bytes) / node_filesystem_size_bytes) * 100 > 80
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "Disk space warning on {{ $labels.instance }}"
        description: "Disk usage is {{ $value }}% on {{ $labels.mountpoint }}"
```

### AlertManager Configuration

```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@claude-deployment.com'
  slack_api_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
    group_wait: 10s
    repeat_interval: 30m
  - match:
      severity: warning
    receiver: 'warning-alerts'
    group_wait: 5m
    repeat_interval: 2h

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://127.0.0.1:5001/'
    
- name: 'critical-alerts'
  slack_configs:
  - channel: '#alerts-critical'
    title: '🚨 Critical Alert'
    text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
  pagerduty_configs:
  - service_key: 'your-pagerduty-service-key'
    
- name: 'warning-alerts'
  slack_configs:
  - channel: '#alerts-warning'
    title: '⚠️ Warning Alert'
    text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'dev', 'instance']
```

### Deploy Alert Configuration

```bash
# Apply alert rules
kubectl apply -f monitoring/alerts/critical-alerts.yaml
kubectl apply -f monitoring/alerts/warning-alerts.yaml

# Update AlertManager configuration
kubectl create secret generic alertmanager-config \
  --from-file=alertmanager.yml=monitoring/alertmanager.yml \
  --namespace=monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart AlertManager to reload config
kubectl rollout restart deployment/alertmanager -n monitoring
```

## Alert Response Procedures

### Alert Handling Workflow

```
Alert Fired → Notification Sent → On-Call Acknowledges → Investigation → Resolution → Post-Mortem
```

### Response Time SLAs

| Severity | Acknowledgment | First Response | Resolution Target |
|----------|----------------|----------------|-------------------|
| Critical | 5 minutes | 15 minutes | 1 hour |
| Warning | 30 minutes | 1 hour | 4 hours |
| Info | N/A | Next business day | N/A |

### Critical Alert Response

#### APIServerDown

**Immediate Actions**:
```bash
# Check pod status
kubectl get pods -n claude-deployment-prod -l app=claude-deployment-api

# Check recent events
kubectl get events -n claude-deployment-prod --sort-by='.lastTimestamp' | tail -10

# Check node health
kubectl get nodes

# Scale up if needed
kubectl scale deployment claude-deployment-api --replicas=8 -n claude-deployment-prod
```

**Investigation**:
```bash
# Check application logs
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --tail=50

# Check resource usage
kubectl top pods -n claude-deployment-prod

# Check load balancer
aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN
```

#### HighErrorRate

**Immediate Actions**:
```bash
# Check error patterns
kubectl logs deployment/claude-deployment-api -n claude-deployment-prod --since=10m | grep ERROR | tail -20

# Check external dependencies
curl -I https://api.openai.com/v1/models

# Enable circuit breaker if needed
kubectl patch configmap claude-deployment-config -n claude-deployment-prod \
  -p '{"data":{"circuit-breaker-enabled":"true"}}'
```

#### DatabaseDown

**Immediate Actions**:
```bash
# Check RDS status
aws rds describe-db-instances --db-instance-identifier claude-deployment-primary

# Test connectivity from pods
kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1;"

# Check for maintenance windows
aws rds describe-pending-maintenance-actions
```

### Warning Alert Response

#### HighResponseTime

**Investigation**:
```bash
# Check current performance metrics
curl -s 'http://prometheus:9090/api/v1/query?query=histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))'

# Check database performance
psql $DATABASE_URL -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 5;"

# Check resource constraints
kubectl top pods -n claude-deployment-prod --sort-by=cpu
```

**Mitigation**:
```bash
# Scale up if resource constrained
kubectl scale deployment claude-deployment-api --replicas=10 -n claude-deployment-prod

# Increase resource limits if needed
kubectl patch deployment claude-deployment-api -n claude-deployment-prod \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"6Gi","cpu":"2000m"}}}]}}}}'
```

### Alert Escalation

#### Escalation Triggers

1. **Critical alerts not acknowledged within 5 minutes**
2. **Critical alerts not resolved within 1 hour**
3. **Multiple related alerts firing simultaneously**
4. **Customer-reported issues during alert investigation**

#### Escalation Procedure

```bash
# Manual escalation script
#!/bin/bash
# escalate-alert.sh

ALERT_NAME="$1"
ALERT_SEVERITY="$2"

# Notify engineering manager
curl -X POST https://hooks.slack.com/services/... \
  -d "{
    \"channel\": \"#engineering-managers\",
    \"text\": \"🚨 ESCALATION: $ALERT_NAME (Severity: $ALERT_SEVERITY)\",
    \"username\": \"AlertManager\"
  }"

# Create PagerDuty incident if critical
if [ "$ALERT_SEVERITY" = "critical" ]; then
  curl -X POST https://events.pagerduty.com/v2/enqueue \
    -H "Content-Type: application/json" \
    -d "{
      \"routing_key\": \"$PAGERDUTY_ROUTING_KEY\",
      \"event_action\": \"trigger\",
      \"payload\": {
        \"summary\": \"$ALERT_NAME\",
        \"severity\": \"critical\",
        \"source\": \"AlertManager\"
      }
    }"
fi
```

## Log Management

### Log Collection Architecture

```
Application Pods → Fluent Bit → Elasticsearch → Kibana
                              ↓
                           S3 Archive
```

### Fluent Bit Configuration

```yaml
# fluent-bit.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: kube-system
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020

    [INPUT]
        Name              tail
        Path              /var/log/containers/*claude-deployment*.log
        Parser            docker
        Tag               kube.*
        Refresh_Interval  5
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On

    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Merge_Log           On
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off

    [OUTPUT]
        Name            es
        Match           *
        Host            elasticsearch.logging.svc.cluster.local
        Port            9200
        Index           claude-deployment-logs
        Type            _doc
        Logstash_Format On
        Logstash_Prefix claude-deployment
        Retry_Limit     False

    [OUTPUT]
        Name            s3
        Match           *
        bucket          claude-deployment-logs-archive
        region          us-west-2
        total_file_size 1M
        upload_timeout  10m
        use_put_object  On
```

### Log Analysis Queries

#### Application Error Analysis

```bash
# Find errors in last hour
curl -X GET "elasticsearch.logging.svc.cluster.local:9200/claude-deployment-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"match": {"kubernetes.labels.app": "claude-deployment-api"}},
          {"match": {"log": "ERROR"}},
          {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]
      }
    },
    "sort": [{"@timestamp": {"order": "desc"}}],
    "size": 100
  }'

# Count errors by endpoint
curl -X GET "elasticsearch.logging.svc.cluster.local:9200/claude-deployment-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "aggs": {
      "error_endpoints": {
        "terms": {
          "field": "endpoint.keyword",
          "size": 10
        }
      }
    },
    "query": {
      "bool": {
        "must": [
          {"match": {"level": "ERROR"}},
          {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]
      }
    },
    "size": 0
  }'
```

#### Performance Analysis

```bash
# Find slow requests
curl -X GET "elasticsearch.logging.svc.cluster.local:9200/claude-deployment-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"match": {"kubernetes.labels.app": "claude-deployment-api"}},
          {"range": {"response_time": {"gte": 1000}}}
        ]
      }
    },
    "sort": [{"response_time": {"order": "desc"}}],
    "size": 50
  }'
```

### Log Retention and Archival

```bash
# Set up index lifecycle management
curl -X PUT "elasticsearch.logging.svc.cluster.local:9200/_ilm/policy/claude-deployment-logs-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "actions": {
            "rollover": {
              "max_size": "10GB",
              "max_age": "1d"
            }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "allocate": {
              "number_of_replicas": 0
            }
          }
        },
        "cold": {
          "min_age": "30d",
          "actions": {
            "allocate": {
              "number_of_replicas": 0
            }
          }
        },
        "delete": {
          "min_age": "90d"
        }
      }
    }
  }'
```

## Performance Monitoring

### Application Performance Monitoring (APM)

#### Custom Metrics Collection

```python
# Example: Custom metrics in application code
from prometheus_client import Counter, Histogram, Gauge
import time

# Define metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')
ACTIVE_CONNECTIONS = Gauge('http_connections_active', 'Active HTTP connections')
DATABASE_QUERIES = Counter('database_queries_total', 'Total database queries', ['query_type'])
CACHE_HITS = Counter('cache_hits_total', 'Total cache hits', ['cache_type'])

# Usage in request handler
@REQUEST_LATENCY.time()
def handle_request(method, endpoint):
    start_time = time.time()
    try:
        # Process request
        result = process_request()
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status='200').inc()
        return result
    except Exception as e:
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status='500').inc()
        raise
    finally:
        ACTIVE_CONNECTIONS.dec()
```

#### Database Performance Monitoring

```bash
# Enable PostgreSQL monitoring
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-exporter-config
  namespace: monitoring
data:
  queries.yaml: |
    pg_stat_statements:
      query: "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 100"
      metrics:
        - query:
            usage: "LABEL"
            description: "Query text"
        - calls:
            usage: "COUNTER"
            description: "Number of times executed"
        - total_time:
            usage: "COUNTER"
            description: "Total time spent in milliseconds"
        - mean_time:
            usage: "GAUGE"
            description: "Mean time spent in milliseconds"
EOF

# Deploy postgres exporter
kubectl apply -f monitoring/postgres-exporter.yaml
```

### SLI/SLO Monitoring

#### Service Level Indicators

```prometheus
# Availability SLI
sum(rate(http_requests_total{status!~"5.."}[5m])) / sum(rate(http_requests_total[5m]))

# Latency SLI
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) < 0.5

# Error Rate SLI
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) < 0.001
```

#### SLO Dashboard

```json
{
  "dashboard": {
    "title": "SLO Dashboard",
    "panels": [
      {
        "title": "Availability SLO (99.9%)",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{status!~\"5..\"}[30d])) / sum(rate(http_requests_total[30d])) * 100",
            "legendFormat": "30-day Availability %"
          }
        ],
        "thresholds": [
          {"color": "red", "value": 99.9},
          {"color": "green", "value": 99.95}
        ]
      }
    ]
  }
}
```

## Infrastructure Monitoring

### Kubernetes Cluster Monitoring

#### Cluster Health Metrics

```bash
# Deploy kube-state-metrics
kubectl apply -f https://github.com/kubernetes/kube-state-metrics/examples/standard

# Key cluster metrics
kubectl get --raw /metrics | grep -E "(kube_node_status_condition|kube_pod_status_phase|kube_deployment_status_replicas)"
```

#### Node Monitoring

```bash
# Deploy node exporter
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: node-exporter
  template:
    metadata:
      labels:
        app: node-exporter
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: node-exporter
        image: prom/node-exporter:latest
        args:
        - --path.procfs=/host/proc
        - --path.sysfs=/host/sys
        - --collector.filesystem.ignored-mount-points
        - ^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)
        ports:
        - containerPort: 9100
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
EOF
```

### AWS Infrastructure Monitoring

#### CloudWatch Integration

```bash
# Configure CloudWatch exporter
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudwatch-exporter-config
  namespace: monitoring
data:
  config.yml: |
    region: us-west-2
    metrics:
    - aws_namespace: AWS/RDS
      aws_metric_name: CPUUtilization
      aws_dimensions: [DBInstanceIdentifier]
      aws_statistics: [Average]
    - aws_namespace: AWS/RDS
      aws_metric_name: DatabaseConnections
      aws_dimensions: [DBInstanceIdentifier]
      aws_statistics: [Average]
    - aws_namespace: AWS/ElastiCache
      aws_metric_name: CPUUtilization
      aws_dimensions: [CacheClusterId]
      aws_statistics: [Average]
    - aws_namespace: AWS/ApplicationELB
      aws_metric_name: RequestCount
      aws_dimensions: [LoadBalancer]
      aws_statistics: [Sum]
EOF
```

## Troubleshooting Monitoring Issues

### Prometheus Issues

#### Metrics Not Being Scraped

**Investigation**:
```bash
# Check Prometheus targets
kubectl port-forward svc/prometheus 9090:9090 -n monitoring
# Visit http://localhost:9090/targets

# Check service discovery
kubectl get servicemonitor -n claude-deployment-prod
kubectl describe servicemonitor claude-deployment-api -n claude-deployment-prod

# Verify metrics endpoint
kubectl exec -it deployment/claude-deployment-api -n claude-deployment-prod -- \
  curl localhost:8080/metrics
```

**Solutions**:
```bash
# Fix service labels
kubectl patch svc claude-deployment-api -n claude-deployment-prod \
  -p '{"metadata":{"labels":{"monitoring":"enabled"}}}'

# Restart Prometheus
kubectl rollout restart deployment/prometheus -n monitoring

# Check Prometheus configuration
kubectl get prometheus -n monitoring -o yaml
```

#### High Memory Usage

**Investigation**:
```bash
# Check Prometheus memory usage
kubectl top pod -n monitoring | grep prometheus

# Check retention settings
kubectl get prometheus -n monitoring -o yaml | grep retention

# Check series count
curl -s 'http://localhost:9090/api/v1/query?query=prometheus_tsdb_symbol_table_size_bytes'
```

**Solutions**:
```bash
# Reduce retention period
kubectl patch prometheus kube-prometheus-stack-prometheus -n monitoring \
  -p '{"spec":{"retention":"7d"}}'

# Increase memory limits
kubectl patch deployment prometheus -n monitoring \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"prometheus","resources":{"limits":{"memory":"8Gi"}}}]}}}}'
```

### Grafana Issues

#### Dashboard Not Loading

**Investigation**:
```bash
# Check Grafana logs
kubectl logs deployment/grafana -n monitoring --tail=50

# Check data source connection
kubectl exec -it deployment/grafana -n monitoring -- \
  curl -s http://prometheus:9090/api/v1/label/__name__/values
```

**Solutions**:
```bash
# Restart Grafana
kubectl rollout restart deployment/grafana -n monitoring

# Reset data source
kubectl exec -it deployment/grafana -n monitoring -- \
  grafana-cli admin reset-admin-password newpassword
```

### AlertManager Issues

#### Alerts Not Being Sent

**Investigation**:
```bash
# Check AlertManager status
kubectl logs deployment/alertmanager -n monitoring --tail=50

# Check alert rules
kubectl get prometheusrule -n monitoring

# Test webhook
curl -X POST https://hooks.slack.com/services/... \
  -d '{"text":"Test alert from AlertManager"}'
```

**Solutions**:
```bash
# Reload AlertManager configuration
kubectl rollout restart deployment/alertmanager -n monitoring

# Update webhook URL
kubectl patch secret alertmanager-config -n monitoring \
  -p '{"data":{"alertmanager.yml":"<base64-encoded-config>"}}'
```

---

## Quick Reference

### Essential Commands

```bash
# Check all monitoring services
kubectl get pods -n monitoring

# Port forward to Grafana
kubectl port-forward svc/grafana 3000:3000 -n monitoring

# Port forward to Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n monitoring

# Check alert rules
kubectl get prometheusrule -A

# View current alerts
curl -s http://localhost:9093/api/v1/alerts
```

### Emergency Procedures

```bash
# Disable all alerts temporarily
kubectl scale deployment alertmanager --replicas=0 -n monitoring

# Emergency dashboard access
kubectl port-forward svc/grafana 3000:3000 -n monitoring
# Admin credentials: admin/admin (default)

# Quick metrics check
curl -s http://localhost:9090/api/v1/query?query=up
```

### Key URLs

- **Grafana**: https://grafana.claude-deployment.com
- **Prometheus**: https://prometheus.claude-deployment.com
- **AlertManager**: https://alertmanager.claude-deployment.com
- **Kibana**: https://kibana.claude-deployment.com

### Contact Information

- **Monitoring Team**: monitoring@company.com
- **On-Call Engineer**: +1-555-0123
- **Slack Channel**: #monitoring-alerts