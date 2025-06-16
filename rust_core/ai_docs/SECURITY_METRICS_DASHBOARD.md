# Security Metrics Dashboard

## Overview

This document provides comprehensive security metrics, KPIs, Grafana dashboard configurations, and Prometheus queries for monitoring the Claude Optimized Deployment security posture in real-time.

## 1. Real-Time Security Metrics and KPIs

### Core Security KPIs

```yaml
security_kpis:
  authentication:
    - metric: authentication_success_rate
      target: "> 99.5%"
      slo: "99.9% over 30 days"
    - metric: authentication_latency_p95
      target: "< 100ms"
      slo: "< 50ms for 95% of requests"
    
  authorization:
    - metric: unauthorized_access_attempts
      target: "< 0.1% of total requests"
      alert_threshold: "> 1% in 5 minutes"
    - metric: rbac_policy_violations
      target: "0"
      alert_threshold: "> 5 in 1 hour"
  
  vulnerability_management:
    - metric: critical_vulnerabilities_open
      target: "0"
      slo: "Remediation within 24 hours"
    - metric: high_vulnerabilities_open
      target: "< 5"
      slo: "Remediation within 7 days"
  
  incident_response:
    - metric: mean_time_to_detect (MTTD)
      target: "< 5 minutes"
      slo: "< 2 minutes for critical incidents"
    - metric: mean_time_to_respond (MTTR)
      target: "< 30 minutes"
      slo: "< 15 minutes for critical incidents"
```

### Prometheus Queries for Core Metrics

```promql
# Authentication Success Rate
sum(rate(auth_attempts_total{result="success"}[5m])) / sum(rate(auth_attempts_total[5m])) * 100

# Authentication Latency P95
histogram_quantile(0.95, sum(rate(auth_duration_seconds_bucket[5m])) by (le))

# Unauthorized Access Attempts
sum(rate(auth_attempts_total{result="unauthorized"}[5m])) / sum(rate(auth_attempts_total[5m])) * 100

# RBAC Policy Violations
sum(increase(rbac_violations_total[1h]))

# Active Security Incidents
sum(security_incidents_active)

# Vulnerability Count by Severity
sum(vulnerabilities_open) by (severity)
```

## 2. Grafana Dashboard Queries

### Authentication Dashboard

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-auth",
    "title": "Security - Authentication Metrics",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "type": "graph",
        "title": "Authentication Success Rate",
        "targets": [
          {
            "expr": "sum(rate(auth_attempts_total{result=\"success\"}[5m])) / sum(rate(auth_attempts_total[5m])) * 100",
            "legendFormat": "Success Rate %",
            "refId": "A"
          }
        ],
        "yaxes": [
          {
            "format": "percent",
            "min": 0,
            "max": 100
          }
        ],
        "alert": {
          "conditions": [
            {
              "evaluator": {
                "params": [99.5],
                "type": "lt"
              },
              "query": {
                "params": ["A", "5m", "now"]
              },
              "reducer": {
                "type": "avg"
              },
              "type": "query"
            }
          ],
          "frequency": "60s",
          "handler": 1,
          "name": "Low Authentication Success Rate",
          "noDataState": "alerting"
        }
      },
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "type": "graph",
        "title": "Authentication Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, sum(rate(auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "P50",
            "refId": "A"
          },
          {
            "expr": "histogram_quantile(0.95, sum(rate(auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "P95",
            "refId": "B"
          },
          {
            "expr": "histogram_quantile(0.99, sum(rate(auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "P99",
            "refId": "C"
          }
        ],
        "yaxes": [
          {
            "format": "ms",
            "min": 0
          }
        ]
      },
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
        "type": "stat",
        "title": "Failed Authentication Attempts",
        "targets": [
          {
            "expr": "sum(increase(auth_attempts_total{result!=\"success\"}[1h]))",
            "refId": "A"
          }
        ],
        "options": {
          "colorMode": "value",
          "graphMode": "area",
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["lastNotNull"],
            "fields": "",
            "values": false
          },
          "textMode": "auto"
        },
        "thresholds": {
          "mode": "absolute",
          "steps": [
            {"color": "green", "value": null},
            {"color": "yellow", "value": 100},
            {"color": "red", "value": 500}
          ]
        }
      },
      {
        "id": 4,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
        "type": "table",
        "title": "Top Failed Authentication Sources",
        "targets": [
          {
            "expr": "topk(10, sum(increase(auth_attempts_total{result=\"failed\"}[1h])) by (source_ip))",
            "format": "table",
            "instant": true,
            "refId": "A"
          }
        ]
      }
    ],
    "refresh": "10s",
    "time": {
      "from": "now-6h",
      "to": "now"
    }
  }
}
```

### Vulnerability Tracking Dashboard

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-vulns",
    "title": "Security - Vulnerability Tracking",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0},
        "type": "piechart",
        "title": "Vulnerabilities by Severity",
        "targets": [
          {
            "expr": "sum(vulnerabilities_open) by (severity)",
            "legendFormat": "{{severity}}",
            "refId": "A"
          }
        ],
        "options": {
          "pieType": "donut",
          "displayLabels": ["name", "percent"],
          "legendDisplayMode": "list"
        }
      },
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 8, "x": 8, "y": 0},
        "type": "stat",
        "title": "Critical Vulnerabilities",
        "targets": [
          {
            "expr": "sum(vulnerabilities_open{severity=\"critical\"})",
            "refId": "A"
          }
        ],
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "orientation": "auto"
        },
        "thresholds": {
          "mode": "absolute",
          "steps": [
            {"color": "green", "value": 0},
            {"color": "red", "value": 1}
          ]
        }
      },
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 8, "x": 16, "y": 0},
        "type": "gauge",
        "title": "Security Score",
        "targets": [
          {
            "expr": "security_score",
            "refId": "A"
          }
        ],
        "options": {
          "showThresholdLabels": true,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "max": 100,
            "min": 0,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 70},
                {"color": "green", "value": 85}
              ]
            },
            "unit": "percent"
          }
        }
      },
      {
        "id": 4,
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
        "type": "graph",
        "title": "Vulnerability Trend",
        "targets": [
          {
            "expr": "sum(vulnerabilities_open) by (severity)",
            "legendFormat": "{{severity}}",
            "refId": "A"
          }
        ],
        "yaxes": [
          {
            "format": "short",
            "min": 0
          }
        ]
      }
    ],
    "refresh": "30s",
    "time": {
      "from": "now-7d",
      "to": "now"
    }
  }
}
```

## 3. Alert Rules for Security Incidents

### Prometheus Alert Rules

```yaml
groups:
  - name: security_alerts
    interval: 30s
    rules:
      # Authentication Alerts
      - alert: HighAuthenticationFailureRate
        expr: |
          (sum(rate(auth_attempts_total{result="failed"}[5m])) / 
           sum(rate(auth_attempts_total[5m]))) > 0.1
        for: 5m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High authentication failure rate detected"
          description: "Authentication failure rate is {{ $value | humanizePercentage }} (threshold: 10%)"
          runbook_url: "https://wiki.internal/runbooks/high-auth-failures"
      
      - alert: BruteForceAttempt
        expr: |
          sum(increase(auth_attempts_total{result="failed"}[5m])) by (source_ip) > 50
        for: 1m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Potential brute force attack from {{ $labels.source_ip }}"
          description: "{{ $value }} failed authentication attempts in 5 minutes"
          runbook_url: "https://wiki.internal/runbooks/brute-force-response"
      
      # Authorization Alerts
      - alert: RBACPolicyViolation
        expr: increase(rbac_violations_total[5m]) > 5
        for: 1m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "Multiple RBAC policy violations detected"
          description: "{{ $value }} RBAC violations in the last 5 minutes"
      
      - alert: UnauthorizedAPIAccess
        expr: |
          sum(rate(api_requests_total{status="403"}[5m])) > 10
        for: 5m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High rate of unauthorized API access attempts"
          description: "{{ $value }} unauthorized API requests per second"
      
      # Vulnerability Alerts
      - alert: CriticalVulnerabilityDetected
        expr: vulnerabilities_open{severity="critical"} > 0
        for: 1m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Critical vulnerability detected"
          description: "{{ $value }} critical vulnerabilities are open"
          action: "Immediate remediation required"
      
      - alert: HighVulnerabilityCount
        expr: sum(vulnerabilities_open{severity="high"}) > 10
        for: 30m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High number of high-severity vulnerabilities"
          description: "{{ $value }} high-severity vulnerabilities are open"
      
      # Security Incident Alerts
      - alert: ActiveSecurityIncident
        expr: security_incidents_active > 0
        for: 1m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Active security incident in progress"
          description: "{{ $value }} active security incidents detected"
          action: "Initiate incident response procedure"
      
      - alert: AnomalousTrafficPattern
        expr: |
          (sum(rate(http_requests_total[5m])) / 
           sum(rate(http_requests_total[5m] offset 1h))) > 5
        for: 10m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "Anomalous traffic pattern detected"
          description: "Traffic is {{ $value }}x higher than 1 hour ago"
      
      # Compliance Alerts
      - alert: ComplianceCheckFailed
        expr: compliance_check_failures > 0
        for: 5m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "Compliance check failures detected"
          description: "{{ $value }} compliance checks have failed"
      
      # Performance Impact Alerts
      - alert: SecurityProcessingLatencyHigh
        expr: |
          histogram_quantile(0.95, 
            sum(rate(security_processing_duration_seconds_bucket[5m])) by (le)
          ) > 0.5
        for: 10m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High security processing latency"
          description: "P95 security processing latency is {{ $value }}s (threshold: 0.5s)"
```

## 4. Security Score Calculation Methodology

### Security Score Formula

```python
def calculate_security_score():
    """
    Calculate overall security score (0-100)
    Based on weighted factors across multiple security domains
    """
    
    # Component weights (total = 100%)
    weights = {
        'vulnerability_score': 0.25,
        'authentication_score': 0.20,
        'authorization_score': 0.15,
        'compliance_score': 0.15,
        'incident_score': 0.15,
        'configuration_score': 0.10
    }
    
    # Calculate component scores
    scores = {
        'vulnerability_score': calculate_vulnerability_score(),
        'authentication_score': calculate_authentication_score(),
        'authorization_score': calculate_authorization_score(),
        'compliance_score': calculate_compliance_score(),
        'incident_score': calculate_incident_score(),
        'configuration_score': calculate_configuration_score()
    }
    
    # Calculate weighted total
    total_score = sum(scores[component] * weights[component] 
                     for component in weights)
    
    return round(total_score, 2)

def calculate_vulnerability_score():
    """
    Score based on open vulnerabilities
    """
    critical_vulns = get_metric('vulnerabilities_open{severity="critical"}')
    high_vulns = get_metric('vulnerabilities_open{severity="high"}')
    medium_vulns = get_metric('vulnerabilities_open{severity="medium"}')
    low_vulns = get_metric('vulnerabilities_open{severity="low"}')
    
    # Deduction formula
    score = 100
    score -= critical_vulns * 20  # -20 points per critical
    score -= high_vulns * 10      # -10 points per high
    score -= medium_vulns * 5     # -5 points per medium
    score -= low_vulns * 1        # -1 point per low
    
    return max(0, score)

def calculate_authentication_score():
    """
    Score based on authentication metrics
    """
    success_rate = get_metric('auth_success_rate')
    failed_attempts = get_metric('auth_failed_attempts_1h')
    mfa_coverage = get_metric('mfa_enabled_percentage')
    
    # Base score from success rate
    score = success_rate
    
    # Deductions for failures
    if failed_attempts > 1000:
        score -= 20
    elif failed_attempts > 500:
        score -= 10
    elif failed_attempts > 100:
        score -= 5
    
    # Bonus for MFA coverage
    score += (mfa_coverage - 50) * 0.2  # Bonus/penalty around 50% baseline
    
    return max(0, min(100, score))
```

### Prometheus Recording Rules for Security Score

```yaml
groups:
  - name: security_score_rules
    interval: 60s
    rules:
      # Vulnerability Score Component
      - record: security:vulnerability_score
        expr: |
          100 - (
            sum(vulnerabilities_open{severity="critical"}) * 20 +
            sum(vulnerabilities_open{severity="high"}) * 10 +
            sum(vulnerabilities_open{severity="medium"}) * 5 +
            sum(vulnerabilities_open{severity="low"}) * 1
          )
      
      # Authentication Score Component
      - record: security:authentication_score
        expr: |
          (sum(rate(auth_attempts_total{result="success"}[1h])) / 
           sum(rate(auth_attempts_total[1h]))) * 100 *
          (1 - clamp_max(sum(increase(auth_attempts_total{result="failed"}[1h])) / 1000, 0.2))
      
      # Authorization Score Component
      - record: security:authorization_score
        expr: |
          100 - (sum(increase(rbac_violations_total[1h])) * 2)
      
      # Compliance Score Component
      - record: security:compliance_score
        expr: |
          (sum(compliance_checks_passed) / 
           sum(compliance_checks_total)) * 100
      
      # Incident Score Component
      - record: security:incident_score
        expr: |
          100 - (
            sum(security_incidents_active) * 50 +
            sum(increase(security_incidents_total[24h])) * 5
          )
      
      # Overall Security Score
      - record: security_score
        expr: |
          security:vulnerability_score * 0.25 +
          security:authentication_score * 0.20 +
          security:authorization_score * 0.15 +
          security:compliance_score * 0.15 +
          security:incident_score * 0.15 +
          security:configuration_score * 0.10
```

## 5. Vulnerability Tracking Dashboard

### Detailed Vulnerability Dashboard JSON

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-vuln-detail",
    "title": "Security - Vulnerability Details",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 6, "w": 6, "x": 0, "y": 0},
        "type": "stat",
        "title": "Total Vulnerabilities",
        "targets": [
          {
            "expr": "sum(vulnerabilities_open)",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "green", "value": 0},
                {"color": "yellow", "value": 10},
                {"color": "red", "value": 50}
              ]
            }
          }
        }
      },
      {
        "id": 2,
        "gridPos": {"h": 6, "w": 6, "x": 6, "y": 0},
        "type": "bargauge",
        "title": "Vulnerabilities by Type",
        "targets": [
          {
            "expr": "sum(vulnerabilities_open) by (type)",
            "legendFormat": "{{type}}",
            "refId": "A"
          }
        ],
        "options": {
          "displayMode": "gradient",
          "orientation": "horizontal"
        }
      },
      {
        "id": 3,
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 0},
        "type": "table",
        "title": "Critical Vulnerabilities Detail",
        "targets": [
          {
            "expr": "vulnerabilities_detail{severity=\"critical\"}",
            "format": "table",
            "instant": true,
            "refId": "A"
          }
        ],
        "transformations": [
          {
            "id": "organize",
            "options": {
              "excludeByName": {
                "Time": true,
                "__name__": true
              },
              "renameByName": {
                "cve_id": "CVE ID",
                "component": "Component",
                "description": "Description",
                "remediation": "Remediation"
              }
            }
          }
        ]
      },
      {
        "id": 4,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 6},
        "type": "graph",
        "title": "Vulnerability Discovery vs Remediation",
        "targets": [
          {
            "expr": "sum(increase(vulnerabilities_discovered_total[1d]))",
            "legendFormat": "Discovered",
            "refId": "A"
          },
          {
            "expr": "sum(increase(vulnerabilities_remediated_total[1d]))",
            "legendFormat": "Remediated",
            "refId": "B"
          }
        ],
        "yaxes": [
          {
            "format": "short",
            "min": 0
          }
        ]
      },
      {
        "id": 5,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 6},
        "type": "heatmap",
        "title": "Vulnerability Age Distribution",
        "targets": [
          {
            "expr": "vulnerability_age_days_bucket",
            "format": "heatmap",
            "refId": "A"
          }
        ],
        "options": {
          "calculate": false,
          "yAxis": {
            "unit": "days",
            "decimals": 0
          }
        }
      }
    ],
    "refresh": "1m",
    "time": {
      "from": "now-30d",
      "to": "now"
    }
  }
}
```

## 6. Authentication Success/Failure Rates

### Detailed Authentication Metrics

```promql
# Authentication Success Rate by Method
sum(rate(auth_attempts_total{result="success"}[5m])) by (method) / 
sum(rate(auth_attempts_total[5m])) by (method) * 100

# Authentication Failure Reasons
sum(increase(auth_attempts_total{result="failed"}[1h])) by (reason)

# MFA Usage Rate
sum(rate(auth_attempts_total{mfa_used="true"}[5m])) / 
sum(rate(auth_attempts_total[5m])) * 100

# Token Refresh Rate
sum(rate(token_refresh_total[5m]))

# Session Duration Distribution
histogram_quantile(0.95, sum(rate(session_duration_seconds_bucket[5m])) by (le))

# Concurrent Sessions
sum(active_sessions) by (user_type)

# Geographic Authentication Distribution
sum(rate(auth_attempts_total[5m])) by (country)

# Authentication by Time of Day
sum(increase(auth_attempts_total[1h])) by (hour)
```

### Authentication Performance Dashboard

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-auth-perf",
    "title": "Security - Authentication Performance",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "type": "graph",
        "title": "Authentication Methods Performance",
        "targets": [
          {
            "expr": "sum(rate(auth_attempts_total{result=\"success\"}[5m])) by (method)",
            "legendFormat": "{{method}} - Success",
            "refId": "A"
          },
          {
            "expr": "sum(rate(auth_attempts_total{result=\"failed\"}[5m])) by (method)",
            "legendFormat": "{{method}} - Failed",
            "refId": "B"
          }
        ]
      },
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "type": "heatmap",
        "title": "Authentication Latency Heatmap",
        "targets": [
          {
            "expr": "sum(increase(auth_duration_seconds_bucket[5m])) by (le)",
            "format": "heatmap",
            "refId": "A"
          }
        ]
      },
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 8},
        "type": "piechart",
        "title": "Authentication Failure Reasons",
        "targets": [
          {
            "expr": "sum(increase(auth_attempts_total{result=\"failed\"}[1h])) by (reason)",
            "legendFormat": "{{reason}}",
            "refId": "A"
          }
        ]
      },
      {
        "id": 4,
        "gridPos": {"h": 8, "w": 8, "x": 8, "y": 8},
        "type": "stat",
        "title": "MFA Adoption Rate",
        "targets": [
          {
            "expr": "(sum(users_with_mfa_enabled) / sum(users_total)) * 100",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 50},
                {"color": "green", "value": 80}
              ]
            }
          }
        }
      },
      {
        "id": 5,
        "gridPos": {"h": 8, "w": 8, "x": 16, "y": 8},
        "type": "worldmap-panel",
        "title": "Authentication by Geography",
        "targets": [
          {
            "expr": "sum(increase(auth_attempts_total[1h])) by (country)",
            "refId": "A"
          }
        ]
      }
    ]
  }
}
```

## 7. Performance Impact of Security Features

### Security Performance Metrics

```promql
# Security Processing Overhead
(sum(rate(security_processing_duration_seconds_sum[5m])) / 
 sum(rate(request_duration_seconds_sum[5m]))) * 100

# Encryption/Decryption Performance
histogram_quantile(0.95, sum(rate(crypto_operation_duration_seconds_bucket[5m])) by (le, operation))

# WAF Processing Latency
histogram_quantile(0.95, sum(rate(waf_processing_duration_seconds_bucket[5m])) by (le))

# Security Middleware Impact
sum(rate(middleware_duration_seconds_sum{middleware=~"security.*"}[5m])) by (middleware)

# TLS Handshake Duration
histogram_quantile(0.95, sum(rate(tls_handshake_duration_seconds_bucket[5m])) by (le))

# Security Cache Hit Rate
sum(rate(security_cache_hits_total[5m])) / 
sum(rate(security_cache_requests_total[5m])) * 100

# Resource Usage by Security Components
sum(container_memory_usage_bytes{pod=~"security-.*"}) by (pod)
```

### Performance Impact Dashboard

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-performance",
    "title": "Security - Performance Impact",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "type": "graph",
        "title": "Security Processing Overhead",
        "targets": [
          {
            "expr": "(sum(rate(security_processing_duration_seconds_sum[5m])) / sum(rate(request_duration_seconds_sum[5m]))) * 100",
            "legendFormat": "Security Overhead %",
            "refId": "A"
          }
        ],
        "yaxes": [
          {
            "format": "percent",
            "min": 0
          }
        ],
        "alert": {
          "conditions": [
            {
              "evaluator": {
                "params": [10],
                "type": "gt"
              },
              "query": {
                "params": ["A", "5m", "now"]
              },
              "reducer": {
                "type": "avg"
              },
              "type": "query"
            }
          ],
          "frequency": "60s",
          "name": "High Security Processing Overhead"
        }
      },
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "type": "graph",
        "title": "Cryptographic Operations Performance",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(crypto_operation_duration_seconds_bucket[5m])) by (le, operation))",
            "legendFormat": "{{operation}} - P95",
            "refId": "A"
          }
        ],
        "yaxes": [
          {
            "format": "s",
            "min": 0
          }
        ]
      },
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
        "type": "graph",
        "title": "Security Components Resource Usage",
        "targets": [
          {
            "expr": "sum(container_memory_usage_bytes{pod=~\"security-.*\"}) by (pod) / 1024 / 1024",
            "legendFormat": "{{pod}} - Memory",
            "refId": "A"
          },
          {
            "expr": "sum(rate(container_cpu_usage_seconds_total{pod=~\"security-.*\"}[5m])) by (pod) * 100",
            "legendFormat": "{{pod}} - CPU %",
            "refId": "B",
            "yaxis": 2
          }
        ],
        "yaxes": [
          {
            "format": "decmbytes",
            "min": 0
          },
          {
            "format": "percent",
            "min": 0
          }
        ]
      }
    ]
  }
}
```

## 8. Compliance Status Indicators

### Compliance Metrics

```promql
# Overall Compliance Score
(sum(compliance_checks_passed) / sum(compliance_checks_total)) * 100

# Compliance by Framework
sum(compliance_checks_passed) by (framework) / 
sum(compliance_checks_total) by (framework) * 100

# Failed Compliance Controls
compliance_checks_total{status="failed"}

# Time Since Last Compliance Scan
time() - compliance_last_scan_timestamp

# Compliance Trend
sum(increase(compliance_checks_passed[7d])) / 
sum(increase(compliance_checks_total[7d])) * 100
```

### Compliance Dashboard

```json
{
  "dashboard": {
    "id": null,
    "uid": "security-compliance",
    "title": "Security - Compliance Status",
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0},
        "type": "gauge",
        "title": "Overall Compliance Score",
        "targets": [
          {
            "expr": "(sum(compliance_checks_passed) / sum(compliance_checks_total)) * 100",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "max": 100,
            "min": 0,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 80},
                {"color": "green", "value": 95}
              ]
            },
            "unit": "percent"
          }
        }
      },
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 0},
        "type": "bargauge",
        "title": "Compliance by Framework",
        "targets": [
          {
            "expr": "(sum(compliance_checks_passed) by (framework) / sum(compliance_checks_total) by (framework)) * 100",
            "legendFormat": "{{framework}}",
            "refId": "A"
          }
        ],
        "options": {
          "displayMode": "gradient",
          "orientation": "horizontal"
        }
      },
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
        "type": "table",
        "title": "Failed Compliance Controls",
        "targets": [
          {
            "expr": "compliance_checks_total{status=\"failed\"}",
            "format": "table",
            "instant": true,
            "refId": "A"
          }
        ],
        "transformations": [
          {
            "id": "organize",
            "options": {
              "excludeByName": {
                "Time": true,
                "__name__": true,
                "status": true
              },
              "renameByName": {
                "control_id": "Control ID",
                "control_name": "Control Name",
                "framework": "Framework",
                "severity": "Severity",
                "last_checked": "Last Checked"
              }
            }
          }
        ]
      }
    ]
  }
}
```

## Implementation Guide

### 1. Deploy Prometheus Recording Rules

```bash
# Apply recording rules
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-security-rules
  namespace: monitoring
data:
  security-rules.yml: |
$(cat security-rules.yml | sed 's/^/    /')
EOF

# Reload Prometheus configuration
kubectl -n monitoring exec -it prometheus-0 -- kill -HUP 1
```

### 2. Import Grafana Dashboards

```bash
# Import dashboards via API
for dashboard in security-auth security-vulns security-performance security-compliance; do
  curl -X POST http://grafana.local/api/dashboards/db \
    -H "Authorization: Bearer $GRAFANA_API_KEY" \
    -H "Content-Type: application/json" \
    -d @${dashboard}-dashboard.json
done
```

### 3. Configure Alertmanager

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'security-team'
  routes:
    - match:
        severity: critical
        team: security
      receiver: security-critical
      continue: true
    - match:
        severity: warning
        team: security
      receiver: security-warning

receivers:
  - name: 'security-team'
    slack_configs:
      - api_url: '${SECURITY_SLACK_WEBHOOK}'
        channel: '#security-alerts'
        
  - name: 'security-critical'
    pagerduty_configs:
      - service_key: '${PAGERDUTY_SECURITY_KEY}'
        severity: critical
        
  - name: 'security-warning'
    email_configs:
      - to: 'security-team@company.com'
        from: 'alerts@company.com'
```

### 4. Testing and Validation

```bash
# Test Prometheus queries
promtool query instant http://prometheus:9090 'security_score'

# Validate alert rules
promtool check rules security-alerts.yml

# Test dashboard load performance
curl -w "@curl-format.txt" -o /dev/null -s http://grafana.local/api/dashboards/uid/security-auth

# Generate test metrics
python scripts/generate_security_test_metrics.py
```

## Maintenance and Updates

1. **Weekly Tasks**:
   - Review alert thresholds based on false positive rates
   - Update vulnerability database
   - Analyze security score trends

2. **Monthly Tasks**:
   - Dashboard performance optimization
   - Alert rule tuning based on incident analysis
   - Security metrics accuracy validation

3. **Quarterly Tasks**:
   - Full security metrics review
   - Dashboard redesign based on user feedback
   - Integration with new security tools

## References

- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Grafana Dashboard Best Practices](https://grafana.com/docs/grafana/latest/best-practices/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Security Metrics](https://owasp.org/www-project-security-metrics/)