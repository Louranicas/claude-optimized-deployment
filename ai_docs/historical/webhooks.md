# Webhook Documentation

The Claude-Optimized Deployment Engine provides comprehensive webhook support for real-time event notifications. This allows your applications to receive immediate notifications about deployments, security events, system health changes, and more.

## Table of Contents

1. [Overview](#overview)
2. [Event Types](#event-types)
3. [Webhook Registration](#webhook-registration)
4. [Security](#security)
5. [Event Payloads](#event-payloads)
6. [Error Handling](#error-handling)
7. [Best Practices](#best-practices)
8. [Examples](#examples)

## Overview

Webhooks enable real-time communication between the CODE platform and your applications. When specific events occur, CODE will send HTTP POST requests to your configured webhook endpoints with detailed event data.

### Key Features

- **Real-time notifications**: Immediate event delivery
- **Reliable delivery**: Automatic retries with exponential backoff
- **Secure communication**: HMAC signature verification
- **Flexible filtering**: Subscribe to specific event types
- **Rich payloads**: Comprehensive event data
- **Custom headers**: Add authentication tokens and custom metadata

## Event Types

### Deployment Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `deployment.started` | Deployment process initiated | When a new deployment begins |
| `deployment.completed` | Deployment finished successfully | When deployment completes without errors |
| `deployment.failed` | Deployment encountered errors | When deployment fails at any stage |
| `deployment.cancelled` | Deployment was cancelled | Manual cancellation or timeout |
| `deployment.stage_completed` | Individual stage completed | Each deployment stage finishes |

### Security Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `security.vulnerability_found` | Security vulnerability detected | Security scan finds new vulnerabilities |
| `security.scan_completed` | Security scan finished | Any security scan completes |
| `security.policy_violation` | Security policy violated | Policy enforcement triggers |
| `security.threat_detected` | Active threat identified | Real-time threat detection |

### Circuit Breaker Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `circuit_breaker.opened` | Circuit breaker opened | Service failure threshold exceeded |
| `circuit_breaker.closed` | Circuit breaker closed | Service recovered and threshold met |
| `circuit_breaker.half_open` | Circuit breaker testing | Attempting recovery after timeout |

### System Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `system.health_degraded` | System health declining | Health check failures |
| `system.resource_exhausted` | Resource limits reached | CPU, memory, or storage limits |
| `system.service_unavailable` | Critical service down | Essential service failures |

### Monitoring Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `alert.triggered` | Monitoring alert fired | Threshold breach detected |
| `alert.resolved` | Alert condition cleared | Metrics return to normal |
| `metric.threshold_breach` | Metric exceeded threshold | Custom metric rules |

## Webhook Registration

### Register a Webhook

```bash
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/webhooks \
  -d '{
    "url": "https://your-service.com/webhooks/code",
    "events": [
      "deployment.started",
      "deployment.completed", 
      "deployment.failed",
      "security.vulnerability_found"
    ],
    "secret": "your-webhook-secret",
    "headers": {
      "Authorization": "Bearer your-service-token",
      "X-Custom-Header": "custom-value"
    },
    "retry_policy": {
      "max_retries": 3,
      "backoff_seconds": 60
    }
  }'
```

Response:
```json
{
  "webhook_id": "123e4567-e89b-12d3-a456-426614174000",
  "url": "https://your-service.com/webhooks/code",
  "events": [
    "deployment.started",
    "deployment.completed",
    "deployment.failed",
    "security.vulnerability_found"
  ],
  "created_at": "2025-05-31T10:00:00.000Z",
  "status": "active",
  "last_triggered": null,
  "trigger_count": 0
}
```

### List Webhooks

```bash
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/webhooks
```

### Update Webhook

```bash
curl -X PUT -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/webhooks/123e4567-e89b-12d3-a456-426614174000 \
  -d '{
    "events": [
      "deployment.started",
      "deployment.completed",
      "deployment.failed",
      "security.vulnerability_found",
      "circuit_breaker.opened"
    ]
  }'
```

### Delete Webhook

```bash
curl -X DELETE -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/webhooks/123e4567-e89b-12d3-a456-426614174000
```

## Security

### HMAC Signature Verification

All webhook payloads are signed using HMAC-SHA256 with your webhook secret. Verify signatures to ensure authenticity:

#### Python Example

```python
import hmac
import hashlib
from flask import request

def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature using HMAC-SHA256."""
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    
    # Remove 'sha256=' prefix if present
    if signature.startswith('sha256='):
        signature = signature[7:]
    
    return hmac.compare_digest(expected_signature, signature)

@app.route('/webhooks/code', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-CODE-Signature')
    payload = request.get_data()
    
    if not verify_webhook_signature(payload, signature, WEBHOOK_SECRET):
        return 'Invalid signature', 401
    
    # Process webhook
    event_data = request.get_json()
    handle_event(event_data)
    
    return 'OK', 200
```

#### Node.js Example

```javascript
const crypto = require('crypto');
const express = require('express');

function verifyWebhookSignature(payload, signature, secret) {
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(payload, 'utf8')
        .digest('hex');
    
    // Remove 'sha256=' prefix if present
    const actualSignature = signature.startsWith('sha256=') 
        ? signature.slice(7) 
        : signature;
    
    return crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'hex'),
        Buffer.from(actualSignature, 'hex')
    );
}

app.post('/webhooks/code', express.raw({type: 'application/json'}), (req, res) => {
    const signature = req.headers['x-code-signature'];
    const payload = req.body;
    
    if (!verifyWebhookSignature(payload, signature, WEBHOOK_SECRET)) {
        return res.status(401).send('Invalid signature');
    }
    
    // Process webhook
    const eventData = JSON.parse(payload);
    handleEvent(eventData);
    
    res.status(200).send('OK');
});
```

### Headers

CODE sends the following headers with each webhook:

- `Content-Type: application/json`
- `X-CODE-Signature: sha256=<signature>`
- `X-CODE-Event: <event_type>`
- `X-CODE-Delivery: <unique_delivery_id>`
- `X-CODE-Timestamp: <unix_timestamp>`
- Custom headers you configured during registration

## Event Payloads

### Common Structure

All webhook payloads follow this structure:

```json
{
  "event": "event.type",
  "timestamp": "2025-05-31T10:00:00.000Z",
  "delivery_id": "123e4567-e89b-12d3-a456-426614174000",
  "data": {
    // Event-specific data
  },
  "metadata": {
    "source": "code-api",
    "version": "1.0.0",
    "environment": "production"
  }
}
```

### Deployment Events

#### deployment.started

```json
{
  "event": "deployment.started",
  "timestamp": "2025-05-31T10:00:00.000Z",
  "delivery_id": "123e4567-e89b-12d3-a456-426614174000",
  "data": {
    "deployment_id": "dep-789xyz",
    "application_name": "my-web-app",
    "environment": "production",
    "deployment_type": "kubernetes",
    "version": "v2.1.0",
    "source": {
      "type": "git",
      "repository": "https://github.com/company/my-web-app.git",
      "branch": "main",
      "commit_sha": "abc123def456"
    },
    "initiated_by": "user@company.com",
    "estimated_duration": 300
  },
  "metadata": {
    "source": "code-api",
    "version": "1.0.0",
    "environment": "production"
  }
}
```

#### deployment.completed

```json
{
  "event": "deployment.completed",
  "timestamp": "2025-05-31T10:05:00.000Z",
  "delivery_id": "456e7890-e89b-12d3-a456-426614174111",
  "data": {
    "deployment_id": "dep-789xyz",
    "application_name": "my-web-app",
    "environment": "production",
    "version": "v2.1.0",
    "duration_seconds": 287,
    "status": "succeeded",
    "stages": [
      {
        "name": "security_scan",
        "status": "succeeded",
        "duration_seconds": 45
      },
      {
        "name": "build",
        "status": "succeeded", 
        "duration_seconds": 120
      },
      {
        "name": "deploy",
        "status": "succeeded",
        "duration_seconds": 90
      },
      {
        "name": "health_check",
        "status": "succeeded",
        "duration_seconds": 32
      }
    ],
    "artifacts": [
      {
        "name": "docker_image",
        "type": "container_image",
        "url": "my-registry.com/my-web-app:v2.1.0"
      },
      {
        "name": "deployment_manifest",
        "type": "kubernetes_manifest",
        "url": "s3://deployments/my-web-app/v2.1.0/manifest.yaml"
      }
    ],
    "metrics": {
      "resources_created": 5,
      "resources_updated": 3,
      "pods_deployed": 3,
      "services_exposed": 2
    }
  }
}
```

#### deployment.failed

```json
{
  "event": "deployment.failed",
  "timestamp": "2025-05-31T10:03:00.000Z",
  "delivery_id": "789e1234-e89b-12d3-a456-426614174222",
  "data": {
    "deployment_id": "dep-789xyz",
    "application_name": "my-web-app",
    "environment": "production",
    "version": "v2.1.0",
    "duration_seconds": 180,
    "status": "failed",
    "failed_stage": "security_scan",
    "error": {
      "code": "SECURITY_VULNERABILITIES_FOUND",
      "message": "High severity vulnerabilities detected",
      "details": {
        "critical_count": 0,
        "high_count": 3,
        "medium_count": 7
      }
    },
    "logs_url": "https://logs.company.com/deployments/dep-789xyz"
  }
}
```

### Security Events

#### security.vulnerability_found

```json
{
  "event": "security.vulnerability_found",
  "timestamp": "2025-05-31T10:00:00.000Z",
  "delivery_id": "sec-123456-789",
  "data": {
    "scan_id": "scan-abc123",
    "scan_type": "dependency",
    "target": {
      "type": "file",
      "path": "./package.json",
      "application": "my-web-app"
    },
    "vulnerability": {
      "id": "CVE-2025-1234",
      "title": "Remote Code Execution in lodash",
      "description": "A vulnerability in lodash allows remote code execution...",
      "severity": "high",
      "cvss_score": 8.5,
      "component": "lodash",
      "version": "4.17.10",
      "fixed_version": "4.17.21",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
        "https://github.com/lodash/lodash/security/advisories"
      ]
    },
    "remediation": {
      "fix_available": true,
      "recommended_action": "upgrade",
      "commands": ["npm update lodash"]
    }
  }
}
```

#### security.scan_completed

```json
{
  "event": "security.scan_completed",
  "timestamp": "2025-05-31T10:02:00.000Z",
  "delivery_id": "scan-comp-456",
  "data": {
    "scan_id": "scan-abc123",
    "scan_type": "comprehensive",
    "target": {
      "type": "repository",
      "path": "./",
      "application": "my-web-app"
    },
    "duration_seconds": 120,
    "status": "completed",
    "summary": {
      "total_issues": 12,
      "critical": 0,
      "high": 3,
      "medium": 7,
      "low": 2,
      "fixed_available": 10
    },
    "scan_components": [
      {
        "type": "dependency",
        "issues_found": 8,
        "coverage": "100%"
      },
      {
        "type": "container",
        "issues_found": 4,
        "coverage": "100%"
      },
      {
        "type": "code",
        "issues_found": 0,
        "coverage": "95%"
      }
    ],
    "report_url": "https://security.company.com/reports/scan-abc123"
  }
}
```

### Circuit Breaker Events

#### circuit_breaker.opened

```json
{
  "event": "circuit_breaker.opened",
  "timestamp": "2025-05-31T10:01:00.000Z",
  "delivery_id": "cb-opened-123",
  "data": {
    "breaker_name": "payment-service",
    "previous_state": "closed",
    "current_state": "open",
    "trigger_reason": "failure_threshold_exceeded",
    "metrics": {
      "failure_count": 15,
      "success_count": 2,
      "failure_rate": 0.88,
      "consecutive_failures": 8,
      "last_failure_time": "2025-05-31T10:00:58.000Z",
      "last_success_time": "2025-05-31T09:58:42.000Z"
    },
    "configuration": {
      "failure_threshold": 10,
      "timeout_duration": 60,
      "half_open_max_calls": 3
    },
    "service_info": {
      "endpoint": "https://payment-service.internal:8080",
      "health_check": "/health",
      "tags": ["payment", "critical"]
    }
  }
}
```

### System Events

#### alert.triggered

```json
{
  "event": "alert.triggered",
  "timestamp": "2025-05-31T10:00:00.000Z",
  "delivery_id": "alert-trigger-789",
  "data": {
    "alert_id": "alert-cpu-high",
    "name": "High CPU Usage",
    "description": "CPU usage exceeded 85% for more than 5 minutes",
    "severity": "warning",
    "source": "prometheus",
    "query": "avg(rate(cpu_usage_total[5m])) > 0.85",
    "current_value": 0.92,
    "threshold": 0.85,
    "duration": "6m32s",
    "labels": {
      "instance": "web-server-1",
      "job": "node-exporter",
      "environment": "production"
    },
    "annotations": {
      "summary": "High CPU usage detected on web-server-1",
      "description": "CPU usage is 92%, exceeding the 85% threshold",
      "runbook_url": "https://runbooks.company.com/cpu-high"
    }
  }
}
```

## Error Handling

### Retry Policy

CODE implements automatic retry with exponential backoff:

1. **Initial retry**: After 1 second
2. **Subsequent retries**: Exponential backoff (2s, 4s, 8s, etc.)
3. **Maximum retries**: Configurable (default: 3)
4. **Maximum backoff**: Configurable (default: 300 seconds)

### Response Expectations

Your webhook endpoint should:

- **Return HTTP 2xx** for successful processing
- **Return HTTP 4xx** for permanent failures (no retry)
- **Return HTTP 5xx** for temporary failures (will retry)
- **Respond within 30 seconds** (default timeout)

### Failed Delivery Handling

When webhooks fail after all retries:

1. Event is marked as `failed`
2. Webhook status may be set to `inactive` after repeated failures
3. Failed events are logged for debugging
4. Optionally, configure dead letter queue for failed events

## Best Practices

### Security

1. **Always verify signatures**: Implement HMAC verification
2. **Use HTTPS**: Never use HTTP for webhook endpoints
3. **Validate event types**: Only process expected events
4. **Rate limiting**: Implement rate limiting on your webhook endpoint
5. **Authentication**: Use additional authentication headers if needed

### Performance

1. **Respond quickly**: Acknowledge receipt immediately (HTTP 200)
2. **Process asynchronously**: Queue events for background processing
3. **Implement idempotency**: Handle duplicate events gracefully
4. **Monitor webhook health**: Track processing times and error rates

### Reliability

1. **Handle duplicates**: Events may be delivered more than once
2. **Implement timeouts**: Don't let webhook processing hang
3. **Log everything**: Keep detailed logs for debugging
4. **Graceful degradation**: Continue operating if webhook processing fails

### Example Implementation

```python
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Event processing queue
event_queue = asyncio.Queue()

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify webhook HMAC signature."""
    expected = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    actual = signature.replace('sha256=', '') if signature.startswith('sha256=') else signature
    return hmac.compare_digest(expected, actual)

@app.route('/webhooks/code', methods=['POST'])
def handle_webhook():
    """Handle CODE webhook events."""
    try:
        # Get signature and payload
        signature = request.headers.get('X-CODE-Signature')
        payload = request.get_data()
        
        # Verify signature
        if not verify_signature(payload, signature, WEBHOOK_SECRET):
            logger.warning('Invalid webhook signature')
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse event data
        event_data = request.get_json()
        event_type = event_data.get('event')
        delivery_id = event_data.get('delivery_id')
        
        # Log receipt
        logger.info(f'Received webhook: {event_type} ({delivery_id})')
        
        # Queue for async processing
        asyncio.create_task(process_event_async(event_data))
        
        # Immediate response
        return jsonify({'status': 'received', 'delivery_id': delivery_id}), 200
        
    except Exception as e:
        logger.error(f'Webhook processing error: {e}')
        return jsonify({'error': 'Internal server error'}), 500

async def process_event_async(event_data: Dict[str, Any]):
    """Process webhook event asynchronously."""
    event_type = event_data.get('event')
    
    try:
        if event_type == 'deployment.completed':
            await handle_deployment_completed(event_data)
        elif event_type == 'deployment.failed':
            await handle_deployment_failed(event_data)
        elif event_type == 'security.vulnerability_found':
            await handle_vulnerability_found(event_data)
        elif event_type == 'circuit_breaker.opened':
            await handle_circuit_breaker_opened(event_data)
        else:
            logger.info(f'Unhandled event type: {event_type}')
            
    except Exception as e:
        logger.error(f'Error processing event {event_type}: {e}')

async def handle_deployment_completed(event_data: Dict[str, Any]):
    """Handle successful deployment completion."""
    data = event_data['data']
    
    # Send notification
    await send_slack_notification(
        channel='#deployments',
        message=f"🚀 Deployment {data['version']} completed successfully!",
        details={
            'Application': data['application_name'],
            'Environment': data['environment'],
            'Duration': f"{data['duration_seconds']}s"
        }
    )
    
    # Update deployment tracking
    await update_deployment_status(data['deployment_id'], 'completed')

async def handle_deployment_failed(event_data: Dict[str, Any]):
    """Handle deployment failure."""
    data = event_data['data']
    
    # Send alert
    await send_slack_alert(
        channel='#alerts',
        message=f"❌ Deployment {data['version']} failed",
        error=data['error'],
        mention=['@oncall']
    )
    
    # Create incident ticket
    await create_incident_ticket(
        title=f"Deployment failure: {data['application_name']} {data['version']}",
        description=data['error']['message'],
        severity='high'
    )

async def handle_vulnerability_found(event_data: Dict[str, Any]):
    """Handle security vulnerability detection."""
    data = event_data['data']
    vuln = data['vulnerability']
    
    if vuln['severity'] in ['critical', 'high']:
        await send_security_alert(
            vulnerability=vuln,
            target=data['target'],
            remediation=data['remediation']
        )

async def handle_circuit_breaker_opened(event_data: Dict[str, Any]):
    """Handle circuit breaker opening."""
    data = event_data['data']
    
    await send_incident_alert(
        service=data['breaker_name'],
        failure_rate=data['metrics']['failure_rate'],
        consecutive_failures=data['metrics']['consecutive_failures']
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Testing Webhooks

### Test Endpoint

Use a test service like ngrok or RequestBin to test webhooks during development:

```bash
# Install ngrok
npm install -g ngrok

# Expose local development server
ngrok http 8080

# Use the ngrok URL for webhook registration
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/webhooks \
  -d '{
    "url": "https://abc123.ngrok.io/webhooks/code",
    "events": ["deployment.completed"],
    "secret": "test-secret"
  }'
```

### Manual Testing

Trigger events manually to test webhook delivery:

```bash
# Trigger a test deployment
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/deployments \
  -d '{
    "application_name": "test-app",
    "environment": "development", 
    "deployment_type": "docker",
    "source": {
      "type": "docker_image",
      "location": "nginx:latest"
    }
  }'
```

### Webhook Testing Tools

1. **ngrok**: Expose local servers to the internet
2. **RequestBin**: Capture and inspect webhook requests
3. **Postman Mock Server**: Mock webhook endpoints
4. **webhook.site**: Online webhook testing service

This comprehensive webhook documentation provides everything needed to integrate with CODE's event system and build responsive, event-driven applications.