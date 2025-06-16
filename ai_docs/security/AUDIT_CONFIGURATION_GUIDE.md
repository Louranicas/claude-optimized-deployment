# Audit Configuration Guide

This guide explains how to configure the secure audit logging system in the Claude Optimized Deployment project.

## Overview

The audit logging system requires a signing key to ensure the integrity and tamper-resistance of audit logs. This key is used to create HMAC signatures for each audit event.

## Security Requirements

- **Signing Key**: Must be at least 32 characters long
- **Storage**: Should be stored securely, never in version control
- **Production**: Must be provided via environment variable or secure key management

## Configuration Methods

### 1. Environment Variable (Recommended for Production)

Set the `AUDIT_SIGNING_KEY` environment variable:

```bash
export AUDIT_SIGNING_KEY='your-secure-random-key-at-least-32-chars-long'
```

### 2. Configuration File (Development Only)

For development environments, you can store the key in a file:

```bash
mkdir -p ~/.claude_deployment
echo 'your-secure-random-key-at-least-32-chars-long' > ~/.claude_deployment/audit_signing_key
chmod 600 ~/.claude_deployment/audit_signing_key
```

### 3. Generate a Secure Key

Use the provided utility to generate a secure random key:

```bash
python -m src.auth.audit_config
```

This will:
- Generate a cryptographically secure random key
- Save it to `~/.claude_deployment/audit_signing_key`
- Display the key for copying to environment variables

## Production Deployment

### Docker

Add to your Docker environment:

```dockerfile
ENV AUDIT_SIGNING_KEY=${AUDIT_SIGNING_KEY}
```

### Kubernetes

Use a Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: audit-config
type: Opaque
data:
  signing-key: <base64-encoded-key>
```

Then reference in your deployment:

```yaml
env:
  - name: AUDIT_SIGNING_KEY
    valueFrom:
      secretKeyRef:
        name: audit-config
        key: signing-key
```

### AWS/Cloud Deployment

Use your cloud provider's secret management service:

- **AWS**: AWS Secrets Manager or Systems Manager Parameter Store
- **Azure**: Azure Key Vault
- **GCP**: Google Secret Manager

## Testing

For unit tests, use the provided test utilities:

```python
from src.auth.test_utils import get_test_audit_logger

# Create a test logger with auto-generated signing key
audit_logger = get_test_audit_logger()
```

## Validation

The system validates the signing key:

1. **Required**: Cannot be None or empty
2. **Length**: Must be at least 32 characters
3. **Not Default**: Cannot use "default-signing-key"

## Error Handling

If the signing key is not configured properly, you'll see:

```
ValueError: signing_key is required for audit log integrity
```

Or:

```
ValueError: No audit signing key configured. Set AUDIT_SIGNING_KEY environment variable
```

## Best Practices

1. **Key Generation**: Use cryptographically secure random generation
2. **Key Rotation**: Implement regular key rotation in production
3. **Key Storage**: Never commit keys to version control
4. **Key Access**: Limit access to the signing key
5. **Monitoring**: Monitor audit log generation for failures

## Example Integration

```python
from src.auth.audit_config import get_audit_logger

# Get configured logger
audit_logger = get_audit_logger()

# Log an event
await audit_logger.log_event(
    event_type=AuditEventType.LOGIN_SUCCESS,
    user_id="user123",
    ip_address="192.168.1.1",
    details={"method": "password"}
)
```

## Troubleshooting

### Key Not Found

Check that one of these is configured:
- `AUDIT_SIGNING_KEY` environment variable
- `~/.claude_deployment/audit_signing_key` file

### Key Too Short

Ensure your key is at least 32 characters. Generate a new one:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Permission Denied

If using file storage, ensure proper permissions:

```bash
chmod 600 ~/.claude_deployment/audit_signing_key
```