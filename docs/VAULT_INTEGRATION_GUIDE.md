# HashiCorp Vault Integration Guide

## Overview

The CODE project includes a comprehensive HashiCorp Vault integration for secure secret management with automatic rotation, caching, and compliance features.

## Architecture

### Components

1. **Enhanced Vault Client** (`src/core/vault_client.py`)
   - Connection pooling for high performance
   - Built-in caching with TTL
   - Automatic retry and error handling
   - Health monitoring and metrics

2. **Secrets Manager** (`src/core/secrets_manager.py`)
   - Unified interface for secret access
   - Environment variable fallback
   - Integration with enhanced Vault client
   - Thread-safe operations

3. **Rotation Manager** (`src/core/secret_rotation_manager.py`)
   - Automatic secret rotation based on policies
   - Scheduled rotation with maintenance windows
   - Approval workflows for sensitive secrets
   - Compliance tracking and reporting

4. **Audit Integration** (`src/core/secrets_audit.py`)
   - Comprehensive audit logging
   - Anomaly detection
   - Compliance reporting
   - Access pattern analysis

## Quick Start

### 1. Start Vault in Development Mode

```bash
# Using Docker Compose
docker-compose -f docker-compose.vault.yml up -d

# Using standalone script
./scripts/vault_init.sh
```

### 2. Initialize Vault

```bash
# Run the Python setup script
python scripts/vault_setup.py

# Or use the shell script for basic setup
./scripts/vault_init.sh
```

### 3. Configure Application

Create `.env` file with Vault credentials:

```env
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=dev-only-token
VAULT_NAMESPACE=
```

### 4. Use in Code

```python
from src.core.secrets_manager import get_secret, set_secret

# Get a secret
db_config = get_secret("app/database")
api_key = get_secret("app/api-keys/openai", "key")

# Set a secret
set_secret("app/new-secret", {
    "username": "user",
    "password": "secure-password"
})
```

## Features

### 1. Secret Management

#### Basic Operations

```python
from src.core.vault_client import EnhancedVaultClient, VaultConfig

# Initialize client
config = VaultConfig(
    url="http://localhost:8200",
    token="your-token"
)
client = EnhancedVaultClient(config)

# Write secret
client.write_secret("app/api/key", {
    "key": "sk-1234567890",
    "created": "2024-01-01"
})

# Read secret
data = client.read_secret("app/api/key")
print(data["key"])

# Delete secret
client.delete_secret("app/api/key")
```

#### Versioning

```python
# Read specific version
data = client.read_secret("app/api/key", version=2)

# Get metadata
metadata = client.get_secret_metadata("app/api/key")
print(f"Current version: {metadata.version}")
print(f"Created: {metadata.created_time}")
```

### 2. Automatic Rotation

#### Enable Rotation

```python
from datetime import timedelta
from src.core.vault_client import rotate_api_key

# Enable automatic rotation
client.enable_automatic_rotation(
    path="app/api-keys/service",
    interval=timedelta(days=90),
    rotation_func=rotate_api_key
)
```

#### Custom Rotation Functions

```python
def rotate_custom_secret(current: Dict[str, Any]) -> Dict[str, Any]:
    """Custom rotation logic."""
    new_data = current.copy()
    new_data["password"] = generate_secure_password()
    new_data["rotated_at"] = datetime.utcnow().isoformat()
    new_data["old_password"] = current.get("password")
    return new_data

client.enable_automatic_rotation(
    path="app/custom/secret",
    interval=timedelta(days=30),
    rotation_func=rotate_custom_secret
)
```

### 3. Caching

Caching is enabled by default with configurable TTL:

```python
config = VaultConfig(
    enable_cache=True,
    cache_ttl=300,  # 5 minutes
    cache_size=1000  # Max entries
)
```

### 4. High Availability

The client includes connection pooling and automatic failover:

```python
config = VaultConfig(
    enable_ha=True,
    ha_discover_nodes=True,
    max_retries=3,
    retry_delay=1.0
)
```

## Secret Types and Rotation Policies

### Default Rotation Intervals

| Secret Type | Rotation Interval | Auto-Rotate | Requires Approval |
|-------------|------------------|-------------|-------------------|
| API Keys | 90 days | Yes | No |
| Database Passwords | 60 days | No | Yes |
| Service Tokens | 30 days | Yes | No |
| Encryption Keys | 365 days | No | Yes |
| JWT Secrets | 180 days | Yes | No |
| OAuth Secrets | 365 days | No | Yes |
| SSH Keys | 365 days | No | Yes |
| TLS Certificates | 365 days | Yes | No |

### Customizing Rotation Policies

Edit `src/core/secrets_rotation_config.py`:

```python
from datetime import timedelta
from src.core.secrets_rotation_config import RotationPolicy, SecretType

custom_policy = RotationPolicy(
    secret_type=SecretType.API_KEY,
    rotation_interval=timedelta(days=60),
    grace_period=timedelta(days=7),
    auto_rotate=True,
    requires_approval=False,
    max_versions=3
)
```

## Security Best Practices

### 1. Authentication

Use AppRole authentication for applications:

```python
# Generate AppRole credentials
role_id, secret_id = setup_approle_auth()

# Authenticate with AppRole
client = hvac.Client()
client.auth.approle.login(
    role_id=role_id,
    secret_id=secret_id
)
```

### 2. Access Control

Apply least-privilege policies:

```hcl
# Application policy
path "secret/data/app/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

### 3. Encryption at Rest

All cached secrets are encrypted:

```python
# Encryption is automatic for cached values
manager = SecretsManager(enable_cache=True)
secret = manager.get_secret("app/sensitive")  # Encrypted in cache
```

### 4. Audit Logging

All secret access is logged:

```python
from src.core.secrets_audit import get_secret_audit_logger

audit_logger = get_secret_audit_logger()
report = await audit_logger.generate_audit_report(
    start_date=datetime.utcnow() - timedelta(days=7),
    end_date=datetime.utcnow()
)
```

## Monitoring and Alerts

### Prometheus Metrics

The integration exposes metrics for monitoring:

- `vault_operations_total`: Total operations by type and status
- `vault_operation_duration_seconds`: Operation latency
- `vault_cache_hits_total`: Cache hit rate
- `vault_rotation_completed_total`: Rotation success/failure
- `secret_rotation_overdue_total`: Overdue rotations

### Grafana Dashboard

Import the dashboard from `monitoring/dashboards/vault_dashboard.json`

### Alerts

Configure alerts for:
- Failed rotations
- Overdue rotations
- Authentication failures
- High error rates

## Troubleshooting

### Common Issues

1. **Connection Failed**
   ```bash
   # Check Vault status
   vault status
   
   # Verify environment variables
   echo $VAULT_ADDR
   echo $VAULT_TOKEN
   ```

2. **Permission Denied**
   ```bash
   # Check token policies
   vault token lookup
   
   # List token capabilities
   vault token capabilities secret/app/database
   ```

3. **Secret Not Found**
   ```bash
   # List secrets
   vault kv list secret/app
   
   # Check if using correct path
   vault kv get secret/app/database
   ```

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger("src.core.vault_client").setLevel(logging.DEBUG)
```

## Testing

Run integration tests:

```bash
# Start Vault
docker-compose -f docker-compose.vault.yml up -d

# Run tests
python tests/test_vault_integration.py

# Run with pytest
pytest tests/test_vault_integration.py -v
```

## Production Deployment

### 1. Initialize Production Vault

```bash
# Initialize with 5 key shares, threshold of 3
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault (requires 3 keys)
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>
```

### 2. Enable TLS

Configure TLS in `vault/config/vault-prod.hcl`:

```hcl
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
}
```

### 3. High Availability Setup

Use Consul or integrated storage:

```hcl
storage "consul" {
  address = "consul:8500"
  path    = "vault/"
}

ha_enabled = true
```

### 4. Backup Strategy

```bash
# Backup Vault data
vault operator raft snapshot save backup.snap

# Restore from backup
vault operator raft snapshot restore backup.snap
```

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Get secrets from Vault
  env:
    VAULT_ADDR: ${{ secrets.VAULT_ADDR }}
    VAULT_ROLE_ID: ${{ secrets.VAULT_ROLE_ID }}
    VAULT_SECRET_ID: ${{ secrets.VAULT_SECRET_ID }}
  run: |
    # Authenticate
    vault write auth/approle/login \
      role_id=$VAULT_ROLE_ID \
      secret_id=$VAULT_SECRET_ID
    
    # Get secrets
    DB_PASSWORD=$(vault kv get -field=password secret/app/database)
    API_KEY=$(vault kv get -field=key secret/app/api-keys/service)
```

### Docker Integration

```dockerfile
# Multi-stage build to inject secrets
FROM vault:latest as vault
ARG VAULT_TOKEN
RUN vault kv get -format=json secret/app/config > /tmp/config.json

FROM python:3.11
COPY --from=vault /tmp/config.json /app/config.json
```

## Migration Guide

### From Environment Variables

```python
# Before
api_key = os.getenv("OPENAI_API_KEY")

# After
api_key = get_secret("app/api-keys/openai", "key")
```

### From Config Files

```python
# Before
with open("config.json") as f:
    config = json.load(f)

# After
config = get_secret("app/config")
```

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review logs in `vault/logs/`
3. Contact the security team
4. Open an issue in the project repository