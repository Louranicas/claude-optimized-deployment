# Secret Management Guide

This guide explains how to use the HashiCorp Vault integration for managing secrets in the Claude Optimized Deployment project.

## Overview

The project uses HashiCorp Vault as the primary secret management solution with automatic fallback to environment variables for development environments. This provides:

- **Centralized secret storage** - All secrets in one secure location
- **Access control** - Fine-grained permissions for different services
- **Audit logging** - Track who accessed which secrets when
- **Secret rotation** - Easy to update secrets without code changes
- **Encryption at rest** - Secrets are encrypted in Vault storage
- **Development flexibility** - Falls back to env vars when Vault isn't available

## Architecture

```
┌─────────────────┐
│   Application   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SecretsManager  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ HashiCorp Vault │ ←──→│ Env Variables   │
│   (Primary)     │     │   (Fallback)    │
└─────────────────┘     └─────────────────┘
```

## Quick Start

### 1. Install Vault

Using Docker:
```bash
docker run -d \
  --name vault \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=dev-token' \
  vault:latest
```

Or install locally:
```bash
# macOS
brew install vault

# Ubuntu/Debian
sudo apt-get install vault
```

### 2. Setup Vault

Run the setup script:
```bash
./scripts/setup_vault.sh
```

This will:
- Enable the KV v2 secret engine
- Create the secret structure
- Set up access policies
- Generate tokens for the application

### 3. Configure Application

Update your `.env` file:
```env
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=<token-from-setup-script>
```

### 4. Migrate Existing Secrets

If you have existing environment variables:
```bash
python scripts/migrate_secrets_to_vault.py --env-file .env
```

## Usage in Code

### Basic Usage

```python
from src.core.secrets_manager import get_secret

# Get a single secret
db_url = get_secret("database/connection", "url")

# Get all secrets at a path
db_config = get_secret("database/connection")
# Returns: {"host": "...", "port": "...", "user": "...", ...}
```

### Using the SecretsManager Class

```python
from src.core.secrets_manager import SecretsManager

# Initialize with custom settings
secrets = SecretsManager(
    vault_url="https://vault.company.com",
    vault_token="s.abcdef123456",
    cache_ttl=600,  # Cache for 10 minutes
    enable_fallback=True  # Fall back to env vars
)

# Get a secret
api_key = secrets.get_secret("api-keys/openai", "key")

# Set a secret
secrets.set_secret("api-keys/custom", {"key": "new-value"})

# List secrets
keys = secrets.list_secrets("api-keys")
```

### Convenience Functions

The module provides convenience functions for common secrets:

```python
from src.core.secrets_manager import (
    get_database_url,
    get_api_key,
    get_jwt_secret
)

# Get database URL
db_url = get_database_url()

# Get API key for a service
openai_key = get_api_key("openai")

# Get JWT secret
jwt_secret = get_jwt_secret()
```

## Secret Organization

Secrets are organized in a hierarchical structure:

```
secret/
├── database/
│   ├── connection/     # DB connection details
│   │   ├── url        # Full connection URL
│   │   ├── host       # Database host
│   │   ├── port       # Database port
│   │   ├── user       # Database user
│   │   ├── password   # Database password
│   │   └── name       # Database name
│   └── pool/          # Connection pool config
│       ├── size       # Pool size
│       ├── max_overflow
│       └── timeout
├── auth/
│   ├── jwt/           # JWT configuration
│   │   ├── secret     # JWT signing secret
│   │   └── algorithm  # JWT algorithm
│   └── app/           # App-level secrets
│       └── secret     # Application secret key
├── api-keys/          # External API keys
│   ├── anthropic/
│   │   └── key
│   ├── openai/
│   │   └── key
│   └── google/
│       └── key
├── cache/
│   └── redis/         # Redis configuration
│       ├── host
│       ├── port
│       └── password
└── monitoring/        # Monitoring config
    ├── prometheus/
    └── grafana/
```

## Environment Variable Fallback

When Vault is not available (e.g., in development), the system falls back to environment variables using this mapping:

| Vault Path | Environment Variable |
|------------|---------------------|
| `database/connection/url` | `DATABASE_URL` |
| `database/connection/host` | `DB_HOST` |
| `database/connection/port` | `DB_PORT` |
| `database/pool/size` | `DB_POOL_SIZE` |
| `auth/jwt/secret` | `JWT_SECRET_KEY` |
| `api-keys/anthropic/key` | `ANTHROPIC_API_KEY` |
| `api-keys/openai/key` | `OPENAI_API_KEY` |

## Security Features

### 1. Encrypted Cache

Secrets are cached locally with encryption:
- Uses machine-specific encryption keys
- Configurable TTL (default: 5 minutes)
- Automatic cache invalidation on updates

### 2. Automatic Token Renewal

The Vault token is automatically renewed to prevent expiration:
- Renewal happens every hour
- Logs warnings if renewal fails

### 3. Access Control

Use Vault policies to control access:

```hcl
# Read-only access to API keys
path "secret/data/api-keys/*" {
  capabilities = ["read"]
}

# Full access to database secrets
path "secret/data/database/*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

### 4. Audit Logging

Enable Vault audit logging:
```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

## Production Deployment

### 1. High Availability Setup

Use Vault's HA mode with Consul backend:
```hcl
storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
}

ha_enabled = true
```

### 2. Auto-Unseal

Configure auto-unseal using AWS KMS:
```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}
```

### 3. Authentication Methods

Instead of tokens, use:

- **AppRole** for applications
- **Kubernetes Auth** for K8s deployments
- **AWS IAM** for AWS services

Example AppRole setup:
```bash
# Enable AppRole
vault auth enable approle

# Create role
vault write auth/approle/role/myapp \
    token_policies="app-read,database-read" \
    token_ttl=1h \
    token_max_ttl=4h

# Get credentials
ROLE_ID=$(vault read -field=role_id auth/approle/role/myapp/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/myapp/secret-id)
```

### 4. Secret Rotation

Implement automatic rotation:
```python
import asyncio
from datetime import datetime, timedelta

async def rotate_database_password():
    """Rotate database password every 30 days."""
    while True:
        # Generate new password
        new_password = generate_secure_password()
        
        # Update in database
        await update_database_password(new_password)
        
        # Update in Vault
        secrets_manager.set_secret("database/connection", {
            "password": new_password
        })
        
        # Wait 30 days
        await asyncio.sleep(30 * 24 * 60 * 60)
```

## Troubleshooting

### Common Issues

1. **Vault not accessible**
   ```
   VaultConnectionError: Cannot connect to Vault
   ```
   - Check VAULT_ADDR is correct
   - Ensure Vault is running
   - Verify network connectivity

2. **Authentication failed**
   ```
   Failed to authenticate with Vault
   ```
   - Check VAULT_TOKEN is valid
   - Verify token hasn't expired
   - Ensure token has correct policies

3. **Secret not found**
   ```
   SecretNotFoundError: Secret not found: api-keys/service
   ```
   - Verify secret exists in Vault
   - Check fallback environment variable
   - Ensure correct path and key

### Debug Mode

Enable debug logging:
```python
import logging
logging.getLogger("src.core.secrets_manager").setLevel(logging.DEBUG)
```

## Migration Guide

### From Environment Variables

1. Export current mapping:
   ```bash
   python scripts/migrate_secrets_to_vault.py --export-mapping env_mapping.json
   ```

2. Review and customize mapping

3. Run migration:
   ```bash
   python scripts/migrate_secrets_to_vault.py --mapping-file env_mapping.json
   ```

### From Other Secret Stores

1. Export secrets from current system
2. Transform to Vault format
3. Import using the Vault CLI or API

## Best Practices

1. **Never commit secrets** - Use Vault or environment variables
2. **Use least privilege** - Grant minimal required permissions
3. **Rotate regularly** - Set up automatic rotation for sensitive secrets
4. **Monitor access** - Enable audit logging and review regularly
5. **Backup Vault** - Regular snapshots of Vault data
6. **Use namespaces** - Separate environments (dev/staging/prod)
7. **Enable versioning** - Keep history of secret changes

## Reference

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Python Client (HVAC)](https://hvac.readthedocs.io/)
- [Vault Best Practices](https://learn.hashicorp.com/tutorials/vault/production-hardening)