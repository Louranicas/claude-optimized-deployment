# Secret Management Quick Reference

## Setup (One-time)

1. **Start Vault** (development mode):
   ```bash
   docker-compose -f docker-compose.vault.yml up -d
   ```

2. **Initialize Vault**:
   ```bash
   ./scripts/setup_vault.sh
   ```

3. **Set environment variables**:
   ```bash
   export VAULT_ADDR=http://localhost:8200
   export VAULT_TOKEN=<token-from-setup>
   ```

## Common Operations

### Get a Secret

```python
from src.core.secrets_manager import get_secret

# Get a single value
api_key = get_secret("api-keys/openai", "key")

# Get all values at a path
db_config = get_secret("database/connection")
```

### Set a Secret

```python
from src.core.secrets_manager import set_secret

# Set a secret
set_secret("api-keys/custom", {"key": "my-api-key"})
```

### Use Convenience Functions

```python
from src.core.secrets_manager import get_database_url, get_api_key, get_jwt_secret

# Database URL
db_url = get_database_url()

# API keys
openai_key = get_api_key("openai")
anthropic_key = get_api_key("anthropic")

# JWT secret
jwt_secret = get_jwt_secret()
```

## Environment Variable Mapping

| Secret | Vault Path | Environment Variable |
|--------|------------|---------------------|
| Database URL | `database/connection/url` | `DATABASE_URL` |
| JWT Secret | `auth/jwt/secret` | `JWT_SECRET_KEY` |
| Anthropic API | `api-keys/anthropic/key` | `ANTHROPIC_API_KEY` |
| OpenAI API | `api-keys/openai/key` | `OPENAI_API_KEY` |

## Migration

Migrate existing `.env` file:
```bash
python scripts/migrate_secrets_to_vault.py --env-file .env
```

## Testing

Run with mock Vault (no real Vault needed):
```python
from unittest.mock import patch

with patch('src.core.secrets_manager.get_secret', return_value="mock-value"):
    # Your test code
```

## Troubleshooting

- **Vault not running**: Check `docker ps` and start with `docker-compose -f docker-compose.vault.yml up -d`
- **Authentication failed**: Re-run `./scripts/setup_vault.sh` to get a new token
- **Secret not found**: Falls back to environment variables automatically

## Production Checklist

- [ ] Enable TLS on Vault
- [ ] Use AppRole or Kubernetes auth instead of tokens
- [ ] Enable audit logging
- [ ] Set up auto-unseal
- [ ] Configure secret rotation
- [ ] Use separate namespaces for environments
- [ ] Regular backups of Vault data