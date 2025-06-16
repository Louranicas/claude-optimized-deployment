#!/bin/bash
# Setup HashiCorp Vault for the Claude Optimized Deployment project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
VAULT_ADDR=${VAULT_ADDR:-"http://localhost:8200"}
VAULT_NAMESPACE=${VAULT_NAMESPACE:-""}

echo -e "${GREEN}Setting up HashiCorp Vault for Claude Optimized Deployment${NC}"
echo "Vault Address: $VAULT_ADDR"

# Check if Vault is running
if ! vault status >/dev/null 2>&1; then
    echo -e "${RED}Vault is not running or not accessible at $VAULT_ADDR${NC}"
    echo "Please start Vault first. You can use Docker:"
    echo "  docker run -d --name vault -p 8200:8200 vault:latest"
    exit 1
fi

# Check if we're authenticated
if ! vault token lookup >/dev/null 2>&1; then
    echo -e "${YELLOW}Not authenticated to Vault. Please login:${NC}"
    vault login
fi

echo -e "${GREEN}Enabling KV v2 secret engine...${NC}"
vault secrets enable -version=2 -path=secret kv || echo "KV v2 already enabled"

echo -e "${GREEN}Creating secret paths structure...${NC}"

# Database secrets
vault kv put secret/database/connection \
    host="localhost" \
    port="5432" \
    user="code_user" \
    password="change_me_in_production" \
    name="code_deployment" \
    url="postgresql://code_user:change_me_in_production@localhost:5432/code_deployment"

vault kv put secret/database/pool \
    size="20" \
    max_overflow="10" \
    timeout="30" \
    recycle="3600" \
    echo="false"

# Auth/JWT secrets
vault kv put secret/auth/jwt \
    secret="$(openssl rand -base64 64)" \
    algorithm="HS256" \
    access_token_expire_minutes="15" \
    refresh_token_expire_days="30"

vault kv put secret/auth/app \
    secret="$(openssl rand -base64 32)"

# API Keys (placeholders - update with real keys)
vault kv put secret/api-keys/anthropic \
    key="your-anthropic-api-key-here"

vault kv put secret/api-keys/openai \
    key="your-openai-api-key-here"

vault kv put secret/api-keys/google \
    key="your-google-api-key-here"

# Redis configuration
vault kv put secret/cache/redis \
    host="localhost" \
    port="6379" \
    password="" \
    db="0"

# Monitoring
vault kv put secret/monitoring/prometheus \
    port="9090" \
    scrape_interval="15s"

vault kv put secret/monitoring/grafana \
    port="3000" \
    admin_user="admin" \
    admin_password="$(openssl rand -base64 12)"

echo -e "${GREEN}Creating Vault policies...${NC}"

# Application read policy
cat <<EOF | vault policy write app-read -
path "secret/data/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/*" {
  capabilities = ["list"]
}
EOF

# Application write policy (for admin operations)
cat <<EOF | vault policy write app-write -
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/*" {
  capabilities = ["list", "delete"]
}
EOF

# Database-specific policy
cat <<EOF | vault policy write database-read -
path "secret/data/database/*" {
  capabilities = ["read", "list"]
}
EOF

# API keys policy
cat <<EOF | vault policy write api-keys-read -
path "secret/data/api-keys/*" {
  capabilities = ["read", "list"]
}
EOF

echo -e "${GREEN}Creating tokens for different services...${NC}"

# Create token for the application (with read access)
APP_TOKEN=$(vault token create -policy=app-read -policy=database-read -policy=api-keys-read -format=json | jq -r '.auth.client_token')
echo -e "${YELLOW}Application Token: $APP_TOKEN${NC}"
echo "Save this token in your .env file as VAULT_TOKEN=$APP_TOKEN"

# Create admin token (with write access)
ADMIN_TOKEN=$(vault token create -policy=app-write -format=json | jq -r '.auth.client_token')
echo -e "${YELLOW}Admin Token (for migrations): $ADMIN_TOKEN${NC}"

echo -e "${GREEN}Vault setup complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Update your .env file with:"
echo "   VAULT_ADDR=$VAULT_ADDR"
echo "   VAULT_TOKEN=$APP_TOKEN"
echo ""
echo "2. Update API keys in Vault:"
echo "   vault kv put secret/api-keys/anthropic key=your-actual-key"
echo "   vault kv put secret/api-keys/openai key=your-actual-key"
echo ""
echo "3. Run the migration script to import existing secrets:"
echo "   python scripts/migrate_secrets_to_vault.py --env-file .env"
echo ""
echo "4. For production, consider:"
echo "   - Using Vault's auth methods (AppRole, Kubernetes, etc.)"
echo "   - Enabling audit logging"
echo "   - Setting up auto-unseal"
echo "   - Implementing secret rotation"