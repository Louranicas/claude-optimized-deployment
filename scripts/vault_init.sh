#!/bin/bash

# HashiCorp Vault Initialization Script
# This script initializes and configures Vault for the CODE project

set -e

# Configuration
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_VERSION="${VAULT_VERSION:-1.15.4}"
VAULT_DATA_DIR="${VAULT_DATA_DIR:-./vault/data}"
VAULT_CONFIG_DIR="${VAULT_CONFIG_DIR:-./vault/config}"
VAULT_LOGS_DIR="${VAULT_LOGS_DIR:-./vault/logs}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Vault is installed
check_vault_installed() {
    if ! command -v vault &> /dev/null; then
        log_error "Vault is not installed. Please install Vault first."
        log_info "You can download Vault from: https://www.vaultproject.io/downloads"
        exit 1
    fi
    
    INSTALLED_VERSION=$(vault version | grep "Vault" | awk '{print $2}' | sed 's/v//')
    log_info "Vault version $INSTALLED_VERSION is installed"
}

# Create directory structure
create_directories() {
    log_info "Creating Vault directory structure..."
    
    mkdir -p "$VAULT_DATA_DIR"
    mkdir -p "$VAULT_CONFIG_DIR"
    mkdir -p "$VAULT_LOGS_DIR"
    mkdir -p "$VAULT_CONFIG_DIR/policies"
    mkdir -p "$VAULT_CONFIG_DIR/auth"
    
    log_info "Directory structure created"
}

# Generate Vault configuration
generate_vault_config() {
    log_info "Generating Vault configuration..."
    
    cat > "$VAULT_CONFIG_DIR/vault.hcl" <<EOF
# Vault server configuration

ui = true
disable_mlock = true

storage "file" {
  path = "$VAULT_DATA_DIR"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = 1  # Set to 0 for production with proper TLS certificates
  # tls_cert_file = "$VAULT_CONFIG_DIR/tls/vault.crt"
  # tls_key_file  = "$VAULT_CONFIG_DIR/tls/vault.key"
}

api_addr = "$VAULT_ADDR"
cluster_addr = "http://127.0.0.1:8201"

# Enable audit logging
# audit {
#   file {
#     path = "$VAULT_LOGS_DIR/audit.log"
#   }
# }

# Performance tuning
max_lease_ttl = "768h"       # 32 days
default_lease_ttl = "168h"   # 7 days

# High Availability (Enterprise only)
# ha_storage "consul" {
#   address = "127.0.0.1:8500"
#   path    = "vault/"
# }

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

log_level = "info"
log_format = "json"
EOF

    log_info "Vault configuration generated at $VAULT_CONFIG_DIR/vault.hcl"
}

# Generate systemd service file
generate_systemd_service() {
    log_info "Generating systemd service file..."
    
    cat > "$VAULT_CONFIG_DIR/vault.service" <<EOF
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=$VAULT_CONFIG_DIR/vault.hcl

[Service]
Type=notify
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=$VAULT_CONFIG_DIR/vault.hcl
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

    log_info "Systemd service file generated at $VAULT_CONFIG_DIR/vault.service"
    log_info "To install: sudo cp $VAULT_CONFIG_DIR/vault.service /etc/systemd/system/"
}

# Start Vault in dev mode for initial setup
start_vault_dev() {
    log_info "Starting Vault in dev mode for initial setup..."
    
    # Check if Vault is already running
    if pgrep -x "vault" > /dev/null; then
        log_warn "Vault is already running. Stopping it first..."
        pkill -x "vault"
        sleep 2
    fi
    
    # Start Vault in dev mode
    vault server -dev -dev-root-token-id="dev-only-token" &
    VAULT_PID=$!
    
    sleep 5
    
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="dev-only-token"
    
    log_info "Vault started in dev mode (PID: $VAULT_PID)"
}

# Initialize Vault policies
init_policies() {
    log_info "Initializing Vault policies..."
    
    # Admin policy
    cat > "$VAULT_CONFIG_DIR/policies/admin.hcl" <<'EOF'
# Admin policy - full access
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

    # Application policy
    cat > "$VAULT_CONFIG_DIR/policies/application.hcl" <<'EOF'
# Application policy - read access to secrets
path "secret/data/application/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/application/*" {
  capabilities = ["read", "list"]
}

# Allow token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

    # Developer policy
    cat > "$VAULT_CONFIG_DIR/policies/developer.hcl" <<'EOF'
# Developer policy - read/write access to dev secrets
path "secret/data/dev/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/dev/*" {
  capabilities = ["read", "list", "delete"]
}

# Read-only access to prod secrets
path "secret/data/prod/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/prod/*" {
  capabilities = ["read", "list"]
}
EOF

    # CI/CD policy
    cat > "$VAULT_CONFIG_DIR/policies/cicd.hcl" <<'EOF'
# CI/CD policy - deploy and rotate secrets
path "secret/data/cicd/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "secret/metadata/cicd/*" {
  capabilities = ["read", "list"]
}

# Allow creating temporary tokens
path "auth/token/create" {
  capabilities = ["create", "update"]
}
EOF

    # Apply policies
    vault policy write admin "$VAULT_CONFIG_DIR/policies/admin.hcl"
    vault policy write application "$VAULT_CONFIG_DIR/policies/application.hcl"
    vault policy write developer "$VAULT_CONFIG_DIR/policies/developer.hcl"
    vault policy write cicd "$VAULT_CONFIG_DIR/policies/cicd.hcl"
    
    log_info "Policies initialized"
}

# Enable secret engines
enable_secret_engines() {
    log_info "Enabling secret engines..."
    
    # KV v2 secret engine (main)
    vault secrets enable -version=2 -path=secret kv || log_warn "KV v2 already enabled at secret/"
    
    # Database secret engine
    vault secrets enable database || log_warn "Database secret engine already enabled"
    
    # PKI secret engine for certificates
    vault secrets enable pki || log_warn "PKI secret engine already enabled"
    
    # Transit secret engine for encryption
    vault secrets enable transit || log_warn "Transit secret engine already enabled"
    
    # Configure KV engine
    vault kv metadata put -max-versions=10 secret/
    
    log_info "Secret engines enabled"
}

# Enable auth methods
enable_auth_methods() {
    log_info "Enabling auth methods..."
    
    # AppRole auth method
    vault auth enable approle || log_warn "AppRole auth already enabled"
    
    # Kubernetes auth method
    vault auth enable kubernetes || log_warn "Kubernetes auth already enabled"
    
    # JWT/OIDC auth method
    vault auth enable jwt || log_warn "JWT auth already enabled"
    
    log_info "Auth methods enabled"
}

# Create initial secrets structure
create_initial_secrets() {
    log_info "Creating initial secrets structure..."
    
    # Application secrets
    vault kv put secret/application/database \
        host="localhost" \
        port="5432" \
        username="app_user" \
        password="$(openssl rand -base64 32)" \
        name="code_db"
    
    # API keys
    vault kv put secret/application/api-keys/openai \
        key="sk-dummy-key-replace-me" \
        organization="org-dummy"
    
    vault kv put secret/application/api-keys/anthropic \
        key="sk-ant-dummy-key-replace-me"
    
    # JWT secret
    vault kv put secret/application/auth/jwt \
        secret="$(openssl rand -base64 64)" \
        algorithm="HS256" \
        issuer="code-app"
    
    # Encryption keys
    vault kv put secret/application/encryption \
        key="$(openssl rand -base64 32)" \
        algorithm="AES-256-GCM"
    
    log_info "Initial secrets created"
}

# Configure audit logging
configure_audit() {
    log_info "Configuring audit logging..."
    
    # Enable file audit device
    vault audit enable file file_path="$VAULT_LOGS_DIR/audit.log" || log_warn "File audit already enabled"
    
    # Enable syslog audit device (optional)
    # vault audit enable syslog || log_warn "Syslog audit already enabled"
    
    log_info "Audit logging configured"
}

# Generate AppRole credentials
generate_approle_creds() {
    log_info "Generating AppRole credentials..."
    
    # Create AppRole for the application
    vault write auth/approle/role/code-app \
        token_policies="application" \
        token_ttl=1h \
        token_max_ttl=4h \
        secret_id_ttl=0 \
        secret_id_num_uses=0
    
    # Get role ID
    ROLE_ID=$(vault read -field=role_id auth/approle/role/code-app/role-id)
    
    # Generate secret ID
    SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/code-app/secret-id)
    
    # Save credentials
    cat > "$VAULT_CONFIG_DIR/approle-creds.json" <<EOF
{
  "role_id": "$ROLE_ID",
  "secret_id": "$SECRET_ID",
  "mount_path": "approle"
}
EOF
    
    chmod 600 "$VAULT_CONFIG_DIR/approle-creds.json"
    
    log_info "AppRole credentials saved to $VAULT_CONFIG_DIR/approle-creds.json"
}

# Initialize production Vault
init_production_vault() {
    log_info "Initializing production Vault..."
    
    # Initialize Vault
    INIT_OUTPUT=$(vault operator init -key-shares=5 -key-threshold=3 -format=json)
    
    # Save the output
    echo "$INIT_OUTPUT" > "$VAULT_CONFIG_DIR/vault-init.json"
    chmod 600 "$VAULT_CONFIG_DIR/vault-init.json"
    
    log_warn "IMPORTANT: Save the unseal keys and root token from $VAULT_CONFIG_DIR/vault-init.json"
    log_warn "Store them securely and separately. Delete the file after saving the keys."
    
    # Extract keys
    UNSEAL_KEY_1=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY_2=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[1]')
    UNSEAL_KEY_3=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[2]')
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
    
    # Unseal Vault
    vault operator unseal "$UNSEAL_KEY_1"
    vault operator unseal "$UNSEAL_KEY_2"
    vault operator unseal "$UNSEAL_KEY_3"
    
    # Login with root token
    vault login "$ROOT_TOKEN"
    
    log_info "Vault initialized and unsealed"
}

# Main setup function
main() {
    log_info "Starting HashiCorp Vault setup for CODE project..."
    
    check_vault_installed
    create_directories
    generate_vault_config
    generate_systemd_service
    
    # For development setup
    if [[ "${VAULT_ENV:-dev}" == "dev" ]]; then
        start_vault_dev
        enable_secret_engines
        enable_auth_methods
        init_policies
        create_initial_secrets
        configure_audit
        generate_approle_creds
        
        log_info "Development Vault setup complete!"
        log_info "Vault UI available at: http://127.0.0.1:8200"
        log_info "Login token: dev-only-token"
        
        # Keep Vault running
        log_info "Press Ctrl+C to stop Vault..."
        wait $VAULT_PID
    else
        log_info "Production setup requires manual initialization"
        log_info "1. Start Vault: vault server -config=$VAULT_CONFIG_DIR/vault.hcl"
        log_info "2. Run: $0 init-prod"
    fi
}

# Handle production initialization
if [[ "$1" == "init-prod" ]]; then
    init_production_vault
    enable_secret_engines
    enable_auth_methods
    init_policies
    create_initial_secrets
    configure_audit
    generate_approle_creds
    log_info "Production Vault setup complete!"
else
    main
fi