// Production Vault Configuration

// Storage backend - using Consul for HA
storage "consul" {
  address = "consul:8500"
  path    = "vault/"
}

// Listener configuration
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = "true"  // Enable TLS in production!
  
  // Uncomment for TLS (recommended for production)
  // tls_cert_file = "/vault/certs/vault.crt"
  // tls_key_file  = "/vault/certs/vault.key"
}

// Enable UI
ui = true

// Cluster configuration
cluster_addr = "http://127.0.0.1:8201"
api_addr     = "http://127.0.0.1:8200"

// Performance tuning
max_lease_ttl     = "768h"    // 32 days
default_lease_ttl = "768h"    // 32 days

// Logging
log_level = "info"
log_format = "json"

// Telemetry for monitoring
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

// Auto-unseal using AWS KMS (optional)
// seal "awskms" {
//   region     = "us-east-1"
//   kms_key_id = "alias/vault-unseal"
// }

// Auto-unseal using Azure Key Vault (optional)
// seal "azurekeyvault" {
//   tenant_id      = "00000000-0000-0000-0000-000000000000"
//   client_id      = "00000000-0000-0000-0000-000000000000"
//   client_secret  = "your-client-secret"
//   vault_name     = "your-key-vault"
//   key_name       = "vault-unseal"
// }