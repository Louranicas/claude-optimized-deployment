# HashiCorp Vault Setup Guide for Claude Deployment

This guide provides instructions for setting up HashiCorp Vault to securely manage secrets for the Claude deployment.

## Prerequisites

1. Kubernetes cluster with `kubectl` configured
2. Helm 3.x installed
3. External Secrets Operator installed
4. Appropriate RBAC permissions

## Installation Steps

### 1. Install HashiCorp Vault

```bash
# Add HashiCorp Helm repository
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

# Create vault namespace
kubectl create namespace vault

# Install Vault with HA configuration
helm install vault hashicorp/vault \
  --namespace vault \
  --set server.ha.enabled=true \
  --set server.ha.replicas=3 \
  --set server.affinity="podAntiAffinity" \
  --set ui.enabled=true \
  --set injector.enabled=true
```

### 2. Initialize and Unseal Vault

```bash
# Initialize Vault
kubectl exec -n vault vault-0 -- vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json > cluster-keys.json

# Unseal each Vault pod
VAULT_UNSEAL_KEY_1=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[0]")
VAULT_UNSEAL_KEY_2=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[1]")
VAULT_UNSEAL_KEY_3=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[2]")

# Unseal vault-0
kubectl exec -n vault vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY_1
kubectl exec -n vault vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY_2
kubectl exec -n vault vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY_3

# Repeat for vault-1 and vault-2
```

### 3. Configure Kubernetes Authentication

```bash
# Get root token
VAULT_ROOT_TOKEN=$(cat cluster-keys.json | jq -r ".root_token")

# Configure Kubernetes auth method
kubectl exec -n vault vault-0 -- vault login $VAULT_ROOT_TOKEN
kubectl exec -n vault vault-0 -- vault auth enable kubernetes

# Configure Kubernetes auth
kubectl exec -n vault vault-0 -- vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
  token_reviewer_jwt="$(kubectl exec -n vault vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  kubernetes_ca_cert="$(kubectl exec -n vault vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"
```

### 4. Create Vault Policy

```bash
# Create policy for Claude deployment
cat <<EOF | kubectl exec -n vault -i vault-0 -- vault policy write claude-deployment -
path "secret/data/claude-deployment/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/claude-deployment/*" {
  capabilities = ["read", "list"]
}
EOF

# Create Kubernetes auth role
kubectl exec -n vault vault-0 -- vault write auth/kubernetes/role/claude-deployment \
  bound_service_account_names=claude-vault-auth \
  bound_service_account_namespaces=claude-deployment \
  policies=claude-deployment \
  ttl=24h
```

### 5. Install External Secrets Operator

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets \
  external-secrets/external-secrets \
  --namespace external-secrets-system \
  --create-namespace \
  --set installCRDs=true
```

### 6. Store Secrets in Vault

```bash
# Enable KV v2 secrets engine
kubectl exec -n vault vault-0 -- vault secrets enable -path=secret kv-v2

# Store database credentials
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/database \
  database-url="postgresql://user:password@host:5432/dbname" \
  username="claude_user" \
  password="$(openssl rand -base64 32)" \
  host="claude-deployment-db" \
  port="5432" \
  database="claude_deployment"

# Store Redis credentials
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/redis \
  redis-url="redis://claude-deployment-redis:6379/0" \
  password="$(openssl rand -base64 32)"

# Store JWT secret
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/auth \
  jwt-secret="$(openssl rand -base64 64)"

# Store API keys (replace with actual keys)
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/api-keys \
  openai-api-key="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx" \
  anthropic-api-key="sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx" \
  google-api-key="AIzaxxxxxxxxxxxxxxxxxxxxxxxx"

# Store monitoring credentials
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/monitoring \
  grafana-admin-password="$(openssl rand -base64 16)" \
  prometheus-basic-auth="prometheus:$(openssl rand -base64 16)"

# Store TLS certificates (replace with actual certificates)
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/tls \
  tls.crt="$(cat /path/to/tls.crt | base64)" \
  tls.key="$(cat /path/to/tls.key | base64)"

# Store container registry credentials
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/registry \
  dockerconfigjson='{"auths":{"registry.example.com":{"username":"user","password":"pass","auth":"base64"}}}'

# Store webhook secrets
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/webhooks \
  github-webhook-secret="$(openssl rand -hex 32)" \
  slack-webhook-url="https://hooks.slack.com/services/..." \
  pagerduty-api-key="xxxxxxxxxxxxxxxxxxxxxxxx"

# Store backup credentials
kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/backup \
  aws-access-key-id="AKIAIOSFODNN7EXAMPLE" \
  aws-secret-access-key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  s3-bucket-name="claude-deployment-backups" \
  backup-encryption-key="$(openssl rand -base64 32)"
```

## Security Best Practices

### 1. Enable Audit Logging

```bash
kubectl exec -n vault vault-0 -- vault audit enable file file_path=/vault/logs/audit.log
```

### 2. Configure Auto-Unseal

Use AWS KMS, GCP KMS, or Azure Key Vault for auto-unsealing:

```yaml
# values.yaml for Helm
server:
  seal:
    awskms:
      region: "us-east-1"
      kms_key_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 3. Enable Secret Rotation

```bash
# Enable periodic rotation
kubectl exec -n vault vault-0 -- vault write sys/policies/password/claude-deployment \
  policy="length=32 rule=charset:[:alnum:]"

# Configure automatic rotation
kubectl exec -n vault vault-0 -- vault write secret/config/claude-deployment/database \
  rotation_period="30d"
```

### 4. Backup and Disaster Recovery

```bash
# Enable snapshots
kubectl exec -n vault vault-0 -- vault operator raft snapshot save backup.snap

# Store in S3
aws s3 cp backup.snap s3://vault-backups/$(date +%Y%m%d_%H%M%S)_backup.snap
```

### 5. Monitoring and Alerting

Configure Prometheus metrics:

```yaml
telemetry:
  prometheus_retention_time: "30s"
  disable_hostname: true
```

## Verification

### 1. Verify External Secrets

```bash
# Check if secrets are synced
kubectl get externalsecrets -n claude-deployment
kubectl describe externalsecret claude-deployment-db-secret -n claude-deployment

# Verify created secrets
kubectl get secrets -n claude-deployment
```

### 2. Test Secret Access

```bash
# Deploy a test pod
kubectl run -n claude-deployment test-pod --image=alpine:latest --rm -it -- sh

# Inside the pod, verify secrets are mounted
cat /vault/secrets/database
```

## Troubleshooting

### Common Issues

1. **External Secret not syncing**
   - Check Vault connectivity
   - Verify ServiceAccount permissions
   - Check Vault policy

2. **Authentication failures**
   - Verify Kubernetes auth configuration
   - Check ServiceAccount tokens

3. **Permission denied errors**
   - Review Vault policies
   - Check path permissions

### Debug Commands

```bash
# Check External Secrets Operator logs
kubectl logs -n external-secrets-system deployment/external-secrets

# Check Vault injector logs
kubectl logs -n vault deployment/vault-agent-injector

# Verify Vault status
kubectl exec -n vault vault-0 -- vault status
```

## Maintenance

### Regular Tasks

1. **Weekly**: Review audit logs
2. **Monthly**: Rotate secrets
3. **Quarterly**: Update Vault and operators
4. **Annually**: Review and update policies

### Secret Rotation Script

```bash
#!/bin/bash
# rotate-secrets.sh

SECRETS=("database" "redis" "auth" "monitoring" "backup")

for secret in "${SECRETS[@]}"; do
  echo "Rotating $secret secrets..."
  case $secret in
    database)
      kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/database \
        password="$(openssl rand -base64 32)"
      ;;
    redis)
      kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/redis \
        password="$(openssl rand -base64 32)"
      ;;
    auth)
      kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/auth \
        jwt-secret="$(openssl rand -base64 64)"
      ;;
    monitoring)
      kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/monitoring \
        grafana-admin-password="$(openssl rand -base64 16)" \
        prometheus-basic-auth="prometheus:$(openssl rand -base64 16)"
      ;;
    backup)
      kubectl exec -n vault vault-0 -- vault kv put secret/claude-deployment/backup \
        backup-encryption-key="$(openssl rand -base64 32)"
      ;;
  esac
done

echo "Secret rotation complete"
```

## Compliance

This setup meets the following compliance requirements:

- **SOC 2**: Encrypted secrets at rest and in transit
- **PCI DSS**: Strong access controls and audit logging
- **HIPAA**: Encryption and access management
- **GDPR**: Data protection and access controls

## References

- [Vault Documentation](https://www.vaultproject.io/docs)
- [External Secrets Operator](https://external-secrets.io/latest/)
- [Kubernetes Secrets Best Practices](https://kubernetes.io/docs/concepts/configuration/secret/)