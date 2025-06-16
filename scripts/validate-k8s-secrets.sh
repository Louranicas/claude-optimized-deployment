#!/bin/bash

# Kubernetes Secrets Security Validation Script
# This script validates that secrets are properly configured for external management

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Kubernetes Secrets Security Validation ==="
echo ""

# Check if required tools are installed
check_tools() {
    local tools=("kubectl" "yq" "jq")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo "Please install missing tools and run again."
        exit 1
    fi
}

# Validate External Secrets CRDs
check_external_secrets_crds() {
    echo "Checking External Secrets CRDs..."
    
    if kubectl get crd externalsecrets.external-secrets.io &> /dev/null; then
        echo -e "${GREEN}✓ External Secrets CRDs installed${NC}"
    else
        echo -e "${RED}✗ External Secrets CRDs not found${NC}"
        echo "  Install External Secrets Operator first"
        return 1
    fi
}

# Check for hardcoded secrets
check_hardcoded_secrets() {
    echo ""
    echo "Scanning for hardcoded secrets in k8s/secrets.yaml..."
    
    local file="k8s/secrets.yaml"
    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ File not found: $file${NC}"
        return 1
    fi
    
    # Check for base64 encoded values that look like real secrets
    local suspicious_patterns=(
        "password"
        "secret"
        "key"
        "token"
        "credential"
    )
    
    local found_issues=0
    
    # Check if file contains actual Secret objects (should only have ExternalSecret)
    if grep -q "^kind: Secret$" "$file"; then
        echo -e "${RED}✗ Found Kubernetes Secret objects (should use ExternalSecret)${NC}"
        found_issues=1
    else
        echo -e "${GREEN}✓ No hardcoded Secret objects found${NC}"
    fi
    
    # Check for base64 encoded values
    if grep -E "^\s*[a-zA-Z0-9+/]{20,}={0,2}\s*$" "$file" | grep -v "^#"; then
        echo -e "${YELLOW}⚠ Found potential base64 encoded values${NC}"
        echo "  Verify these are not actual secrets"
        found_issues=1
    fi
    
    return $found_issues
}

# Validate ExternalSecret configuration
check_external_secrets() {
    echo ""
    echo "Validating ExternalSecret configurations..."
    
    local namespace="claude-deployment"
    
    # Get all ExternalSecrets
    local external_secrets=$(kubectl get externalsecrets -n "$namespace" -o json 2>/dev/null | jq -r '.items[].metadata.name' || echo "")
    
    if [ -z "$external_secrets" ]; then
        echo -e "${YELLOW}⚠ No ExternalSecrets found in namespace $namespace${NC}"
        echo "  Deploy the secrets.yaml file to create them"
        return 0
    fi
    
    for secret in $external_secrets; do
        echo -e "\nChecking ExternalSecret: $secret"
        
        # Check if secret store is configured
        local store=$(kubectl get externalsecret "$secret" -n "$namespace" -o json | jq -r '.spec.secretStoreRef.name')
        if [ -n "$store" ] && [ "$store" != "null" ]; then
            echo -e "  ${GREEN}✓ Secret store configured: $store${NC}"
        else
            echo -e "  ${RED}✗ No secret store configured${NC}"
        fi
        
        # Check refresh interval
        local refresh=$(kubectl get externalsecret "$secret" -n "$namespace" -o json | jq -r '.spec.refreshInterval // "not set"')
        echo -e "  Refresh interval: $refresh"
        
        # Check if target secret exists
        local target=$(kubectl get externalsecret "$secret" -n "$namespace" -o json | jq -r '.spec.target.name')
        if kubectl get secret "$target" -n "$namespace" &> /dev/null; then
            echo -e "  ${GREEN}✓ Target secret exists${NC}"
        else
            echo -e "  ${YELLOW}⚠ Target secret not yet created${NC}"
        fi
    done
}

# Check Vault integration
check_vault_integration() {
    echo ""
    echo "Checking Vault integration..."
    
    # Check if Vault is installed
    if kubectl get pods -n vault -l app.kubernetes.io/name=vault &> /dev/null; then
        echo -e "${GREEN}✓ Vault pods found${NC}"
        
        # Check Vault status
        local vault_pods=$(kubectl get pods -n vault -l app.kubernetes.io/name=vault -o json | jq -r '.items[].metadata.name')
        for pod in $vault_pods; do
            echo -e "  Checking $pod..."
            local sealed=$(kubectl exec -n vault "$pod" -- vault status -format=json 2>/dev/null | jq -r '.sealed' || echo "unknown")
            if [ "$sealed" = "false" ]; then
                echo -e "    ${GREEN}✓ Unsealed${NC}"
            elif [ "$sealed" = "true" ]; then
                echo -e "    ${RED}✗ Sealed${NC}"
            else
                echo -e "    ${YELLOW}⚠ Status unknown${NC}"
            fi
        done
    else
        echo -e "${YELLOW}⚠ Vault not found in cluster${NC}"
        echo "  Install Vault for secret management"
    fi
}

# Check RBAC permissions
check_rbac() {
    echo ""
    echo "Checking RBAC configuration..."
    
    local namespace="claude-deployment"
    local service_account="claude-vault-auth"
    
    # Check ServiceAccount
    if kubectl get serviceaccount "$service_account" -n "$namespace" &> /dev/null; then
        echo -e "${GREEN}✓ ServiceAccount $service_account exists${NC}"
    else
        echo -e "${RED}✗ ServiceAccount $service_account not found${NC}"
    fi
    
    # Check Role
    if kubectl get role vault-auth-role -n "$namespace" &> /dev/null; then
        echo -e "${GREEN}✓ Role vault-auth-role exists${NC}"
    else
        echo -e "${RED}✗ Role vault-auth-role not found${NC}"
    fi
    
    # Check RoleBinding
    if kubectl get rolebinding vault-auth-binding -n "$namespace" &> /dev/null; then
        echo -e "${GREEN}✓ RoleBinding vault-auth-binding exists${NC}"
    else
        echo -e "${RED}✗ RoleBinding vault-auth-binding not found${NC}"
    fi
}

# Check security policies
check_security_policies() {
    echo ""
    echo "Checking security policies..."
    
    # Check NetworkPolicy
    if kubectl get networkpolicy vault-access-policy -n claude-deployment &> /dev/null; then
        echo -e "${GREEN}✓ NetworkPolicy for Vault access configured${NC}"
    else
        echo -e "${YELLOW}⚠ NetworkPolicy for Vault access not found${NC}"
    fi
    
    # Check PodSecurityPolicy (or Pod Security Standards)
    if kubectl get podsecuritypolicy claude-secure-secrets-psp &> /dev/null 2>&1; then
        echo -e "${GREEN}✓ PodSecurityPolicy configured${NC}"
    else
        # Check for Pod Security Standards (newer approach)
        local namespace_labels=$(kubectl get namespace claude-deployment -o json | jq -r '.metadata.labels')
        if echo "$namespace_labels" | grep -q "pod-security"; then
            echo -e "${GREEN}✓ Pod Security Standards configured${NC}"
        else
            echo -e "${YELLOW}⚠ No Pod Security Policy/Standards found${NC}"
        fi
    fi
}

# Generate report
generate_report() {
    echo ""
    echo "=== Security Validation Report ==="
    echo ""
    
    local report_file="k8s-secrets-validation-report-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$report_file" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_results": {
    "external_secrets_installed": $(kubectl get crd externalsecrets.external-secrets.io &> /dev/null && echo "true" || echo "false"),
    "no_hardcoded_secrets": $(! grep -q "^kind: Secret$" k8s/secrets.yaml && echo "true" || echo "false"),
    "vault_installed": $(kubectl get pods -n vault -l app.kubernetes.io/name=vault &> /dev/null && echo "true" || echo "false"),
    "rbac_configured": $(kubectl get serviceaccount claude-vault-auth -n claude-deployment &> /dev/null && echo "true" || echo "false"),
    "security_policies": $(kubectl get networkpolicy vault-access-policy -n claude-deployment &> /dev/null && echo "true" || echo "false")
  },
  "recommendations": [
    "Ensure all secrets are stored in Vault",
    "Enable secret rotation policies",
    "Configure audit logging for secret access",
    "Implement least-privilege access controls",
    "Regular security audits and penetration testing"
  ]
}
EOF
    
    echo -e "${GREEN}Report generated: $report_file${NC}"
}

# Main execution
main() {
    check_tools
    
    local exit_code=0
    
    check_external_secrets_crds || exit_code=1
    check_hardcoded_secrets || exit_code=1
    check_external_secrets
    check_vault_integration
    check_rbac
    check_security_policies
    
    generate_report
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}=== Validation completed successfully ===${NC}"
    else
        echo -e "${RED}=== Validation completed with errors ===${NC}"
    fi
    
    return $exit_code
}

# Run main function
main "$@"