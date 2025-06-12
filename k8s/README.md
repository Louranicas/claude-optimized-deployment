# Kubernetes Security Manifests for Claude Deployment

This directory contains comprehensive Kubernetes security manifests with security-hardened configurations for the Claude Deployment project.

## 📁 Directory Structure

```
k8s/
├── README.md                    # This documentation
├── namespace.yaml              # Namespace with security policies and resource quotas
├── pod-security-policies.yaml  # Pod Security Policies (restricted, baseline, privileged)
├── network-policies.yaml       # Network isolation and traffic control
├── rbac.yaml                   # Role-Based Access Control configurations
├── security-context.yaml       # Security contexts and admission controllers
├── secrets.yaml                # Encrypted secrets management
├── configmaps.yaml             # Application and service configurations
├── deployments.yaml            # Security-hardened application deployments
├── services.yaml               # Service definitions and ingress rules
└── monitoring.yaml             # Security monitoring and observability
```

## 🔒 Security Features

### 1. Pod Security Policies
- **Restricted Policy**: Maximum security with non-root execution, read-only filesystem
- **Baseline Policy**: Balanced security for standard applications
- **Privileged Policy**: Admin-level access (use sparingly)

### 2. Network Policies
- **Default Deny All**: Blocks all traffic by default
- **Service-Specific Policies**: Granular ingress/egress rules
- **Database Isolation**: Strict access controls for data layer
- **Monitoring Access**: Controlled metrics collection

### 3. RBAC Configuration
- **Service Accounts**: Dedicated accounts per component
- **Role Separation**: Least-privilege access patterns
- **ClusterRole Bindings**: Secure cluster-level permissions
- **PSP Bindings**: Policy enforcement per service account

### 4. Security Contexts
- **Non-root Execution**: All containers run as non-root users
- **Read-only Filesystems**: Prevents runtime modifications
- **Capability Dropping**: Removes unnecessary Linux capabilities
- **AppArmor/SELinux**: Additional security profile enforcement

## 🚀 Deployment Instructions

### Prerequisites
1. Kubernetes cluster (v1.20+)
2. kubectl configured with cluster access
3. Pod Security Policy admission controller enabled
4. Network policy support (Calico, Cilium, etc.)

### Step 1: Create Namespace and Basic Security
```bash
kubectl apply -f namespace.yaml
kubectl apply -f pod-security-policies.yaml
kubectl apply -f rbac.yaml
```

### Step 2: Configure Secrets and ConfigMaps
```bash
# Update secrets with actual values before applying
kubectl apply -f secrets.yaml
kubectl apply -f configmaps.yaml
```

### Step 3: Apply Network Policies
```bash
kubectl apply -f network-policies.yaml
kubectl apply -f security-context.yaml
```

### Step 4: Deploy Applications
```bash
kubectl apply -f deployments.yaml
kubectl apply -f services.yaml
```

### Step 5: Setup Monitoring
```bash
kubectl apply -f monitoring.yaml
```

## 🔧 Configuration Requirements

### Before Deployment
1. **Update Secrets**: Replace base64 placeholders in `secrets.yaml`
2. **Configure Domains**: Update ingress hostnames in `services.yaml`
3. **Set Resource Limits**: Adjust CPU/memory limits in `deployments.yaml`
4. **Storage Classes**: Ensure `fast-ssd` storage class exists

### Security Hardening Checklist
- [ ] All containers run as non-root
- [ ] Read-only root filesystems enabled
- [ ] Security contexts properly configured
- [ ] Network policies restrict traffic flow
- [ ] RBAC follows least-privilege principle
- [ ] Secrets are encrypted at rest
- [ ] Resource quotas prevent resource exhaustion
- [ ] Monitoring captures security events

## 📊 Security Monitoring

### Prometheus Metrics
- Container security violations
- Network policy denials
- RBAC authorization failures
- Resource quota breaches

### Alerting Rules
- High error rates (>10% 5xx responses)
- Memory usage >80% of limits
- Pod crash looping
- Unauthorized access attempts

### Grafana Dashboards
- Security overview dashboard
- Network traffic analysis
- Resource utilization monitoring
- Compliance status tracking

## 🛡️ Security Policies

### Pod Security Standards
- **Restricted**: Default for all application pods
- **Baseline**: For monitoring and infrastructure components
- **Privileged**: Only for authorized admin operations

### Network Segmentation
- **API Layer**: Ingress from load balancer only
- **Application Layer**: Internal service communication
- **Data Layer**: Database access from application pods only
- **Monitoring**: Metrics collection from all layers

### Access Control
- **API Service**: Read-only access to configs and secrets
- **Worker Service**: Job creation and execution permissions
- **Monitor Service**: Cluster-wide read access for metrics
- **Admin Service**: Full namespace administration

## 🔍 Troubleshooting

### Common Issues

1. **Pod Security Policy Violations**
   ```bash
   kubectl describe pod <pod-name> -n claude-deployment
   # Check for PSP-related events
   ```

2. **Network Policy Blocking Traffic**
   ```bash
   kubectl logs <pod-name> -n claude-deployment
   # Test connectivity with temporary debug pod
   ```

3. **RBAC Permission Denied**
   ```bash
   kubectl auth can-i <verb> <resource> --as=system:serviceaccount:claude-deployment:<sa-name>
   ```

4. **Resource Quota Exceeded**
   ```bash
   kubectl describe quota claude-deployment-quota -n claude-deployment
   ```

### Debug Commands
```bash
# Check security policies
kubectl get psp
kubectl get networkpolicy -n claude-deployment

# Verify RBAC
kubectl get rolebinding,clusterrolebinding -n claude-deployment

# Monitor events
kubectl get events -n claude-deployment --sort-by='.lastTimestamp'

# Security context validation
kubectl get pod <pod-name> -o yaml | grep -A 10 securityContext
```

## 📋 Compliance

This configuration implements security best practices for:
- **CIS Kubernetes Benchmark**
- **NIST Cybersecurity Framework**
- **SOC 2 Type II Requirements**
- **GDPR Data Protection**
- **ISO 27001 Information Security**

## 🔄 Maintenance

### Regular Tasks
- Update container images monthly
- Rotate secrets quarterly
- Review RBAC permissions annually
- Update network policies as needed
- Monitor security alerts daily

### Backup and Recovery
- Database backups via CronJob
- Configuration stored in Git
- Secrets managed via external secret management
- Disaster recovery procedures documented

## 📞 Support

For security issues or questions:
1. Check troubleshooting section
2. Review Kubernetes security documentation
3. Consult with security team
4. Create incident ticket for critical issues

---

**Security Notice**: This configuration implements defense-in-depth security principles. Regularly review and update security policies to maintain protection against evolving threats.