# Deploy-code Configuration Examples

This directory contains comprehensive examples of deploy-code configurations for different deployment scenarios. Each configuration demonstrates best practices and is well-commented to help you understand the available options.

## Configuration Files

### 📋 [minimal.yaml](./minimal.yaml)
**Use Case:** Simple applications with basic deployment needs

- Minimal required configuration
- Local deployment target
- Basic runtime settings
- Perfect starting point for new projects

**Best For:**
- Proof of concepts
- Small applications
- Local development
- Learning deploy-code basics

### 🛠️ [development.yaml](./development.yaml)
**Use Case:** Local development environments with debugging and hot reloading

- Docker-based development setup
- Hot reloading and file watching
- Development tools integration (linting, testing)
- Local services (database, cache, message queue)
- Debugging configuration
- Performance profiling tools

**Features:**
- Multi-container development environment
- Volume mounts for live code editing
- Local service dependencies
- Development-specific environment variables
- Git hooks integration
- API documentation tools

**Best For:**
- Local development
- Team development environments
- Feature development
- Integration testing

### 🏭 [production.yaml](./production.yaml)
**Use Case:** Full production deployments with enterprise features

- Kubernetes deployment with advanced features
- Comprehensive monitoring and observability
- Security hardening and compliance
- Scaling and performance optimization
- Backup and disaster recovery
- Blue-green and canary deployments

**Features:**
- Horizontal and vertical pod autoscaling
- Advanced health checks and probes
- Secret management integration
- Network policies and security contexts
- Comprehensive monitoring (Prometheus, Jaeger)
- Ingress with TLS termination
- Backup strategies and retention policies
- Compliance labeling and governance

**Best For:**
- Production environments
- Enterprise applications
- High-availability services
- Compliance-required deployments

### 🏗️ [multi-service.yaml](./multi-service.yaml)
**Use Case:** Complex microservices architectures

- Multiple interconnected services
- Shared infrastructure components
- Service mesh integration (Istio)
- Cross-service dependencies
- Database per service pattern
- Event-driven architecture with message queues

**Architecture:**
- API Gateway
- User Service
- Order Service  
- Inventory Service
- Notification Service
- Multiple databases (PostgreSQL)
- Redis cluster for caching
- RabbitMQ for messaging

**Features:**
- Service mesh with mTLS
- Circuit breakers and retry policies
- Distributed tracing
- Multi-region disaster recovery
- Cross-cutting security policies
- Comprehensive monitoring dashboard

**Best For:**
- Microservices architectures
- Event-driven systems
- High-scale applications
- Multi-team development

## Usage Examples

### Basic Usage
```bash
# Deploy using minimal configuration
deploy-code --config examples/deploy-code-configs/minimal.yaml

# Deploy development environment
deploy-code --config examples/deploy-code-configs/development.yaml

# Deploy to production
deploy-code --config examples/deploy-code-configs/production.yaml
```

### Validation and Dry Run
```bash
# Validate configuration
deploy-code --config examples/deploy-code-configs/production.yaml --validate

# Dry run (show what would be deployed)
deploy-code --config examples/deploy-code-configs/production.yaml --dry-run

# Check configuration syntax
deploy-code --config examples/deploy-code-configs/production.yaml --check
```

### Environment-Specific Deployments
```bash
# Override environment variables
deploy-code --config examples/deploy-code-configs/production.yaml \
  --set environment.LOG_LEVEL=debug \
  --set scaling.horizontal.minReplicas=5

# Use different target namespace
deploy-code --config examples/deploy-code-configs/production.yaml \
  --set target.kubernetes.namespace=staging
```

## Configuration Structure

All deploy-code configurations follow this general structure:

```yaml
# Application metadata
name: string
version: string
description: string

# Deployment target
target:
  type: local|docker|kubernetes|cloud
  # target-specific configuration

# Source configuration
source:
  repository: string
  branch: string
  # build configuration

# Runtime configuration
runtime:
  command: string
  environment: map
  # runtime-specific settings

# Optional advanced features
scaling: {...}
monitoring: {...}
security: {...}
networking: {...}
```

## Best Practices

### 1. Environment-Specific Configurations
- Use separate files for different environments
- Override values using command-line flags
- Keep sensitive data in external secret stores

### 2. Security Considerations
- Always enable security features in production
- Use network policies to restrict traffic
- Implement proper RBAC controls
- Scan for vulnerabilities regularly

### 3. Monitoring and Observability
- Enable comprehensive monitoring
- Set up alerting for critical metrics
- Use distributed tracing for microservices
- Implement structured logging

### 4. Resource Management
- Set appropriate resource requests and limits
- Configure horizontal and vertical scaling
- Monitor resource usage and adjust as needed
- Use resource quotas to prevent overallocation

### 5. Backup and Recovery
- Implement regular backup strategies
- Test disaster recovery procedures
- Document recovery processes
- Automate backup verification

## Integration with Circle of Experts

The configurations in this directory can be optimized using the Circle of Experts system:

```python
# Generate expert-optimized configuration
python examples/deploy_code_circle_experts.py
```

This will:
- Consult multiple AI experts about your deployment architecture
- Generate optimized configurations based on expert recommendations
- Provide security hardening suggestions
- Create performance optimization guidelines

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   ```bash
   # Check configuration syntax
   deploy-code --config config.yaml --validate
   ```

2. **Resource Constraints**
   ```bash
   # Check resource usage
   kubectl top pods
   kubectl describe pod <pod-name>
   ```

3. **Networking Issues**
   ```bash
   # Check service connectivity
   kubectl get services
   kubectl describe service <service-name>
   ```

4. **Security Context Issues**
   ```bash
   # Check security policies
   kubectl auth can-i <verb> <resource>
   kubectl get networkpolicies
   ```

### Getting Help

- Review the configuration comments for detailed explanations
- Use `deploy-code --help` for command-line options
- Check the main project documentation
- Consult the Circle of Experts for optimization advice

## Contributing

When adding new configuration examples:

1. Follow the established naming convention
2. Include comprehensive comments
3. Document the use case and best practices
4. Test the configuration in relevant environments
5. Update this README with the new example

## License

These configuration examples are part of the claude-optimized-deployment project and are provided under the same license terms.