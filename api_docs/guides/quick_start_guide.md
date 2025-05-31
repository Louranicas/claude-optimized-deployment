# Quick Start Guide - CODE MCP API

Welcome to the Claude-Optimized Deployment Engine (CODE) MCP API! This guide will help you get started with our infrastructure automation tools in minutes.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Your First API Call](#your-first-api-call)
5. [Common Use Cases](#common-use-cases)
6. [Next Steps](#next-steps)

## Prerequisites

Before you begin, ensure you have:

- Python 3.9 or higher
- Docker installed (for container operations)
- Access to at least one cloud provider (AWS, Azure, or GCP)
- API keys for the services you plan to use

## Installation

### Option 1: Using pip

```bash
pip install code-mcp-client
```

### Option 2: From source

```bash
git clone https://github.com/claude-optimized-deployment/code
cd code
pip install -r requirements.txt
python setup.py install
```

### Option 3: Using Docker

```bash
docker pull code-deployment/mcp-client:latest
```

## Configuration

### 1. Environment Variables

Create a `.env` file in your project root:

```bash
# Core Configuration
ENVIRONMENT=development
LOG_LEVEL=INFO

# AI Providers (for Circle of Experts)
ANTHROPIC_API_KEY=your-anthropic-key
OPENAI_API_KEY=your-openai-key
GOOGLE_GEMINI_API_KEY=your-gemini-key

# Infrastructure Providers
AZURE_DEVOPS_TOKEN=your-azure-token
AZURE_DEVOPS_ORGANIZATION=your-org

# Monitoring & Alerts
SLACK_BOT_TOKEN=your-slack-token
PROMETHEUS_URL=http://localhost:9090

# Cloud Storage
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_DEFAULT_REGION=us-east-1

# Search & Research
BRAVE_API_KEY=your-brave-key
```

### 2. Initialize the MCP Manager

```python
from src.mcp.manager import get_mcp_manager
import asyncio

async def main():
    # Initialize the MCP manager
    manager = get_mcp_manager()
    await manager.initialize()
    
    # List available servers
    servers = manager.list_servers()
    print(f"Available MCP servers: {servers}")
    
    # Get all available tools
    tools = manager.get_available_tools()
    print(f"Total tools available: {len(tools)}")

asyncio.run(main())
```

## Your First API Call

Let's start with a simple example - checking the health of your Docker installation:

```python
from src.mcp.manager import get_mcp_manager
import asyncio

async def check_docker():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Check Docker version
    result = await manager.call_tool(
        "docker.docker_ps",
        {"all": True}
    )
    
    print(f"Docker is running with {len(result['containers'])} containers")
    return result

asyncio.run(check_docker())
```

## Common Use Cases

### 1. Deploy a Container to Production

```python
async def deploy_to_production():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Step 1: Build the Docker image
    build_result = await manager.call_tool(
        "docker.docker_build",
        {
            "dockerfile_path": "./Dockerfile",
            "image_tag": "myapp:v1.0.0",
            "build_args": {
                "NODE_ENV": "production"
            }
        }
    )
    print(f"Built image: {build_result['image_id']}")
    
    # Step 2: Run security scan
    scan_result = await manager.call_tool(
        "security-scanner.docker_security_scan",
        {
            "image": "myapp:v1.0.0",
            "severity": "high"
        }
    )
    
    if scan_result['total_vulnerabilities'] > 0:
        print("Security vulnerabilities found!")
        return False
    
    # Step 3: Push to registry
    push_result = await manager.call_tool(
        "docker.docker_push",
        {
            "image_tag": "myapp:v1.0.0",
            "registry": "registry.mycompany.com"
        }
    )
    
    # Step 4: Deploy to Kubernetes
    deploy_result = await manager.call_tool(
        "kubernetes.kubectl_apply",
        {
            "manifest_path": "./k8s/production/",
            "namespace": "production"
        }
    )
    
    # Step 5: Send notification
    await manager.call_tool(
        "slack-notifications.send_notification",
        {
            "channel": "#deployments",
            "notification_type": "deployment_success",
            "title": "Production Deployment Complete",
            "details": {
                "version": "v1.0.0",
                "environment": "production"
            }
        }
    )
    
    return True
```

### 2. Monitor Application Health

```python
async def monitor_application():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Query Prometheus for application metrics
    metrics = await manager.call_tool(
        "prometheus-monitoring.prometheus_query",
        {
            "query": "rate(http_requests_total{job='myapp'}[5m])"
        }
    )
    
    # Check if request rate is abnormal
    request_rate = float(metrics['data']['result'][0]['value'][1])
    
    if request_rate > 1000:
        # Send alert to Slack
        await manager.call_tool(
            "slack-notifications.post_message",
            {
                "channel": "#alerts",
                "text": f"⚠️ High request rate detected: {request_rate} req/s"
            }
        )
    
    return metrics
```

### 3. Automated Security Scanning

```python
async def security_audit():
    manager = get_mcp_manager()
    await manager.initialize()
    
    vulnerabilities = []
    
    # Scan NPM dependencies
    npm_scan = await manager.call_tool(
        "security-scanner.npm_audit",
        {
            "package_json_path": "./package.json",
            "severity": "moderate"
        }
    )
    vulnerabilities.extend(npm_scan['vulnerabilities'])
    
    # Scan Python dependencies
    py_scan = await manager.call_tool(
        "security-scanner.python_safety_check",
        {
            "requirements_path": "./requirements.txt",
            "severity": "moderate"
        }
    )
    vulnerabilities.extend(py_scan['vulnerabilities'])
    
    # Generate report
    if vulnerabilities:
        report = f"Found {len(vulnerabilities)} vulnerabilities:\n"
        for vuln in vulnerabilities:
            report += f"- {vuln['package']}: {vuln['vulnerability']}\n"
        
        # Save report to S3
        await manager.call_tool(
            "s3-storage.s3_upload_file",
            {
                "file_path": "./security_report.txt",
                "bucket": "security-reports",
                "key": f"reports/{datetime.now().isoformat()}.txt"
            }
        )
    
    return vulnerabilities
```

### 4. CI/CD Pipeline Automation

```python
async def trigger_ci_pipeline(branch="main"):
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Trigger Azure DevOps pipeline
    pipeline_result = await manager.call_tool(
        "azure-devops.trigger_pipeline",
        {
            "project": "MyProject",
            "pipeline_id": 42,
            "branch": branch,
            "parameters": {
                "environment": "staging",
                "run_tests": True
            }
        }
    )
    
    build_id = pipeline_result['build_id']
    
    # Monitor build status
    while True:
        status = await manager.call_tool(
            "azure-devops.get_build_status",
            {
                "project": "MyProject",
                "build_id": build_id
            }
        )
        
        if status['status'] in ['completed', 'failed']:
            break
            
        await asyncio.sleep(30)
    
    # Notify team
    await manager.call_tool(
        "slack-notifications.send_notification",
        {
            "channel": "#ci-cd",
            "notification_type": "build_complete",
            "title": f"Build {build_id} {status['status']}",
            "details": status
        }
    )
    
    return status
```

## Error Handling

Always wrap your API calls in try-except blocks:

```python
from src.mcp.protocols import MCPError

async def safe_deploy():
    manager = get_mcp_manager()
    await manager.initialize()
    
    try:
        result = await manager.call_tool(
            "kubernetes.kubectl_apply",
            {"manifest_path": "./k8s/"}
        )
        return result
    except MCPError as e:
        if e.code == -32004:  # Invalid parameters
            print(f"Invalid parameters: {e.message}")
        elif e.code == -32001:  # Authentication error
            print("Authentication failed. Check your credentials.")
        else:
            print(f"MCP Error {e.code}: {e.message}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
```

## Batch Operations

For better performance, batch multiple operations:

```python
async def batch_operations():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Run multiple operations in parallel
    tasks = [
        manager.call_tool("docker.docker_ps", {"all": True}),
        manager.call_tool("kubernetes.kubectl_get", {
            "resource_type": "pods",
            "namespace": "default"
        }),
        manager.call_tool("prometheus-monitoring.prometheus_targets", {})
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Task {i} failed: {result}")
        else:
            print(f"Task {i} succeeded")
    
    return results
```

## Next Steps

Now that you've completed the quick start guide:

1. **Read the Authentication Guide**: Learn about securing your API calls
2. **Explore the API Reference**: Detailed documentation for all tools
3. **Check out Examples**: More complex deployment scenarios
4. **Join the Community**: Get help and share your experiences

### Useful Resources

- [Full API Reference](../reference/mcp_tools_reference.md)
- [Authentication Guide](./authentication_guide.md)
- [Integration Patterns](./integration_patterns.md)
- [Troubleshooting Guide](./troubleshooting.md)

### Getting Help

- **Documentation**: https://docs.code-deployment.com
- **GitHub Issues**: https://github.com/claude-optimized-deployment/code/issues
- **Community Forum**: https://forum.code-deployment.com
- **Slack Channel**: #code-deployment

## Example: Complete Deployment Workflow

Here's a complete example that ties everything together:

```python
import asyncio
from datetime import datetime
from src.mcp.manager import get_mcp_manager

async def complete_deployment_workflow(version: str):
    """
    Complete deployment workflow with all safety checks.
    """
    manager = get_mcp_manager()
    await manager.initialize()
    
    deployment_id = f"deploy-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    try:
        # 1. Pre-deployment checks
        print("🔍 Running pre-deployment checks...")
        
        # Check Docker daemon
        docker_info = await manager.call_tool(
            "desktop-commander.execute_command",
            {"command": "docker info"}
        )
        
        if docker_info['exit_code'] != 0:
            raise Exception("Docker daemon not running")
        
        # 2. Build and scan
        print("🔨 Building application...")
        
        build_result = await manager.call_tool(
            "docker.docker_build",
            {
                "dockerfile_path": ".",
                "image_tag": f"myapp:{version}"
            }
        )
        
        print("🔒 Running security scan...")
        
        scan_result = await manager.call_tool(
            "security-scanner.docker_security_scan",
            {
                "image": f"myapp:{version}",
                "severity": "high"
            }
        )
        
        if scan_result['total_vulnerabilities'] > 0:
            # Create work item for vulnerabilities
            await manager.call_tool(
                "azure-devops.create_work_item",
                {
                    "project": "MyProject",
                    "work_item_type": "Bug",
                    "title": f"Security vulnerabilities in {version}",
                    "description": f"Found {scan_result['total_vulnerabilities']} vulnerabilities"
                }
            )
            raise Exception("Security scan failed")
        
        # 3. Push to registry
        print("📤 Pushing to registry...")
        
        await manager.call_tool(
            "docker.docker_push",
            {
                "image_tag": f"myapp:{version}",
                "registry": "registry.mycompany.com"
            }
        )
        
        # 4. Deploy to staging
        print("🚀 Deploying to staging...")
        
        staging_deploy = await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": "./k8s/staging/",
                "namespace": "staging"
            }
        )
        
        # 5. Run smoke tests
        print("🧪 Running smoke tests...")
        
        await asyncio.sleep(30)  # Wait for pods to start
        
        test_result = await manager.call_tool(
            "desktop-commander.execute_command",
            {
                "command": "pytest tests/smoke/ -v",
                "timeout": 300
            }
        )
        
        if test_result['exit_code'] != 0:
            raise Exception("Smoke tests failed")
        
        # 6. Deploy to production
        print("🎯 Deploying to production...")
        
        prod_deploy = await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": "./k8s/production/",
                "namespace": "production"
            }
        )
        
        # 7. Monitor rollout
        print("📊 Monitoring rollout...")
        
        rollout_status = await manager.call_tool(
            "kubernetes.kubectl_rollout_status",
            {
                "resource_type": "deployment",
                "name": "myapp",
                "namespace": "production",
                "timeout": 600
            }
        )
        
        # 8. Update monitoring
        print("📈 Configuring monitoring...")
        
        # Check application metrics
        metrics = await manager.call_tool(
            "prometheus-monitoring.prometheus_query",
            {
                "query": f'up{{job="myapp",version="{version}"}}'
            }
        )
        
        # 9. Success notification
        await manager.call_tool(
            "slack-notifications.send_notification",
            {
                "channel": "#deployments",
                "notification_type": "deployment_success",
                "title": f"✅ Deployment {deployment_id} Successful",
                "details": {
                    "version": version,
                    "deployment_id": deployment_id,
                    "staging_resources": len(staging_deploy['applied_resources']),
                    "production_resources": len(prod_deploy['applied_resources'])
                },
                "color": "good"
            }
        )
        
        print(f"✅ Deployment {deployment_id} completed successfully!")
        return True
        
    except Exception as e:
        # Rollback and notify
        print(f"❌ Deployment failed: {e}")
        
        await manager.call_tool(
            "slack-notifications.send_notification",
            {
                "channel": "#deployments",
                "notification_type": "deployment_failure",
                "title": f"❌ Deployment {deployment_id} Failed",
                "details": {
                    "version": version,
                    "error": str(e)
                },
                "color": "danger"
            }
        )
        
        # Attempt rollback
        print("🔄 Attempting rollback...")
        
        await manager.call_tool(
            "kubernetes.kubectl_rollout_restart",
            {
                "resource_type": "deployment",
                "name": "myapp",
                "namespace": "production"
            }
        )
        
        return False

# Run the deployment
if __name__ == "__main__":
    asyncio.run(complete_deployment_workflow("v1.2.3"))
```

This example demonstrates:
- Pre-deployment validation
- Security scanning
- Multi-stage deployment
- Health checks and monitoring
- Error handling and rollback
- Team notifications

You're now ready to build powerful infrastructure automation with the CODE MCP API!