# Developer Quickstart Guide

Get up and running with the Claude-Optimized Deployment Engine API in minutes.

## Table of Contents

1. [Quick Setup](#quick-setup)
2. [Authentication](#authentication)
3. [First API Call](#first-api-call)
4. [MCP Tools Basics](#mcp-tools-basics)
5. [Common Workflows](#common-workflows)
6. [SDK Examples](#sdk-examples)
7. [Troubleshooting](#troubleshooting)

## Quick Setup

### Prerequisites

- Python 3.8+ or Node.js 16+
- Docker Desktop (for container management)
- Git (for source control integration)

### Installation

#### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/claude-optimized-deployment.git
cd claude-optimized-deployment

# Start with Docker Compose
docker-compose up -d

# API will be available at http://localhost:8000
```

#### Option 2: Local Development

```bash
# Clone and setup
git clone https://github.com/your-org/claude-optimized-deployment.git
cd claude-optimized-deployment

# Install dependencies
make dev-setup

# Start the API server
make api-run

# API will be available at http://localhost:8000
```

### Verify Installation

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-05-31T10:00:00.000Z"
}
```

## Authentication

### API Key Setup

1. **Get your API key:**
   ```bash
   # Generate a new API key
   curl -X POST http://localhost:8000/auth/api-keys \
     -H "Content-Type: application/json" \
     -d '{"name": "my-deployment-key", "permissions": ["read", "write"]}'
   ```

2. **Set environment variable:**
   ```bash
   export CODE_API_KEY="your-api-key-here"
   ```

3. **Test authentication:**
   ```bash
   curl -H "X-API-Key: $CODE_API_KEY" http://localhost:8000/api/circuit-breakers/status
   ```

### MCP Server Authentication

Configure external service credentials:

```bash
# Create .env file
cat > .env << EOF
# Web Search
BRAVE_API_KEY=your-brave-api-key

# Team Communication  
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token

# Cloud Storage
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# DevOps
AZURE_DEVOPS_TOKEN=your-azure-token
AZURE_DEVOPS_ORGANIZATION=your-org

# Monitoring
PROMETHEUS_URL=http://localhost:9090
EOF

# Restart the service to load new config
make api-restart
```

## First API Call

### Check System Health

```bash
curl -H "X-API-Key: $CODE_API_KEY" \
  http://localhost:8000/api/circuit-breakers/health
```

Response:
```json
{
  "timestamp": "2025-05-31T10:00:00.000Z",
  "health": "healthy",
  "details": {
    "total_breakers": 5,
    "healthy_breakers": 5,
    "degraded_breakers": 0,
    "failed_breakers": 0,
    "overall_failure_rate": "0.0%"
  },
  "recommendations": []
}
```

### List Available MCP Servers

```bash
curl -H "X-API-Key: $CODE_API_KEY" \
  http://localhost:8000/api/mcp/servers
```

Response:
```json
{
  "servers": [
    {
      "name": "docker",
      "version": "1.0.0",
      "description": "Docker container management",
      "capabilities": {
        "tools": true,
        "resources": false,
        "prompts": false
      },
      "tool_count": 8
    },
    {
      "name": "kubernetes",
      "version": "1.0.0", 
      "description": "Kubernetes cluster management",
      "tool_count": 6
    }
  ],
  "total": 11
}
```

## MCP Tools Basics

### Execute Your First Tool

Let's start with a simple Docker command:

```bash
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "docker",
    "tool": "docker_ps",
    "arguments": {
      "all": false
    }
  }'
```

Response:
```json
{
  "success": true,
  "result": {
    "containers": [
      {
        "id": "abc123",
        "name": "code-api",
        "image": "code:latest",
        "status": "Up 2 hours",
        "ports": ["8000:8000"]
      }
    ]
  },
  "execution_time": 0.234
}
```

### Build and Deploy a Container

#### 1. Build Docker Image

```bash
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "docker",
    "tool": "docker_build", 
    "arguments": {
      "dockerfile_path": ".",
      "image_tag": "my-app:latest",
      "build_args": {
        "NODE_VERSION": "18"
      }
    }
  }'
```

#### 2. Run Container

```bash
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "docker", 
    "tool": "docker_run",
    "arguments": {
      "image": "my-app:latest",
      "container_name": "my-app-instance",
      "ports": ["3000:3000"],
      "environment": {
        "NODE_ENV": "production"
      },
      "detach": true
    }
  }'
```

#### 3. Check Container Status

```bash
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "docker",
    "tool": "docker_logs", 
    "arguments": {
      "container": "my-app-instance",
      "tail": 50
    }
  }'
```

## Common Workflows

### 1. Security Scanning Pipeline

```bash
# Scan npm dependencies
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "security-scanner",
    "tool": "npm_audit",
    "arguments": {
      "package_json_path": "./package.json",
      "audit_level": "high"
    }
  }'

# Scan Docker image
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "security-scanner", 
    "tool": "docker_security_scan",
    "arguments": {
      "image_name": "my-app:latest",
      "severity_threshold": "medium"
    }
  }'
```

### 2. Kubernetes Deployment

```bash
# Apply Kubernetes manifests
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "kubernetes",
    "tool": "kubectl_apply",
    "arguments": {
      "manifest_path": "./k8s/",
      "namespace": "production",
      "recursive": true
    }
  }'

# Check deployment status
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "kubernetes",
    "tool": "kubectl_get",
    "arguments": {
      "resource": "deployment",
      "name": "my-app",
      "namespace": "production"
    }
  }'

# Scale deployment
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "kubernetes",
    "tool": "kubectl_scale",
    "arguments": {
      "resource": "deployment",
      "name": "my-app",
      "replicas": 3,
      "namespace": "production"
    }
  }'
```

### 3. Monitoring and Alerts

```bash
# Query Prometheus metrics
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "prometheus-monitoring",
    "tool": "prometheus_query",
    "arguments": {
      "query": "rate(http_requests_total[5m])"
    }
  }'

# Send Slack notification
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "slack-notifications",
    "tool": "send_notification",
    "arguments": {
      "channel": "#deployments",
      "message": "🚀 Deployment completed successfully!",
      "severity": "success"
    }
  }'
```

## SDK Examples

### Python SDK

```python
import asyncio
import aiohttp
from typing import Dict, Any

class CODEClient:
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = None):
        self.base_url = base_url
        self.api_key = api_key
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={"X-API-Key": self.api_key} if self.api_key else {}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def execute_tool(self, server: str, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an MCP tool."""
        async with self.session.post(
            f"{self.base_url}/api/mcp/execute",
            json={
                "server": server,
                "tool": tool,
                "arguments": arguments
            }
        ) as response:
            return await response.json()
    
    async def get_system_health(self) -> Dict[str, Any]:
        """Get system health status."""
        async with self.session.get(f"{self.base_url}/api/circuit-breakers/health") as response:
            return await response.json()
    
    async def deploy_container(self, image: str, name: str, **kwargs) -> Dict[str, Any]:
        """Deploy a container with common defaults."""
        return await self.execute_tool("docker", "docker_run", {
            "image": image,
            "container_name": name,
            "detach": True,
            **kwargs
        })

# Usage example
async def main():
    async with CODEClient(api_key="your-api-key") as client:
        # Check system health
        health = await client.get_system_health()
        print(f"System health: {health['health']}")
        
        # Deploy application
        result = await client.deploy_container(
            image="nginx:latest",
            name="my-nginx",
            ports=["80:80"]
        )
        
        if result['success']:
            print(f"Container deployed: {result['result']['container_id']}")
        else:
            print(f"Deployment failed: {result.get('error')}")

# Run the example
asyncio.run(main())
```

### JavaScript/Node.js SDK

```javascript
const axios = require('axios');

class CODEClient {
    constructor(baseUrl = 'http://localhost:8000', apiKey = null) {
        this.baseUrl = baseUrl;
        this.client = axios.create({
            baseURL: baseUrl,
            headers: apiKey ? { 'X-API-Key': apiKey } : {}
        });
    }

    async executeTool(server, tool, arguments) {
        try {
            const response = await this.client.post('/api/mcp/execute', {
                server,
                tool,
                arguments
            });
            return response.data;
        } catch (error) {
            throw new Error(`Tool execution failed: ${error.response?.data?.error?.message || error.message}`);
        }
    }

    async getSystemHealth() {
        const response = await this.client.get('/api/circuit-breakers/health');
        return response.data;
    }

    async deployContainer(image, name, options = {}) {
        return this.executeTool('docker', 'docker_run', {
            image,
            container_name: name,
            detach: true,
            ...options
        });
    }

    async buildImage(dockerfilePath, imageTag, buildArgs = {}) {
        return this.executeTool('docker', 'docker_build', {
            dockerfile_path: dockerfilePath,
            image_tag: imageTag,
            build_args: buildArgs
        });
    }

    async deployToKubernetes(manifestPath, namespace = 'default') {
        return this.executeTool('kubernetes', 'kubectl_apply', {
            manifest_path: manifestPath,
            namespace,
            recursive: true
        });
    }
}

// Usage example
async function deployApplication() {
    const client = new CODEClient('http://localhost:8000', process.env.CODE_API_KEY);
    
    try {
        // Check system health
        const health = await client.getSystemHealth();
        console.log(`System health: ${health.health}`);
        
        if (health.health !== 'healthy') {
            throw new Error('System is not healthy, aborting deployment');
        }
        
        // Build Docker image
        console.log('Building Docker image...');
        const buildResult = await client.buildImage('.', 'my-app:latest', {
            NODE_VERSION: '18',
            BUILD_ENV: 'production'
        });
        
        if (!buildResult.success) {
            throw new Error(`Build failed: ${buildResult.error}`);
        }
        
        console.log(`Built image: ${buildResult.result.image_tag}`);
        
        // Deploy to Kubernetes
        console.log('Deploying to Kubernetes...');
        const deployResult = await client.deployToKubernetes('./k8s/', 'production');
        
        if (!deployResult.success) {
            throw new Error(`Deployment failed: ${deployResult.error}`);
        }
        
        console.log('Deployment completed successfully!');
        console.log(`Applied resources: ${deployResult.result.applied_resources.length}`);
        
    } catch (error) {
        console.error(`Deployment failed: ${error.message}`);
        process.exit(1);
    }
}

// Run deployment
if (require.main === module) {
    deployApplication();
}

module.exports = CODEClient;
```

### Bash/Shell Scripting

```bash
#!/bin/bash

# CODE API Client Functions
CODE_API_BASE="http://localhost:8000"
CODE_API_KEY="${CODE_API_KEY:-}"

# Function to execute MCP tools
execute_tool() {
    local server="$1"
    local tool="$2"
    local arguments="$3"
    
    curl -s -X POST \
        -H "X-API-Key: $CODE_API_KEY" \
        -H "Content-Type: application/json" \
        "$CODE_API_BASE/api/mcp/execute" \
        -d "{
            \"server\": \"$server\",
            \"tool\": \"$tool\",
            \"arguments\": $arguments
        }"
}

# Function to check system health
check_health() {
    curl -s -H "X-API-Key: $CODE_API_KEY" \
        "$CODE_API_BASE/api/circuit-breakers/health" | \
        jq -r '.health'
}

# Deployment script
deploy_application() {
    echo "🔍 Checking system health..."
    local health=$(check_health)
    
    if [[ "$health" != "healthy" ]]; then
        echo "❌ System is not healthy: $health"
        exit 1
    fi
    
    echo "✅ System is healthy"
    
    echo "🏗️ Building Docker image..."
    local build_result=$(execute_tool "docker" "docker_build" '{
        "dockerfile_path": ".",
        "image_tag": "my-app:latest",
        "build_args": {
            "NODE_VERSION": "18"
        }
    }')
    
    local build_success=$(echo "$build_result" | jq -r '.success')
    if [[ "$build_success" != "true" ]]; then
        echo "❌ Build failed"
        echo "$build_result" | jq '.error'
        exit 1
    fi
    
    echo "✅ Build completed"
    
    echo "🚀 Deploying to Kubernetes..."
    local deploy_result=$(execute_tool "kubernetes" "kubectl_apply" '{
        "manifest_path": "./k8s/",
        "namespace": "production",
        "recursive": true
    }')
    
    local deploy_success=$(echo "$deploy_result" | jq -r '.success')
    if [[ "$deploy_success" != "true" ]]; then
        echo "❌ Deployment failed"
        echo "$deploy_result" | jq '.error'
        exit 1
    fi
    
    echo "✅ Deployment completed successfully!"
    
    # Send Slack notification
    execute_tool "slack-notifications" "send_notification" '{
        "channel": "#deployments",
        "message": "🎉 Production deployment completed!",
        "severity": "success"
    }' > /dev/null
}

# Run deployment
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    deploy_application
fi
```

## Troubleshooting

### Common Issues

#### 1. API Key Authentication Failed

**Error:** `401 Unauthorized`

**Solution:**
```bash
# Check if API key is set
echo $CODE_API_KEY

# Verify API key format
curl -H "X-API-Key: $CODE_API_KEY" http://localhost:8000/auth/verify

# Generate new API key if needed
curl -X POST http://localhost:8000/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"name": "new-key", "permissions": ["read", "write"]}'
```

#### 2. MCP Server Not Available

**Error:** `Server 'docker' not found`

**Solution:**
```bash
# Check server status
curl -H "X-API-Key: $CODE_API_KEY" http://localhost:8000/api/mcp/servers

# Restart MCP services
make mcp-restart

# Check Docker daemon
docker info
```

#### 3. Tool Execution Timeout

**Error:** `Tool execution timeout`

**Solution:**
```bash
# Check system resources
docker stats

# Increase timeout in tool call
curl -X POST -H "X-API-Key: $CODE_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/mcp/execute \
  -d '{
    "server": "docker",
    "tool": "docker_build",
    "arguments": {
      "dockerfile_path": ".",
      "image_tag": "my-app:latest",
      "timeout": 600
    }
  }'
```

#### 4. Permission Denied

**Error:** `Permission denied accessing Docker`

**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart session or run:
newgrp docker

# Verify Docker access
docker ps
```

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Restart API server
make api-restart

# Check logs
make api-logs
```

### API Health Endpoints

```bash
# Overall system health
curl http://localhost:8000/health

# Circuit breaker health
curl -H "X-API-Key: $CODE_API_KEY" http://localhost:8000/api/circuit-breakers/health

# MCP server health
curl -H "X-API-Key: $CODE_API_KEY" http://localhost:8000/api/experts/health
```

## Next Steps

1. **Explore the OpenAPI documentation**: Visit `http://localhost:8000/docs` for interactive API documentation
2. **Join our community**: [GitHub Discussions](https://github.com/your-org/claude-optimized-deployment/discussions)
3. **Read the full documentation**: [Complete API Reference](./mcp-tools.md)
4. **Check out examples**: Browse the `/examples` directory for more complex workflows
5. **Set up monitoring**: Configure Prometheus and Grafana for observability

## Getting Help

- **Documentation**: [API Reference](./mcp-tools.md)
- **GitHub Issues**: [Report bugs](https://github.com/your-org/claude-optimized-deployment/issues)
- **Community**: [Discussions](https://github.com/your-org/claude-optimized-deployment/discussions)
- **Email Support**: support@code-engine.io

You're now ready to build powerful deployment automation with the CODE API! 🚀