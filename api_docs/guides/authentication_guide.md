# Authentication Guide - CODE MCP API

This guide covers authentication methods for all MCP servers in the CODE project. Each service requires specific credentials and configuration.

## Table of Contents

1. [Overview](#overview)
2. [Authentication Methods](#authentication-methods)
3. [Service-Specific Authentication](#service-specific-authentication)
4. [Security Best Practices](#security-best-practices)
5. [Troubleshooting](#troubleshooting)

## Overview

The CODE MCP API uses different authentication methods depending on the service:

- **API Keys**: For external services (Brave, Slack, OpenAI)
- **Access Tokens**: For cloud providers (AWS, Azure)
- **Service Accounts**: For Kubernetes and Google Cloud
- **No Authentication**: For local tools (Docker, Desktop Commander)

## Authentication Methods

### 1. Environment Variables (Recommended)

The most secure way to provide credentials is through environment variables:

```bash
# Create a .env file (never commit this!)
cat > .env << EOF
# AI Providers
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_GEMINI_API_KEY=AI...

# Cloud Providers
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AZURE_DEVOPS_TOKEN=...
AZURE_DEVOPS_ORGANIZATION=myorg

# Communication
SLACK_BOT_TOKEN=xoxb-...

# Search
BRAVE_API_KEY=BSA...

# Monitoring
PROMETHEUS_URL=http://prometheus:9090
EOF
```

Load environment variables in Python:

```python
from dotenv import load_dotenv
import os

# Load from .env file
load_dotenv()

# Access credentials
api_key = os.getenv("OPENAI_API_KEY")
```

### 2. Configuration Files

For more complex setups, use configuration files:

```yaml
# config/credentials.yaml
credentials:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
  openai:
    api_key: ${OPENAI_API_KEY}
  aws:
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    region: us-east-1
  azure:
    devops_token: ${AZURE_DEVOPS_TOKEN}
    organization: ${AZURE_DEVOPS_ORGANIZATION}
```

Load configuration:

```python
import yaml
import os
from string import Template

def load_config(config_path="config/credentials.yaml"):
    with open(config_path, 'r') as f:
        config_template = f.read()
    
    # Substitute environment variables
    config_str = Template(config_template).safe_substitute(os.environ)
    config = yaml.safe_load(config_str)
    
    return config
```

### 3. Programmatic Authentication

Pass credentials directly (use only for testing):

```python
from src.mcp.manager import MCPManager

# Initialize with credentials
manager = MCPManager()

# Configure specific server
manager.configure_server("brave", {
    "api_key": "your-brave-api-key"
})

# Or pass during tool call
result = await manager.call_tool(
    "s3-storage.s3_upload_file",
    {
        "file_path": "./file.txt",
        "bucket": "my-bucket",
        "key": "uploads/file.txt"
    },
    auth={
        "aws_access_key_id": "AKIA...",
        "aws_secret_access_key": "..."
    }
)
```

## Service-Specific Authentication

### AI Providers (Circle of Experts)

#### Anthropic (Claude)

```bash
# Get API key from: https://console.anthropic.com/
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

Usage:
```python
# Automatically loaded from environment
expert = ClaudeExpert()
response = await expert.query("How to optimize Kubernetes?")
```

#### OpenAI (GPT)

```bash
# Get API key from: https://platform.openai.com/api-keys
export OPENAI_API_KEY="sk-..."
```

#### Google Gemini

```bash
# Get API key from: https://makersuite.google.com/app/apikey
export GOOGLE_GEMINI_API_KEY="AIza..."
```

#### DeepSeek

```bash
# Get API key from: https://platform.deepseek.com/
export DEEPSEEK_API_KEY="sk-..."
```

### Cloud Providers

#### AWS (S3 Storage)

```bash
# Option 1: Access keys
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

# Option 2: AWS CLI profile
export AWS_PROFILE="my-profile"

# Option 3: IAM role (for EC2/ECS)
# No configuration needed - auto-detected
```

Advanced AWS configuration:

```python
# Use specific credentials
result = await manager.call_tool(
    "s3-storage.s3_upload_file",
    {
        "file_path": "./backup.tar.gz",
        "bucket": "backups",
        "key": "2024/backup.tar.gz"
    },
    aws_config={
        "region_name": "eu-west-1",
        "aws_access_key_id": "AKIA...",
        "aws_secret_access_key": "...",
        "aws_session_token": "..."  # For temporary credentials
    }
)
```

#### Azure DevOps

```bash
# Get PAT from: https://dev.azure.com/{org}/_usersSettings/tokens
export AZURE_DEVOPS_TOKEN="..."
export AZURE_DEVOPS_ORGANIZATION="myorg"
```

Create Personal Access Token (PAT):
1. Go to Azure DevOps > User Settings > Personal Access Tokens
2. Click "New Token"
3. Select scopes:
   - Work Items (Read & Write)
   - Code (Read & Write)
   - Build (Read & Execute)
   - Release (Read, Write, & Execute)

#### Google Cloud

```bash
# Option 1: Service account key file
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Option 2: Application default credentials
gcloud auth application-default login
```

### Communication Services

#### Slack

```bash
# Get bot token from: https://api.slack.com/apps
export SLACK_BOT_TOKEN="xoxb-..."
```

Required OAuth scopes:
- `chat:write` - Send messages
- `channels:read` - List channels
- `channels:join` - Join public channels
- `files:write` - Upload files

Setup:
1. Create Slack app at https://api.slack.com/apps
2. Add OAuth scopes under "OAuth & Permissions"
3. Install to workspace
4. Copy bot token

#### Microsoft Teams (Future)

```bash
# Coming soon
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
```

### Monitoring Services

#### Prometheus

```bash
# No authentication by default
export PROMETHEUS_URL="http://localhost:9090"

# With basic auth
export PROMETHEUS_URL="http://user:pass@prometheus:9090"

# With bearer token
export PROMETHEUS_BEARER_TOKEN="..."
```

Custom authentication:

```python
# Configure Prometheus with auth
manager.configure_server("prometheus-monitoring", {
    "url": "https://prometheus.example.com",
    "auth": {
        "type": "bearer",
        "token": "your-bearer-token"
    }
})
```

### Search Services

#### Brave Search

```bash
# Get API key from: https://brave.com/search/api/
export BRAVE_API_KEY="BSA..."
```

Free tier limits:
- 2,000 queries/month
- Rate limit: 1 query/second

## Security Best Practices

### 1. Credential Storage

**DO:**
- Use environment variables
- Use secret management services (AWS Secrets Manager, Azure Key Vault)
- Rotate credentials regularly
- Use least-privilege access

**DON'T:**
- Hardcode credentials in code
- Commit credentials to git
- Share credentials via email/chat
- Use the same credentials for dev/prod

### 2. Secret Management Integration

#### AWS Secrets Manager

```python
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

# Use with MCP
secrets = get_secret("code-mcp-credentials")
os.environ.update(secrets)
```

#### Azure Key Vault

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def get_azure_secrets(vault_url):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    
    secrets = {}
    for secret in client.list_properties_of_secrets():
        secrets[secret.name] = client.get_secret(secret.name).value
    
    return secrets

# Use with MCP
secrets = get_azure_secrets("https://myvault.vault.azure.net/")
os.environ.update(secrets)
```

#### HashiCorp Vault

```python
import hvac

def get_vault_secrets(vault_url, token):
    client = hvac.Client(url=vault_url, token=token)
    
    # Read secrets
    response = client.secrets.kv.v2.read_secret_version(
        path='code-mcp-credentials'
    )
    return response['data']['data']

# Use with MCP
secrets = get_vault_secrets("http://vault:8200", "s.xxxxx")
os.environ.update(secrets)
```

### 3. Credential Rotation

Implement automatic credential rotation:

```python
import asyncio
from datetime import datetime, timedelta

class CredentialManager:
    def __init__(self, rotation_interval=timedelta(days=30)):
        self.rotation_interval = rotation_interval
        self.last_rotation = {}
    
    async def rotate_if_needed(self, service: str):
        last = self.last_rotation.get(service, datetime.min)
        if datetime.now() - last > self.rotation_interval:
            await self.rotate_credentials(service)
            self.last_rotation[service] = datetime.now()
    
    async def rotate_credentials(self, service: str):
        # Implement rotation logic
        if service == "aws":
            # Create new access key
            # Update secret store
            # Delete old access key
            pass
        elif service == "azure":
            # Regenerate PAT
            # Update secret store
            pass
```

### 4. Audit Logging

Log all authentication events:

```python
import logging
from functools import wraps

auth_logger = logging.getLogger("auth_audit")

def audit_auth(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        service = args[0] if args else "unknown"
        auth_logger.info(f"Authentication attempt for {service}")
        
        try:
            result = await func(*args, **kwargs)
            auth_logger.info(f"Authentication successful for {service}")
            return result
        except Exception as e:
            auth_logger.error(f"Authentication failed for {service}: {e}")
            raise
    
    return wrapper
```

## Troubleshooting

### Common Authentication Errors

#### 1. Invalid API Key

**Error:**
```
MCPError -32001: Authentication failed: Invalid API key
```

**Solution:**
- Verify the API key is correct
- Check if the key is active/not expired
- Ensure no extra spaces or characters

#### 2. Missing Credentials

**Error:**
```
MCPError -32001: No credentials found for service 'slack'
```

**Solution:**
```bash
# Check environment variable is set
echo $SLACK_BOT_TOKEN

# Set if missing
export SLACK_BOT_TOKEN="xoxb-..."
```

#### 3. Insufficient Permissions

**Error:**
```
MCPError -32002: Permission denied: Insufficient scopes
```

**Solution:**
- Review required permissions for the operation
- Update API key/token with necessary scopes
- For cloud services, check IAM policies

#### 4. Rate Limiting

**Error:**
```
MCPError -32006: Rate limit exceeded
```

**Solution:**
```python
# Implement exponential backoff
import asyncio
from typing import TypeVar, Callable

T = TypeVar('T')

async def retry_with_backoff(
    func: Callable[..., T],
    max_retries: int = 3,
    base_delay: float = 1.0
) -> T:
    for attempt in range(max_retries):
        try:
            return await func()
        except MCPError as e:
            if e.code == -32006 and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                await asyncio.sleep(delay)
            else:
                raise
```

### Debug Authentication

Enable debug logging:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Trace authentication
logging.getLogger("mcp.auth").setLevel(logging.DEBUG)
```

Test authentication:

```python
async def test_authentication():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Test each service
    services = [
        "brave", "slack-notifications", "s3-storage",
        "azure-devops", "prometheus-monitoring"
    ]
    
    for service in services:
        try:
            info = await manager.get_server_info(service)
            print(f"✅ {service}: Authenticated")
        except MCPError as e:
            print(f"❌ {service}: {e.message}")
```

## Multi-Environment Setup

Configure different credentials for each environment:

```python
# config/environments.py
import os

ENVIRONMENTS = {
    "development": {
        "SLACK_CHANNEL": "#dev-alerts",
        "K8S_NAMESPACE": "development",
        "AWS_BUCKET": "dev-deployments"
    },
    "staging": {
        "SLACK_CHANNEL": "#staging-alerts",
        "K8S_NAMESPACE": "staging",
        "AWS_BUCKET": "staging-deployments"
    },
    "production": {
        "SLACK_CHANNEL": "#prod-alerts",
        "K8S_NAMESPACE": "production",
        "AWS_BUCKET": "prod-deployments"
    }
}

def load_environment(env_name: str):
    """Load environment-specific configuration."""
    env_config = ENVIRONMENTS.get(env_name, {})
    
    # Load base credentials
    base_env = {
        "ENVIRONMENT": env_name,
        "SLACK_BOT_TOKEN": os.getenv(f"{env_name.upper()}_SLACK_TOKEN"),
        "AWS_ACCESS_KEY_ID": os.getenv(f"{env_name.upper()}_AWS_KEY"),
        # ... more credentials
    }
    
    # Merge with environment config
    return {**base_env, **env_config}

# Usage
env_config = load_environment("production")
os.environ.update(env_config)
```

## Conclusion

Proper authentication is crucial for secure infrastructure automation. Always:

1. Use environment variables or secret management services
2. Follow the principle of least privilege
3. Rotate credentials regularly
4. Monitor authentication events
5. Test authentication before deployment

For more information, see:
- [Security Best Practices](./security_best_practices.md)
- [API Reference](../reference/mcp_tools_reference.md)
- [Troubleshooting Guide](./troubleshooting.md)