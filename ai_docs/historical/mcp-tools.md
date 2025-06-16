# MCP Tools Documentation

The Claude-Optimized Deployment Engine includes 51+ tools across 11 MCP (Model Context Protocol) servers, providing comprehensive infrastructure automation capabilities.

## Server Overview

| Server | Tools | Purpose | Status |
|--------|-------|---------|--------|
| [Brave Search](#brave-search-server) | 4 | Web search and research | ✅ Active |
| [Desktop Commander](#desktop-commander-server) | 6 | Terminal commands and file operations | ✅ Active |
| [Docker](#docker-server) | 8 | Container lifecycle management | ✅ Active |
| [Kubernetes](#kubernetes-server) | 6 | Cluster management | ✅ Active |
| [Azure DevOps](#azure-devops-server) | 5 | CI/CD pipeline automation | ✅ Active |
| [Windows System](#windows-system-server) | 4 | Windows automation | ✅ Active |
| [Prometheus](#prometheus-monitoring-server) | 3 | Metrics and monitoring | ✅ Active |
| [Security Scanner](#security-scanner-server) | 4 | Vulnerability assessment | ✅ Active |
| [Slack Notifications](#slack-notifications-server) | 3 | Team communication | ✅ Active |
| [S3 Storage](#s3-storage-server) | 4 | Cloud storage automation | ✅ Active |
| [Cloud Storage](#cloud-storage-server) | 4 | Multi-cloud storage | ✅ Active |

## Authentication & Configuration

### Environment Variables

```bash
# Web Search
BRAVE_API_KEY=your-brave-api-key

# Team Communication
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token

# Cloud Storage
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1

# DevOps
AZURE_DEVOPS_TOKEN=your-azure-token
AZURE_DEVOPS_ORGANIZATION=your-org

# Monitoring
PROMETHEUS_URL=http://localhost:9090

# System Configuration
KUBECONFIG=/path/to/kubeconfig
DOCKER_HOST=unix:///var/run/docker.sock
```

### Client Initialization

```python
from src.mcp.manager import get_mcp_manager

# Initialize MCP manager
manager = await get_mcp_manager()
await manager.initialize()

# List available servers
servers = manager.list_servers()
print(f"Available servers: {servers}")

# Get all tools
tools = manager.get_available_tools()
print(f"Total tools available: {len(tools)}")
```

---

## Brave Search Server

**Purpose**: Web search, news, local search, and image search capabilities.

### Tools

#### 1. brave_web_search

Search the web using Brave's search API.

**Parameters:**
- `query` (string, required): Search query
- `count` (integer, optional): Number of results (1-20, default: 10)
- `offset` (integer, optional): Pagination offset (default: 0)
- `country` (string, optional): Country code (e.g., 'US', 'GB')
- `search_lang` (string, optional): Language code (default: 'en')
- `safesearch` (string, optional): Safe search level ('off', 'moderate', 'strict')

**Example:**
```python
result = await manager.call_tool("brave", "brave_web_search", {
    "query": "Docker best practices 2025",
    "count": 5,
    "safesearch": "moderate"
})

print(f"Found {len(result['results'])} results")
for item in result['results']:
    print(f"- {item['title']}: {item['url']}")
```

**Response:**
```json
{
  "query": "Docker best practices 2025",
  "results": [
    {
      "title": "Docker Best Practices Guide 2025",
      "url": "https://example.com/docker-guide",
      "description": "Comprehensive guide to Docker best practices...",
      "snippet": "Use multi-stage builds, minimize layer count..."
    }
  ],
  "metadata": {
    "total_results": 5,
    "query_info": {}
  }
}
```

#### 2. brave_local_search

Search for local businesses and places.

**Parameters:**
- `query` (string, required): Local search query
- `count` (integer, optional): Number of results (1-20, default: 5)

**Example:**
```python
result = await manager.call_tool("brave", "brave_local_search", {
    "query": "cloud providers near Silicon Valley",
    "count": 3
})
```

#### 3. brave_news_search

Search for recent news articles.

**Parameters:**
- `query` (string, required): News search query
- `count` (integer, optional): Number of results (1-20, default: 10)
- `freshness` (string, optional): Time range ('pd', 'pw', 'pm', 'py')

**Example:**
```python
result = await manager.call_tool("brave", "brave_news_search", {
    "query": "Kubernetes security vulnerabilities",
    "count": 5,
    "freshness": "pw"  # past week
})
```

#### 4. brave_image_search

Search for images on the web.

**Parameters:**
- `query` (string, required): Image search query
- `count` (integer, optional): Number of results (1-50, default: 10)
- `size` (string, optional): Size filter ('small', 'medium', 'large', 'all')

**Example:**
```python
result = await manager.call_tool("brave", "brave_image_search", {
    "query": "docker architecture diagram",
    "count": 10,
    "size": "large"
})
```

---

## Desktop Commander Server

**Purpose**: Terminal command execution and file management for infrastructure automation.

### Tools

#### 1. execute_command

Execute terminal commands with proper error handling and timeouts.

**Parameters:**
- `command` (string, required): Terminal command to execute
- `working_directory` (string, optional): Working directory
- `timeout` (integer, optional): Timeout in seconds (default: 300)

**Example:**
```python
# Check system status
result = await manager.call_tool("desktop-commander", "execute_command", {
    "command": "systemctl status docker",
    "timeout": 30
})

# Build project
result = await manager.call_tool("desktop-commander", "execute_command", {
    "command": "make build",
    "working_directory": "/path/to/project"
})
```

**Response:**
```json
{
  "success": true,
  "stdout": "● docker.service - Docker Application Container Engine\n   Loaded: loaded...",
  "stderr": "",
  "exit_code": 0,
  "execution_time": 0.234,
  "working_directory": "/current/path"
}
```

#### 2. read_file

Read file contents for configuration management.

**Parameters:**
- `file_path` (string, required): Path to file
- `encoding` (string, optional): File encoding (default: 'utf-8')

**Example:**
```python
result = await manager.call_tool("desktop-commander", "read_file", {
    "file_path": "./docker-compose.yml"
})

print(result['content'])
```

#### 3. write_file

Write content to files for configuration generation.

**Parameters:**
- `file_path` (string, required): Path to file
- `content` (string, required): File content
- `encoding` (string, optional): File encoding (default: 'utf-8')
- `create_dirs` (boolean, optional): Create parent directories (default: true)

**Example:**
```python
nginx_config = """
events {
    worker_connections 1024;
}
http {
    upstream app {
        server app:8000;
    }
    server {
        listen 80;
        location / {
            proxy_pass http://app;
        }
    }
}
"""

result = await manager.call_tool("desktop-commander", "write_file", {
    "file_path": "./nginx/nginx.conf",
    "content": nginx_config,
    "create_dirs": True
})
```

#### 4. list_directory

List directory contents with detailed information.

**Parameters:**
- `directory_path` (string, required): Directory to list
- `include_hidden` (boolean, optional): Include hidden files (default: false)
- `recursive` (boolean, optional): Recursive listing (default: false)

**Example:**
```python
result = await manager.call_tool("desktop-commander", "list_directory", {
    "directory_path": "./k8s",
    "include_hidden": False,
    "recursive": True
})
```

#### 5. make_command

Execute Makefile targets for project automation.

**Parameters:**
- `target` (string, required): Make target to execute
- `working_directory` (string, optional): Working directory
- `variables` (object, optional): Make variables

**Example:**
```python
result = await manager.call_tool("desktop-commander", "make_command", {
    "target": "docker-build",
    "variables": {
        "TAG": "v1.2.3",
        "ENV": "production"
    }
})
```

#### 6. check_file_exists

Check if files or directories exist.

**Parameters:**
- `path` (string, required): Path to check
- `check_type` (string, optional): Type check ('file', 'directory', 'any')

**Example:**
```python
result = await manager.call_tool("desktop-commander", "check_file_exists", {
    "path": "./Dockerfile",
    "check_type": "file"
})

if result['exists']:
    print("Dockerfile found, proceeding with build...")
```

---

## Docker Server

**Purpose**: Complete Docker container lifecycle management and orchestration.

### Tools

#### 1. docker_build

Build Docker images from Dockerfiles with advanced options.

**Parameters:**
- `dockerfile_path` (string, required): Path to Dockerfile or build context
- `image_tag` (string, required): Image tag/name
- `build_args` (object, optional): Build arguments
- `target` (string, optional): Multi-stage build target
- `no_cache` (boolean, optional): Don't use build cache
- `pull` (boolean, optional): Always pull base images

**Example:**
```python
result = await manager.call_tool("docker", "docker_build", {
    "dockerfile_path": ".",
    "image_tag": "my-app:latest",
    "build_args": {
        "NODE_VERSION": "18",
        "BUILD_ENV": "production"
    },
    "target": "production",
    "pull": True
})
```

**Response:**
```json
{
  "success": true,
  "image_id": "sha256:abc123...",
  "image_tag": "my-app:latest",
  "build_time": 45.6,
  "size_mb": 234.5,
  "layers": 12,
  "warnings": []
}
```

#### 2. docker_run

Start containers with comprehensive configuration options.

**Parameters:**
- `image` (string, required): Docker image to run
- `container_name` (string, optional): Container name
- `ports` (array, optional): Port mappings
- `environment` (object, optional): Environment variables
- `volumes` (array, optional): Volume mounts
- `networks` (array, optional): Networks to join
- `detach` (boolean, optional): Run in background (default: true)
- `remove` (boolean, optional): Remove container on exit

**Example:**
```python
result = await manager.call_tool("docker", "docker_run", {
    "image": "my-app:latest",
    "container_name": "my-app-prod",
    "ports": ["80:8000", "443:8443"],
    "environment": {
        "DATABASE_URL": "postgresql://user:pass@db:5432/myapp",
        "REDIS_URL": "redis://redis:6379",
        "LOG_LEVEL": "INFO"
    },
    "volumes": [
        "./logs:/app/logs",
        "./config:/app/config:ro"
    ],
    "networks": ["app-network"],
    "detach": True
})
```

#### 3. docker_ps

List and monitor running containers with detailed information.

**Parameters:**
- `all` (boolean, optional): Show all containers, not just running
- `filter` (object, optional): Filter criteria
- `format` (string, optional): Output format

**Example:**
```python
result = await manager.call_tool("docker", "docker_ps", {
    "all": False,
    "filter": {
        "status": "running",
        "label": "env=production"
    }
})

for container in result['containers']:
    print(f"{container['name']}: {container['status']}")
```

#### 4. docker_logs

Retrieve container logs with filtering and streaming options.

**Parameters:**
- `container` (string, required): Container name or ID
- `follow` (boolean, optional): Follow log output
- `tail` (integer, optional): Number of lines from end
- `since` (string, optional): Show logs since timestamp/duration
- `timestamps` (boolean, optional): Show timestamps

**Example:**
```python
result = await manager.call_tool("docker", "docker_logs", {
    "container": "my-app-prod",
    "tail": 100,
    "since": "1h",
    "timestamps": True
})
```

#### 5. docker_stop

Stop running containers gracefully or forcefully.

**Parameters:**
- `container` (string, required): Container name or ID
- `timeout` (integer, optional): Seconds to wait before killing (default: 10)

**Example:**
```python
result = await manager.call_tool("docker", "docker_stop", {
    "container": "my-app-prod",
    "timeout": 30
})
```

#### 6. docker_remove

Remove containers with various options.

**Parameters:**
- `container` (string, required): Container name or ID
- `force` (boolean, optional): Force removal of running container
- `volumes` (boolean, optional): Remove associated volumes

**Example:**
```python
result = await manager.call_tool("docker", "docker_remove", {
    "container": "old-container",
    "force": True,
    "volumes": True
})
```

#### 7. docker_images

List Docker images with filtering and formatting.

**Parameters:**
- `all` (boolean, optional): Show all images, including intermediates
- `filter` (object, optional): Filter criteria
- `format` (string, optional): Output format

**Example:**
```python
result = await manager.call_tool("docker", "docker_images", {
    "filter": {
        "label": "app=my-app"
    }
})
```

#### 8. docker_system_prune

Clean up unused Docker resources.

**Parameters:**
- `all` (boolean, optional): Remove all unused images, not just dangling
- `volumes` (boolean, optional): Prune volumes
- `force` (boolean, optional): Don't prompt for confirmation

**Example:**
```python
result = await manager.call_tool("docker", "docker_system_prune", {
    "all": True,
    "volumes": True,
    "force": True
})

print(f"Reclaimed {result['space_reclaimed']} of disk space")
```

---

## Kubernetes Server

**Purpose**: Comprehensive Kubernetes cluster management and application deployment.

### Tools

#### 1. kubectl_apply

Deploy resources to Kubernetes cluster.

**Parameters:**
- `manifest_path` (string, required): Path to manifest file or directory
- `namespace` (string, optional): Target namespace
- `dry_run` (boolean, optional): Perform dry run
- `validate` (boolean, optional): Validate manifests (default: true)
- `recursive` (boolean, optional): Process directories recursively

**Example:**
```python
result = await manager.call_tool("kubernetes", "kubectl_apply", {
    "manifest_path": "./k8s/production",
    "namespace": "prod",
    "recursive": True,
    "validate": True
})
```

**Response:**
```json
{
  "success": true,
  "applied_resources": [
    {
      "kind": "Deployment",
      "name": "my-app",
      "namespace": "prod",
      "action": "configured"
    },
    {
      "kind": "Service", 
      "name": "my-app-service",
      "namespace": "prod",
      "action": "created"
    }
  ],
  "warnings": [],
  "execution_time": 2.34
}
```

#### 2. kubectl_get

Query Kubernetes resources with powerful filtering.

**Parameters:**
- `resource` (string, required): Resource type (pods, services, deployments, etc.)
- `name` (string, optional): Specific resource name
- `namespace` (string, optional): Target namespace
- `selector` (string, optional): Label selector
- `output` (string, optional): Output format (json, yaml, wide, etc.)
- `all_namespaces` (boolean, optional): Query all namespaces

**Example:**
```python
# Get all pods in production namespace
result = await manager.call_tool("kubernetes", "kubectl_get", {
    "resource": "pods",
    "namespace": "prod",
    "selector": "app=my-app",
    "output": "json"
})

# Get deployment status
result = await manager.call_tool("kubernetes", "kubectl_get", {
    "resource": "deployment",
    "name": "my-app",
    "namespace": "prod"
})
```

#### 3. kubectl_delete

Remove resources from Kubernetes cluster.

**Parameters:**
- `resource` (string, required): Resource type or manifest path
- `name` (string, optional): Resource name
- `namespace` (string, optional): Target namespace
- `selector` (string, optional): Label selector
- `force` (boolean, optional): Force deletion
- `grace_period` (integer, optional): Grace period in seconds

**Example:**
```python
# Delete specific deployment
result = await manager.call_tool("kubernetes", "kubectl_delete", {
    "resource": "deployment",
    "name": "old-app",
    "namespace": "staging"
})

# Delete all resources with label
result = await manager.call_tool("kubernetes", "kubectl_delete", {
    "resource": "all",
    "selector": "version=v1.0.0",
    "namespace": "dev"
})
```

#### 4. kubectl_scale

Scale deployments and statefulsets.

**Parameters:**
- `resource` (string, required): Resource type (deployment, statefulset, etc.)
- `name` (string, required): Resource name
- `replicas` (integer, required): Target replica count
- `namespace` (string, optional): Target namespace

**Example:**
```python
result = await manager.call_tool("kubernetes", "kubectl_scale", {
    "resource": "deployment",
    "name": "my-app",
    "replicas": 5,
    "namespace": "prod"
})
```

#### 5. kubectl_rollout

Manage deployment rollouts.

**Parameters:**
- `action` (string, required): Rollout action (status, restart, undo, pause, resume)
- `resource` (string, required): Resource type
- `name` (string, required): Resource name
- `namespace` (string, optional): Target namespace
- `revision` (integer, optional): Revision number for undo

**Example:**
```python
# Check rollout status
result = await manager.call_tool("kubernetes", "kubectl_rollout", {
    "action": "status",
    "resource": "deployment",
    "name": "my-app",
    "namespace": "prod"
})

# Rollback to previous version
result = await manager.call_tool("kubernetes", "kubectl_rollout", {
    "action": "undo",
    "resource": "deployment", 
    "name": "my-app",
    "namespace": "prod"
})
```

#### 6. kubectl_logs

Retrieve pod logs with advanced filtering.

**Parameters:**
- `pod_name` (string, required): Pod name
- `namespace` (string, optional): Target namespace
- `container` (string, optional): Container name in pod
- `follow` (boolean, optional): Follow log stream
- `tail` (integer, optional): Number of lines from end
- `since` (string, optional): Show logs since timestamp/duration
- `previous` (boolean, optional): Show logs from previous container

**Example:**
```python
result = await manager.call_tool("kubernetes", "kubectl_logs", {
    "pod_name": "my-app-6b7d4c8f9-xyz12",
    "namespace": "prod",
    "container": "app",
    "tail": 100,
    "since": "1h"
})
```

---

## Azure DevOps Server

**Purpose**: Enterprise CI/CD pipeline automation and project management.

### Tools

#### 1. list_projects

Discover and manage Azure DevOps projects.

**Parameters:**
- `organization` (string, optional): DevOps organization (from env if not provided)
- `state_filter` (string, optional): Project state filter (wellFormed, createPending, etc.)

**Example:**
```python
result = await manager.call_tool("azure-devops", "list_projects", {
    "organization": "my-company"
})

for project in result['projects']:
    print(f"Project: {project['name']} - {project['description']}")
```

#### 2. create_pipeline

Set up automated build and deployment pipelines.

**Parameters:**
- `project` (string, required): Project name or ID
- `name` (string, required): Pipeline name
- `repository` (object, required): Repository configuration
- `yaml_path` (string, required): Path to pipeline YAML
- `folder_path` (string, optional): Pipeline folder path

**Example:**
```python
result = await manager.call_tool("azure-devops", "create_pipeline", {
    "project": "my-web-app",
    "name": "Production Deployment",
    "repository": {
        "type": "TfsGit",
        "name": "my-web-app",
        "default_branch": "main"
    },
    "yaml_path": "/.azure-pipelines/production.yml",
    "folder_path": "\\Production"
})
```

#### 3. run_pipeline

Trigger pipeline execution with parameters.

**Parameters:**
- `project` (string, required): Project name or ID
- `pipeline_id` (integer, required): Pipeline ID
- `branch` (string, optional): Source branch
- `parameters` (object, optional): Pipeline parameters

**Example:**
```python
result = await manager.call_tool("azure-devops", "run_pipeline", {
    "project": "my-web-app",
    "pipeline_id": 123,
    "branch": "main",
    "parameters": {
        "environment": "production",
        "deploy_version": "v2.1.0"
    }
})
```

#### 4. get_build_status

Monitor build and deployment status.

**Parameters:**
- `project` (string, required): Project name or ID
- `build_id` (integer, required): Build ID

**Example:**
```python
result = await manager.call_tool("azure-devops", "get_build_status", {
    "project": "my-web-app",
    "build_id": 5678
})

print(f"Build status: {result['status']}")
print(f"Result: {result['result']}")
```

#### 5. manage_work_items

Create and track development tasks.

**Parameters:**
- `action` (string, required): Action (create, update, get, query)
- `project` (string, required): Project name or ID
- `work_item_type` (string, required): Work item type (Bug, Task, User Story, etc.)
- `title` (string, required for create): Work item title
- `description` (string, optional): Work item description
- `assigned_to` (string, optional): Assignee email
- `work_item_id` (integer, required for update/get): Work item ID

**Example:**
```python
# Create new task
result = await manager.call_tool("azure-devops", "manage_work_items", {
    "action": "create",
    "project": "my-web-app",
    "work_item_type": "Task",
    "title": "Implement new authentication system",
    "description": "Add OAuth2 support with PKCE flow",
    "assigned_to": "developer@company.com"
})

# Update existing task
result = await manager.call_tool("azure-devops", "manage_work_items", {
    "action": "update",
    "project": "my-web-app",
    "work_item_id": 1234,
    "title": "Updated: Implement new authentication system",
    "assigned_to": "senior-dev@company.com"
})
```

---

## Windows System Server

**Purpose**: Native Windows automation and system management capabilities.

### Tools

#### 1. powershell_command

Execute PowerShell scripts and commands with full Windows integration.

**Parameters:**
- `command` (string, required): PowerShell command or script
- `execution_policy` (string, optional): Execution policy override
- `working_directory` (string, optional): Working directory
- `timeout` (integer, optional): Timeout in seconds

**Example:**
```python
# Check Windows services
result = await manager.call_tool("windows-system", "powershell_command", {
    "command": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, Status"
})

# Install Windows features
result = await manager.call_tool("windows-system", "powershell_command", {
    "command": "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux",
    "execution_policy": "Bypass"
})

# Deploy IIS application
script = """
Import-Module WebAdministration
New-WebSite -Name "MyApp" -Port 8080 -PhysicalPath "C:\\inetpub\\myapp"
New-WebApplication -Site "MyApp" -Name "api" -PhysicalPath "C:\\inetpub\\myapp\\api"
"""

result = await manager.call_tool("windows-system", "powershell_command", {
    "command": script
})
```

#### 2. registry_operations

Read and modify Windows registry for system configuration.

**Parameters:**
- `action` (string, required): Registry action (get, set, delete, create_key)
- `hive` (string, required): Registry hive (HKLM, HKCU, etc.)
- `key_path` (string, required): Registry key path
- `value_name` (string, optional): Registry value name
- `value_data` (string, optional): Value data for set operations
- `value_type` (string, optional): Value type (String, DWORD, Binary, etc.)

**Example:**
```python
# Read registry value
result = await manager.call_tool("windows-system", "registry_operations", {
    "action": "get",
    "hive": "HKLM",
    "key_path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
    "value_name": "ProductName"
})

# Set registry value for application configuration
result = await manager.call_tool("windows-system", "registry_operations", {
    "action": "set",
    "hive": "HKLM",
    "key_path": "SOFTWARE\\MyCompany\\MyApp",
    "value_name": "ApiEndpoint",
    "value_data": "https://api.mycompany.com",
    "value_type": "String"
})
```

#### 3. service_management

Control Windows services for application deployment.

**Parameters:**
- `action` (string, required): Service action (start, stop, restart, get_status, set_startup)
- `service_name` (string, required): Windows service name
- `startup_type` (string, optional): Startup type (Automatic, Manual, Disabled)

**Example:**
```python
# Start IIS service
result = await manager.call_tool("windows-system", "service_management", {
    "action": "start",
    "service_name": "W3SVC"
})

# Set service to automatic startup
result = await manager.call_tool("windows-system", "service_management", {
    "action": "set_startup",
    "service_name": "MyAppService",
    "startup_type": "Automatic"
})

# Check service status
result = await manager.call_tool("windows-system", "service_management", {
    "action": "get_status",
    "service_name": "MSSQLSERVER"
})
```

#### 4. windows_feature_management

Manage Windows features and roles.

**Parameters:**
- `action` (string, required): Feature action (enable, disable, get_status)
- `feature_name` (string, required): Windows feature name
- `include_management_tools` (boolean, optional): Include management tools

**Example:**
```python
# Enable IIS
result = await manager.call_tool("windows-system", "windows_feature_management", {
    "action": "enable",
    "feature_name": "IIS-WebServerRole",
    "include_management_tools": True
})

# Enable .NET Framework
result = await manager.call_tool("windows-system", "windows_feature_management", {
    "action": "enable",
    "feature_name": "NetFx3"
})
```

---

## Prometheus Monitoring Server

**Purpose**: Real-time observability, metrics collection, and system monitoring.

### Tools

#### 1. prometheus_query

Execute PromQL queries for instant metrics.

**Parameters:**
- `query` (string, required): PromQL query
- `time` (string, optional): Evaluation timestamp (RFC3339 or Unix timestamp)
- `timeout` (string, optional): Query timeout

**Example:**
```python
# Check CPU usage
result = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
    "query": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
})

# Memory usage percentage
result = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
    "query": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100"
})

# Application-specific metrics
result = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
    "query": "rate(http_requests_total{service=\"my-app\"}[5m])"
})
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {
          "instance": "localhost:9090"
        },
        "value": [1635724800, "42.5"]
      }
    ]
  }
}
```

#### 2. prometheus_query_range

Execute time-series data analysis over ranges.

**Parameters:**
- `query` (string, required): PromQL query
- `start` (string, required): Start timestamp (RFC3339 or Unix)
- `end` (string, required): End timestamp (RFC3339 or Unix)
- `step` (string, required): Query resolution step (e.g., '15s', '1m', '1h')

**Example:**
```python
# Get 24 hours of CPU metrics
result = await manager.call_tool("prometheus-monitoring", "prometheus_query_range", {
    "query": "avg(rate(cpu_usage_total[5m]))",
    "start": "2025-05-30T00:00:00Z",
    "end": "2025-05-31T00:00:00Z", 
    "step": "5m"
})

# Application response time trend
result = await manager.call_tool("prometheus-monitoring", "prometheus_query_range", {
    "query": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
    "start": "2025-05-31T08:00:00Z",
    "end": "2025-05-31T16:00:00Z",
    "step": "1m"
})
```

#### 3. prometheus_targets

Monitor service discovery and target health.

**Parameters:**
- `state` (string, optional): Target state filter (active, dropped, any)

**Example:**
```python
result = await manager.call_tool("prometheus-monitoring", "prometheus_targets", {
    "state": "active"
})

# Check for unhealthy targets
unhealthy = [t for t in result['data']['activeTargets'] if t['health'] != 'up']
if unhealthy:
    print(f"Warning: {len(unhealthy)} targets are down")
```

---

## Security Scanner Server

**Purpose**: Comprehensive vulnerability management and security assessment.

### Tools

#### 1. npm_audit

JavaScript dependency vulnerability scanning.

**Parameters:**
- `package_json_path` (string, required): Path to package.json
- `audit_level` (string, optional): Audit level (info, low, moderate, high, critical)
- `production_only` (boolean, optional): Only check production dependencies
- `fix` (boolean, optional): Attempt to fix vulnerabilities

**Example:**
```python
result = await manager.call_tool("security-scanner", "npm_audit", {
    "package_json_path": "./package.json",
    "audit_level": "high",
    "production_only": True
})

if result['vulnerabilities']['total'] > 0:
    print(f"Found {result['vulnerabilities']['high']} high severity vulnerabilities")
    for vuln in result['advisories']:
        print(f"- {vuln['title']}: {vuln['url']}")
```

**Response:**
```json
{
  "actions": [],
  "advisories": [
    {
      "id": 1179,
      "title": "Prototype Pollution",
      "module_name": "lodash",
      "severity": "high",
      "url": "https://npmjs.com/advisories/1179",
      "vulnerable_versions": "<4.17.12"
    }
  ],
  "vulnerabilities": {
    "total": 5,
    "critical": 0,
    "high": 2,
    "moderate": 3,
    "low": 0
  }
}
```

#### 2. python_safety_check

Python package security assessment.

**Parameters:**
- `requirements_path` (string, required): Path to requirements.txt or Pipfile
- `full_report` (boolean, optional): Generate detailed report
- `ignore` (array, optional): Vulnerability IDs to ignore

**Example:**
```python
result = await manager.call_tool("security-scanner", "python_safety_check", {
    "requirements_path": "./requirements.txt",
    "full_report": True,
    "ignore": ["38765"]  # Ignore specific non-critical vulnerability
})
```

#### 3. docker_security_scan

Container image vulnerability analysis.

**Parameters:**
- `image_name` (string, required): Docker image name and tag
- `severity_threshold` (string, optional): Minimum severity to report
- `scan_layers` (boolean, optional): Include layer-by-layer analysis

**Example:**
```python
result = await manager.call_tool("security-scanner", "docker_security_scan", {
    "image_name": "my-app:latest",
    "severity_threshold": "medium",
    "scan_layers": True
})

print(f"Found {result['summary']['total']} vulnerabilities")
print(f"Critical: {result['summary']['critical']}")
print(f"High: {result['summary']['high']}")
```

#### 4. file_security_scan

Source code security pattern detection.

**Parameters:**
- `file_path` (string, required): Path to file or directory
- `scan_type` (string, optional): Scan type (secrets, patterns, all)
- `recursive` (boolean, optional): Scan directories recursively
- `exclude_patterns` (array, optional): File patterns to exclude

**Example:**
```python
result = await manager.call_tool("security-scanner", "file_security_scan", {
    "file_path": "./src",
    "scan_type": "all",
    "recursive": True,
    "exclude_patterns": ["*.test.js", "*.spec.py", "node_modules/*"]
})

if result['findings']:
    print("Security issues found:")
    for finding in result['findings']:
        print(f"- {finding['file']}: {finding['issue_type']}")
```

---

## Slack Notifications Server

**Purpose**: Team communication automation and deployment notifications.

### Tools

#### 1. send_notification

Send formatted deployment and status updates.

**Parameters:**
- `channel` (string, required): Slack channel name or ID
- `message` (string, required): Message text
- `severity` (string, optional): Message severity (info, warning, error, success)
- `attachments` (array, optional): Rich message attachments
- `mention_users` (array, optional): Users to mention

**Example:**
```python
# Deployment notification
result = await manager.call_tool("slack-notifications", "send_notification", {
    "channel": "#deployments",
    "message": "🚀 Production deployment completed successfully",
    "severity": "success",
    "attachments": [
        {
            "title": "Deployment Details",
            "fields": [
                {"title": "Version", "value": "v2.1.0", "short": True},
                {"title": "Environment", "value": "Production", "short": True},
                {"title": "Duration", "value": "3m 45s", "short": True}
            ],
            "color": "good"
        }
    ]
})

# Alert notification
result = await manager.call_tool("slack-notifications", "send_notification", {
    "channel": "#alerts",
    "message": "⚠️ High CPU usage detected on production servers",
    "severity": "warning",
    "mention_users": ["@oncall-engineer", "@sre-team"]
})
```

#### 2. post_message

Direct team communication with rich formatting.

**Parameters:**
- `channel` (string, required): Slack channel name or ID
- `text` (string, required): Message text
- `blocks` (array, optional): Slack Block Kit blocks
- `thread_ts` (string, optional): Thread timestamp for replies

**Example:**
```python
result = await manager.call_tool("slack-notifications", "post_message", {
    "channel": "#general",
    "text": "Security scan completed",
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Security Scan Results*\n\n✅ No critical vulnerabilities found\n⚠️ 3 medium severity issues detected"
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report"},
                    "url": "https://security.company.com/reports/123"
                }
            ]
        }
    ]
})
```

#### 3. list_channels

Channel discovery and management.

**Parameters:**
- `types` (string, optional): Channel types (public_channel, private_channel, im, mpim)
- `exclude_archived` (boolean, optional): Exclude archived channels

**Example:**
```python
result = await manager.call_tool("slack-notifications", "list_channels", {
    "types": "public_channel,private_channel",
    "exclude_archived": True
})

deployment_channels = [c for c in result['channels'] if 'deploy' in c['name']]
```

---

## S3 Storage Server

**Purpose**: Cloud storage automation for artifacts and backups.

### Tools

#### 1. s3_upload_file

Upload files and artifacts to S3 buckets.

**Parameters:**
- `local_path` (string, required): Local file path
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `metadata` (object, optional): Object metadata
- `storage_class` (string, optional): Storage class (STANDARD, IA, GLACIER, etc.)
- `acl` (string, optional): Access control list

**Example:**
```python
# Upload deployment artifact
result = await manager.call_tool("s3-storage", "s3_upload_file", {
    "local_path": "./dist/app-v2.1.0.tar.gz",
    "bucket": "company-artifacts",
    "key": "releases/app/v2.1.0/app-v2.1.0.tar.gz",
    "metadata": {
        "version": "v2.1.0",
        "build-timestamp": "2025-05-31T10:00:00Z",
        "commit-sha": "abc123def456"
    },
    "storage_class": "STANDARD"
})

# Upload backup
result = await manager.call_tool("s3-storage", "s3_upload_file", {
    "local_path": "./backup/database-20250531.sql.gz",
    "bucket": "company-backups",
    "key": "database/2025/05/31/database-20250531.sql.gz",
    "storage_class": "GLACIER"
})
```

#### 2. s3_download_file

Download files from S3 storage.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `local_path` (string, required): Local destination path

**Example:**
```python
result = await manager.call_tool("s3-storage", "s3_download_file", {
    "bucket": "company-artifacts", 
    "key": "releases/app/v2.0.9/app-v2.0.9.tar.gz",
    "local_path": "./rollback/app-v2.0.9.tar.gz"
})
```

#### 3. s3_list_objects

List and search objects in S3 buckets.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `prefix` (string, optional): Object key prefix filter
- `max_keys` (integer, optional): Maximum number of keys to return

**Example:**
```python
result = await manager.call_tool("s3-storage", "s3_list_objects", {
    "bucket": "company-artifacts",
    "prefix": "releases/app/",
    "max_keys": 50
})

versions = [obj['Key'] for obj in result['objects'] if obj['Key'].endswith('.tar.gz')]
```

#### 4. s3_create_presigned_url

Generate secure file sharing and access URLs.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `expiration` (integer, optional): URL expiration in seconds (default: 3600)
- `http_method` (string, optional): HTTP method (GET, PUT, POST)

**Example:**
```python
# Create download link for artifact
result = await manager.call_tool("s3-storage", "s3_create_presigned_url", {
    "bucket": "company-artifacts",
    "key": "releases/app/v2.1.0/app-v2.1.0.tar.gz",
    "expiration": 7200,  # 2 hours
    "http_method": "GET"
})

download_url = result['presigned_url']
print(f"Download artifact: {download_url}")
```

---

## Cloud Storage Server

**Purpose**: Multi-cloud storage management and synchronization.

### Tools

#### 1. multi_cloud_upload

Upload files to multiple cloud providers simultaneously.

**Parameters:**
- `local_path` (string, required): Local file path
- `destinations` (array, required): Cloud storage destinations
- `sync_metadata` (boolean, optional): Synchronize metadata across providers

**Example:**
```python
result = await manager.call_tool("cloud-storage", "multi_cloud_upload", {
    "local_path": "./critical-backup.tar.gz",
    "destinations": [
        {
            "provider": "aws",
            "bucket": "company-backups-aws",
            "key": "critical/backup-20250531.tar.gz"
        },
        {
            "provider": "azure",
            "container": "company-backups-azure",
            "blob": "critical/backup-20250531.tar.gz"
        },
        {
            "provider": "gcp",
            "bucket": "company-backups-gcp",
            "object": "critical/backup-20250531.tar.gz"
        }
    ],
    "sync_metadata": True
})
```

#### 2. cloud_storage_sync

Synchronize storage between different cloud providers.

**Parameters:**
- `source` (object, required): Source storage configuration
- `destination` (object, required): Destination storage configuration
- `sync_type` (string, optional): Sync type (incremental, full, bidirectional)

**Example:**
```python
result = await manager.call_tool("cloud-storage", "cloud_storage_sync", {
    "source": {
        "provider": "aws",
        "bucket": "primary-storage",
        "prefix": "production/"
    },
    "destination": {
        "provider": "azure",
        "container": "backup-storage",
        "prefix": "production-backup/"
    },
    "sync_type": "incremental"
})
```

#### 3. storage_health_check

Monitor cloud storage health and availability.

**Parameters:**
- `providers` (array, optional): Specific providers to check
- `include_metrics` (boolean, optional): Include performance metrics

**Example:**
```python
result = await manager.call_tool("cloud-storage", "storage_health_check", {
    "providers": ["aws", "azure", "gcp"],
    "include_metrics": True
})

for provider in result['health_status']:
    if provider['status'] != 'healthy':
        print(f"Warning: {provider['provider']} storage issues detected")
```

#### 4. cost_optimization_analysis

Analyze and optimize cloud storage costs.

**Parameters:**
- `time_range` (string, optional): Analysis time range (1d, 7d, 30d, 90d)
- `include_recommendations` (boolean, optional): Include cost optimization suggestions

**Example:**
```python
result = await manager.call_tool("cloud-storage", "cost_optimization_analysis", {
    "time_range": "30d",
    "include_recommendations": True
})

if result['potential_savings'] > 0:
    print(f"Potential monthly savings: ${result['potential_savings']:.2f}")
    for rec in result['recommendations']:
        print(f"- {rec['description']}")
```

---

## Integration Examples

### Complete Deployment Workflow

Here's a comprehensive example combining multiple MCP tools for a complete deployment workflow:

```python
async def deploy_application():
    manager = await get_mcp_manager()
    await manager.initialize()
    
    try:
        # 1. Run security scan
        print("🔍 Running security scan...")
        security_result = await manager.call_tool("security-scanner", "npm_audit", {
            "package_json_path": "./package.json",
            "audit_level": "high"
        })
        
        if security_result['vulnerabilities']['high'] > 0:
            await manager.call_tool("slack-notifications", "send_notification", {
                "channel": "#security",
                "message": f"⚠️ High severity vulnerabilities found: {security_result['vulnerabilities']['high']}",
                "severity": "warning"
            })
            return
        
        # 2. Build Docker image
        print("🏗️ Building Docker image...")
        build_result = await manager.call_tool("docker", "docker_build", {
            "dockerfile_path": ".",
            "image_tag": "my-app:v2.1.0",
            "build_args": {
                "NODE_VERSION": "18",
                "BUILD_ENV": "production"
            }
        })
        
        # 3. Deploy to Kubernetes
        print("🚀 Deploying to Kubernetes...")
        deploy_result = await manager.call_tool("kubernetes", "kubectl_apply", {
            "manifest_path": "./k8s/production",
            "namespace": "prod",
            "recursive": True
        })
        
        # 4. Monitor deployment
        print("📊 Checking deployment status...")
        await asyncio.sleep(30)  # Wait for rollout
        
        status_result = await manager.call_tool("kubernetes", "kubectl_rollout", {
            "action": "status",
            "resource": "deployment",
            "name": "my-app",
            "namespace": "prod"
        })
        
        # 5. Upload artifacts to S3
        print("📦 Uploading artifacts...")
        upload_result = await manager.call_tool("s3-storage", "s3_upload_file", {
            "local_path": "./dist/app-v2.1.0.tar.gz",
            "bucket": "company-artifacts",
            "key": "releases/app/v2.1.0/app-v2.1.0.tar.gz",
            "metadata": {
                "version": "v2.1.0",
                "deployment-timestamp": datetime.now().isoformat()
            }
        })
        
        # 6. Send success notification
        await manager.call_tool("slack-notifications", "send_notification", {
            "channel": "#deployments",
            "message": "🎉 Production deployment v2.1.0 completed successfully!",
            "severity": "success",
            "attachments": [
                {
                    "title": "Deployment Summary",
                    "fields": [
                        {"title": "Version", "value": "v2.1.0", "short": True},
                        {"title": "Environment", "value": "Production", "short": True},
                        {"title": "Build Time", "value": f"{build_result['build_time']:.1f}s", "short": True},
                        {"title": "Image Size", "value": f"{build_result['size_mb']:.1f}MB", "short": True}
                    ],
                    "color": "good"
                }
            ]
        })
        
        print("✅ Deployment completed successfully!")
        
    except Exception as e:
        # Send error notification
        await manager.call_tool("slack-notifications", "send_notification", {
            "channel": "#deployments",
            "message": f"❌ Deployment failed: {str(e)}",
            "severity": "error",
            "mention_users": ["@oncall-engineer"]
        })
        
        print(f"❌ Deployment failed: {e}")
        raise

# Run deployment
await deploy_application()
```

### Monitoring Dashboard Data

```python
async def get_monitoring_dashboard():
    manager = await get_mcp_manager()
    
    # Get system metrics
    cpu_usage = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
        "query": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
    })
    
    memory_usage = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
        "query": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100"
    })
    
    # Get application metrics
    request_rate = await manager.call_tool("prometheus-monitoring", "prometheus_query", {
        "query": "sum(rate(http_requests_total[5m]))"
    })
    
    # Get Kubernetes status
    pods_status = await manager.call_tool("kubernetes", "kubectl_get", {
        "resource": "pods",
        "namespace": "prod",
        "output": "json"
    })
    
    # Create dashboard data
    dashboard = {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "cpu_usage": float(cpu_usage['data']['result'][0]['value'][1]),
            "memory_usage": float(memory_usage['data']['result'][0]['value'][1])
        },
        "application": {
            "request_rate": float(request_rate['data']['result'][0]['value'][1]),
            "pods_running": len([p for p in pods_status['items'] if p['status']['phase'] == 'Running'])
        }
    }
    
    return dashboard
```

This comprehensive MCP tools documentation provides everything needed to leverage the full infrastructure automation capabilities of the Claude-Optimized Deployment Engine. Each tool includes detailed parameters, examples, and real-world usage patterns for effective deployment automation.