# MCP Tools Comprehensive Reference

## Table of Contents

1. [Infrastructure Automation](#infrastructure-automation)
   - [Desktop Commander](#desktop-commander)
   - [Docker](#docker)
   - [Kubernetes](#kubernetes)
2. [DevOps Integration](#devops-integration)
   - [Azure DevOps](#azure-devops)
   - [Windows System](#windows-system)
3. [Security & Monitoring](#security--monitoring)
   - [Security Scanner](#security-scanner)
   - [Prometheus Monitoring](#prometheus-monitoring)
4. [Communication & Storage](#communication--storage)
   - [Slack Notifications](#slack-notifications)
   - [S3 Storage](#s3-storage)
   - [Cloud Storage](#cloud-storage)
5. [Research & Search](#research--search)
   - [Brave Search](#brave-search)

---

## Infrastructure Automation

### Desktop Commander

The Desktop Commander MCP server provides terminal command execution and file management capabilities for infrastructure deployment automation.

#### Available Tools

##### 1. execute_command
Execute terminal commands for infrastructure deployment.

**Parameters:**
- `command` (string, required): Terminal command to execute
- `working_directory` (string, optional): Working directory for command execution
- `timeout` (integer, optional, default: 300): Command timeout in seconds

**Example:**
```json
{
  "tool": "desktop-commander.execute_command",
  "arguments": {
    "command": "npm run build",
    "working_directory": "/app",
    "timeout": 600
  }
}
```

**Response:**
```json
{
  "command": "npm run build",
  "working_directory": "/app",
  "exit_code": 0,
  "stdout": "Build completed successfully...",
  "stderr": "",
  "success": true
}
```

##### 2. read_file
Read file contents for infrastructure configuration.

**Parameters:**
- `file_path` (string, required): Path to file to read
- `encoding` (string, optional, default: "utf-8"): File encoding

**Example:**
```json
{
  "tool": "desktop-commander.read_file",
  "arguments": {
    "file_path": "/app/config.yaml",
    "encoding": "utf-8"
  }
}
```

##### 3. write_file
Write content to file for infrastructure as code.

**Parameters:**
- `file_path` (string, required): Path to file to write
- `content` (string, required): File content to write
- `create_dirs` (boolean, optional, default: true): Create parent directories if needed

**Example:**
```json
{
  "tool": "desktop-commander.write_file",
  "arguments": {
    "file_path": "/app/deploy/k8s-config.yaml",
    "content": "apiVersion: v1\nkind: ConfigMap...",
    "create_dirs": true
  }
}
```

##### 4. list_directory
List directory contents for infrastructure exploration.

**Parameters:**
- `directory_path` (string, required): Directory path to list
- `show_hidden` (boolean, optional, default: false): Show hidden files

##### 5. make_command
Execute Make commands for CODE project automation.

**Parameters:**
- `target` (string, required): Make target to execute (e.g., 'deploy', 'test', 'quality')
- `args` (string, optional): Additional arguments for make command

**Example:**
```json
{
  "tool": "desktop-commander.make_command",
  "arguments": {
    "target": "deploy",
    "args": "ENV=production"
  }
}
```

---

### Docker

Docker container lifecycle management and orchestration.

#### Available Tools

##### 1. docker_build
Build Docker images from Dockerfiles.

**Parameters:**
- `dockerfile_path` (string, required): Path to Dockerfile
- `image_tag` (string, required): Tag for the built image
- `build_args` (object, optional): Build arguments
- `no_cache` (boolean, optional, default: false): Build without cache

**Example:**
```json
{
  "tool": "docker.docker_build",
  "arguments": {
    "dockerfile_path": "./Dockerfile",
    "image_tag": "myapp:v1.2.3",
    "build_args": {
      "NODE_VERSION": "18"
    },
    "no_cache": false
  }
}
```

##### 2. docker_run
Run Docker containers with custom configurations.

**Parameters:**
- `image` (string, required): Docker image to run
- `name` (string, optional): Container name
- `ports` (object, optional): Port mappings (host:container)
- `environment` (object, optional): Environment variables
- `volumes` (array, optional): Volume mounts
- `detach` (boolean, optional, default: true): Run in background

**Example:**
```json
{
  "tool": "docker.docker_run",
  "arguments": {
    "image": "myapp:v1.2.3",
    "name": "myapp-prod",
    "ports": {
      "8080": "3000"
    },
    "environment": {
      "NODE_ENV": "production",
      "DB_HOST": "postgres"
    },
    "volumes": [
      "/data/app:/app/data"
    ],
    "detach": true
  }
}
```

##### 3. docker_stop
Stop running containers.

**Parameters:**
- `container` (string, required): Container name or ID
- `timeout` (integer, optional, default: 10): Seconds to wait before killing

##### 4. docker_remove
Remove containers.

**Parameters:**
- `container` (string, required): Container name or ID
- `force` (boolean, optional, default: false): Force removal

##### 5. docker_ps
List containers.

**Parameters:**
- `all` (boolean, optional, default: false): Show all containers (not just running)
- `filters` (object, optional): Filter containers

##### 6. docker_logs
Get container logs.

**Parameters:**
- `container` (string, required): Container name or ID
- `tail` (integer, optional): Number of lines to show from end
- `follow` (boolean, optional, default: false): Follow log output

##### 7. docker_push
Push image to registry.

**Parameters:**
- `image_tag` (string, required): Image tag to push
- `registry` (string, optional): Registry URL

##### 8. docker_pull
Pull image from registry.

**Parameters:**
- `image` (string, required): Image to pull
- `tag` (string, optional, default: "latest"): Image tag

##### 9. docker_inspect
Inspect container or image.

**Parameters:**
- `name` (string, required): Container or image name
- `type` (string, optional): "container" or "image"

##### 10. docker_compose_up
Run Docker Compose services.

**Parameters:**
- `compose_file` (string, optional): Path to docker-compose.yml
- `services` (array, optional): Specific services to start
- `detach` (boolean, optional, default: true): Run in background

---

### Kubernetes

Kubernetes cluster management and deployment orchestration.

#### Available Tools

##### 1. kubectl_apply
Deploy Kubernetes manifests.

**Parameters:**
- `manifest_path` (string, required): Path to manifest file or directory
- `namespace` (string, optional, default: "default"): Target namespace
- `dry_run` (boolean, optional, default: false): Validate without applying

**Example:**
```json
{
  "tool": "kubernetes.kubectl_apply",
  "arguments": {
    "manifest_path": "./k8s/production/",
    "namespace": "production",
    "dry_run": false
  }
}
```

##### 2. kubectl_get
Get Kubernetes resources.

**Parameters:**
- `resource_type` (string, required): Resource type (e.g., "pods", "services", "deployments")
- `name` (string, optional): Specific resource name
- `namespace` (string, optional): Target namespace
- `output` (string, optional): Output format ("json", "yaml", "wide")

**Example:**
```json
{
  "tool": "kubernetes.kubectl_get",
  "arguments": {
    "resource_type": "pods",
    "namespace": "production",
    "output": "json"
  }
}
```

##### 3. kubectl_delete
Delete Kubernetes resources.

**Parameters:**
- `resource_type` (string, required): Resource type
- `name` (string, required): Resource name
- `namespace` (string, optional): Target namespace
- `force` (boolean, optional, default: false): Force deletion

##### 4. kubectl_describe
Describe Kubernetes resources.

**Parameters:**
- `resource_type` (string, required): Resource type
- `name` (string, required): Resource name
- `namespace` (string, optional): Target namespace

##### 5. kubectl_logs
Get pod logs.

**Parameters:**
- `pod_name` (string, required): Pod name
- `namespace` (string, optional): Target namespace
- `container` (string, optional): Container name in pod
- `tail` (integer, optional): Number of lines from end
- `follow` (boolean, optional, default: false): Follow log output

##### 6. kubectl_scale
Scale deployments or replica sets.

**Parameters:**
- `resource_type` (string, required): "deployment" or "replicaset"
- `name` (string, required): Resource name
- `replicas` (integer, required): Number of replicas
- `namespace` (string, optional): Target namespace

##### 7. kubectl_rollout_status
Check rollout status.

**Parameters:**
- `resource_type` (string, required): Resource type
- `name` (string, required): Resource name
- `namespace` (string, optional): Target namespace
- `timeout` (integer, optional): Timeout in seconds

##### 8. kubectl_rollout_restart
Restart a rollout.

**Parameters:**
- `resource_type` (string, required): Resource type
- `name` (string, required): Resource name
- `namespace` (string, optional): Target namespace

##### 9. kubectl_port_forward
Forward ports from a pod.

**Parameters:**
- `pod_name` (string, required): Pod name
- `ports` (string, required): Port mapping (e.g., "8080:80")
- `namespace` (string, optional): Target namespace

##### 10. helm_install
Install Helm chart.

**Parameters:**
- `release_name` (string, required): Helm release name
- `chart` (string, required): Chart name or path
- `namespace` (string, optional): Target namespace
- `values_file` (string, optional): Path to values file
- `set_values` (object, optional): Override values

---

## DevOps Integration

### Azure DevOps

Azure DevOps integration for CI/CD pipeline automation, work item management, and repository operations.

#### Available Tools

##### 1. list_projects
List Azure DevOps projects.

**Parameters:** None

**Example:**
```json
{
  "tool": "azure-devops.list_projects",
  "arguments": {}
}
```

##### 2. list_pipelines
List build/release pipelines.

**Parameters:**
- `project` (string, required): Project name

##### 3. trigger_pipeline
Trigger a build/release pipeline.

**Parameters:**
- `project` (string, required): Project name
- `pipeline_id` (integer, required): Pipeline ID
- `branch` (string, optional): Source branch
- `parameters` (object, optional): Pipeline parameters

**Example:**
```json
{
  "tool": "azure-devops.trigger_pipeline",
  "arguments": {
    "project": "MyProject",
    "pipeline_id": 42,
    "branch": "main",
    "parameters": {
      "environment": "production"
    }
  }
}
```

##### 4. get_build_status
Get build status and details.

**Parameters:**
- `project` (string, required): Project name
- `build_id` (integer, required): Build ID

##### 5. create_work_item
Create a new work item.

**Parameters:**
- `project` (string, required): Project name
- `work_item_type` (string, required): Type (e.g., "Task", "Bug", "User Story")
- `title` (string, required): Work item title
- `description` (string, optional): Work item description
- `assigned_to` (string, optional): Assignee email
- `tags` (string, optional): Comma-separated tags

##### 6. update_work_item
Update existing work item.

**Parameters:**
- `work_item_id` (integer, required): Work item ID
- `updates` (array, required): Array of update operations

##### 7. list_repositories
List Git repositories.

**Parameters:**
- `project` (string, required): Project name

##### 8. create_pull_request
Create a pull request.

**Parameters:**
- `project` (string, required): Project name
- `repository` (string, required): Repository name
- `source_branch` (string, required): Source branch
- `target_branch` (string, required): Target branch
- `title` (string, required): PR title
- `description` (string, optional): PR description

---

### Windows System

Native Windows automation capabilities.

#### Available Tools

##### 1. powershell_command
Execute PowerShell commands.

**Parameters:**
- `command` (string, required): PowerShell command or script
- `elevated` (boolean, optional, default: false): Run as administrator

**Example:**
```json
{
  "tool": "windows-system.powershell_command",
  "arguments": {
    "command": "Get-Service | Where-Object {$_.Status -eq 'Running'}",
    "elevated": false
  }
}
```

##### 2. get_system_info
Get Windows system information.

**Parameters:** None

##### 3. manage_service
Manage Windows services.

**Parameters:**
- `service_name` (string, required): Service name
- `action` (string, required): Action ("start", "stop", "restart", "status")

##### 4. get_registry_value
Read Windows registry value.

**Parameters:**
- `key_path` (string, required): Registry key path
- `value_name` (string, required): Value name

##### 5. set_registry_value
Set Windows registry value.

**Parameters:**
- `key_path` (string, required): Registry key path
- `value_name` (string, required): Value name
- `value_data` (string, required): Value data
- `value_type` (string, optional): Registry value type

##### 6. get_installed_software
List installed software.

**Parameters:**
- `filter` (string, optional): Filter by name

##### 7. manage_scheduled_task
Manage scheduled tasks.

**Parameters:**
- `task_name` (string, required): Task name
- `action` (string, required): Action ("create", "delete", "run", "status")
- `task_config` (object, optional): Task configuration for create

---

## Security & Monitoring

### Security Scanner

Comprehensive vulnerability management for code and dependencies.

#### Available Tools

##### 1. npm_audit
JavaScript dependency vulnerability scanning.

**Parameters:**
- `package_json_path` (string, required): Path to package.json
- `severity` (string, optional): Minimum severity level
- `fix` (boolean, optional, default: false): Attempt to fix

**Example:**
```json
{
  "tool": "security-scanner.npm_audit",
  "arguments": {
    "package_json_path": "./package.json",
    "severity": "moderate",
    "fix": false
  }
}
```

##### 2. python_safety_check
Python package security assessment.

**Parameters:**
- `requirements_path` (string, required): Path to requirements.txt
- `severity` (string, optional): Minimum severity level

##### 3. docker_security_scan
Container image vulnerability analysis.

**Parameters:**
- `image` (string, required): Docker image to scan
- `severity` (string, optional): Minimum severity level

##### 4. file_security_scan
Source code security pattern detection.

**Parameters:**
- `path` (string, required): Path to scan
- `patterns` (array, optional): Security patterns to check
- `exclude` (array, optional): Paths to exclude

---

### Prometheus Monitoring

Real-time observability and metrics collection.

#### Available Tools

##### 1. prometheus_query
Execute instant PromQL queries.

**Parameters:**
- `query` (string, required): PromQL query
- `time` (string, optional): Evaluation timestamp
- `timeout` (string, optional, default: "30s"): Query timeout

**Example:**
```json
{
  "tool": "prometheus-monitoring.prometheus_query",
  "arguments": {
    "query": "rate(http_requests_total[5m])",
    "timeout": "10s"
  }
}
```

##### 2. prometheus_query_range
Execute range queries for time-series data.

**Parameters:**
- `query` (string, required): PromQL query
- `start` (string, required): Start timestamp
- `end` (string, required): End timestamp
- `step` (string, required): Query resolution step

##### 3. prometheus_targets
Get Prometheus targets and their status.

**Parameters:**
- `state` (string, optional): Filter by state ("active", "dropped")

##### 4. prometheus_alerts
Get active alerts.

**Parameters:**
- `filter` (object, optional): Alert filters

##### 5. prometheus_rules
Get configured alerting rules.

**Parameters:** None

---

## Communication & Storage

### Slack Notifications

Team communication automation.

#### Available Tools

##### 1. send_notification
Send formatted deployment notifications.

**Parameters:**
- `channel` (string, required): Channel ID or name
- `notification_type` (string, required): Type of notification
- `title` (string, required): Notification title
- `details` (object, optional): Additional details
- `color` (string, optional): Sidebar color

**Example:**
```json
{
  "tool": "slack-notifications.send_notification",
  "arguments": {
    "channel": "#deployments",
    "notification_type": "deployment_success",
    "title": "Production Deployment Complete",
    "details": {
      "version": "v1.2.3",
      "environment": "production",
      "duration": "2m 34s"
    },
    "color": "good"
  }
}
```

##### 2. post_message
Send direct messages.

**Parameters:**
- `channel` (string, required): Channel ID or name
- `text` (string, required): Message text
- `thread_ts` (string, optional): Thread timestamp for replies

##### 3. list_channels
List available channels.

**Parameters:**
- `types` (string, optional): Channel types to include

---

### S3 Storage

AWS S3 cloud storage management.

#### Available Tools

##### 1. s3_upload_file
Upload files to S3.

**Parameters:**
- `file_path` (string, required): Local file path
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `metadata` (object, optional): Object metadata

**Example:**
```json
{
  "tool": "s3-storage.s3_upload_file",
  "arguments": {
    "file_path": "./build/app.zip",
    "bucket": "my-deployments",
    "key": "releases/v1.2.3/app.zip",
    "metadata": {
      "version": "1.2.3",
      "build_date": "2024-01-15"
    }
  }
}
```

##### 2. s3_download_file
Download files from S3.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `local_path` (string, required): Local destination path

##### 3. s3_list_objects
List objects in bucket.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `prefix` (string, optional): Key prefix filter
- `max_keys` (integer, optional, default: 1000): Maximum objects

##### 4. s3_delete_object
Delete S3 object.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key

##### 5. s3_create_presigned_url
Generate presigned URL.

**Parameters:**
- `bucket` (string, required): S3 bucket name
- `key` (string, required): S3 object key
- `expiration` (integer, optional, default: 3600): URL expiration in seconds

##### 6. s3_list_buckets
List S3 buckets.

**Parameters:** None

---

### Cloud Storage

Generic cloud storage abstraction.

#### Available Tools

##### 1. upload
Upload file to cloud storage.

**Parameters:**
- `provider` (string, required): Storage provider ("s3", "azure", "gcs")
- `source` (string, required): Local file path
- `destination` (string, required): Cloud destination path
- `options` (object, optional): Provider-specific options

##### 2. download
Download file from cloud storage.

**Parameters:**
- `provider` (string, required): Storage provider
- `source` (string, required): Cloud source path
- `destination` (string, required): Local destination path

##### 3. list
List files in cloud storage.

**Parameters:**
- `provider` (string, required): Storage provider
- `path` (string, required): Cloud path
- `recursive` (boolean, optional, default: false): List recursively

##### 4. delete
Delete file from cloud storage.

**Parameters:**
- `provider` (string, required): Storage provider
- `path` (string, required): Cloud file path

##### 5. sync
Sync local directory with cloud storage.

**Parameters:**
- `provider` (string, required): Storage provider
- `source` (string, required): Source directory
- `destination` (string, required): Destination path
- `direction` (string, required): "upload" or "download"
- `delete` (boolean, optional, default: false): Delete extra files

---

## Research & Search

### Brave Search

Web search capabilities for research and validation.

#### Available Tools

##### 1. brave_web_search
General web search.

**Parameters:**
- `query` (string, required): Search query
- `count` (integer, optional, default: 10): Number of results (1-20)
- `offset` (integer, optional, default: 0): Pagination offset
- `country` (string, optional): Country code (e.g., 'US', 'GB')
- `search_lang` (string, optional, default: "en"): Search language
- `safesearch` (string, optional, default: "moderate"): Safe search setting

**Example:**
```json
{
  "tool": "brave.brave_web_search",
  "arguments": {
    "query": "kubernetes deployment best practices 2024",
    "count": 10,
    "search_lang": "en"
  }
}
```

##### 2. brave_local_search
Search for local businesses and places.

**Parameters:**
- `query` (string, required): Local search query
- `count` (integer, optional, default: 5): Number of results (1-20)

##### 3. brave_news_search
Search for recent news articles.

**Parameters:**
- `query` (string, required): News search query
- `count` (integer, optional, default: 10): Number of results
- `freshness` (string, optional, default: "pw"): Time range ("pd", "pw", "pm", "py")

##### 4. brave_image_search
Search for images on the web.

**Parameters:**
- `query` (string, required): Image search query
- `count` (integer, optional, default: 10): Number of results (1-50)
- `size` (string, optional, default: "all"): Size filter ("small", "medium", "large", "all")

---

## Error Handling

All MCP tools follow a consistent error handling pattern:

### Common Error Codes

- `-32000`: General server error
- `-32001`: Authentication error
- `-32002`: Permission denied
- `-32003`: Resource not found
- `-32004`: Invalid parameters
- `-32005`: Timeout error
- `-32006`: Rate limit exceeded
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

### Error Response Format

```json
{
  "error": {
    "code": -32004,
    "message": "Invalid parameters",
    "data": {
      "field": "namespace",
      "reason": "Namespace 'prod' does not exist"
    }
  }
}
```

## Rate Limiting

Different MCP servers have different rate limits:

- **Brave Search**: 1000 requests/month (free tier)
- **Slack**: 1 request/second per method
- **Azure DevOps**: 200 requests/5 minutes
- **S3**: No hard limit, but throttling may occur
- **Local tools**: No rate limiting

## Best Practices

1. **Error Handling**: Always handle potential errors and timeouts
2. **Authentication**: Store credentials securely in environment variables
3. **Timeouts**: Set appropriate timeouts for long-running operations
4. **Retries**: Implement exponential backoff for transient failures
5. **Logging**: Log all tool calls for audit and debugging
6. **Validation**: Validate parameters before calling tools
7. **Batch Operations**: Use batch operations where available
8. **Resource Cleanup**: Always clean up resources after use