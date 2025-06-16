# Integration Patterns Guide - CODE MCP API

This guide provides best practices and patterns for integrating the CODE MCP API into your infrastructure automation workflows.

## Table of Contents

1. [Architectural Patterns](#architectural-patterns)
2. [Workflow Patterns](#workflow-patterns)
3. [Error Handling Patterns](#error-handling-patterns)
4. [Performance Patterns](#performance-patterns)
5. [Security Patterns](#security-patterns)
6. [Event-Driven Patterns](#event-driven-patterns)
7. [Testing Patterns](#testing-patterns)

## Architectural Patterns

### 1. Service Facade Pattern

Create a unified interface for complex MCP operations:

```python
from typing import Dict, Any, Optional
from src.mcp.manager import get_mcp_manager

class DeploymentFacade:
    """Simplified interface for deployment operations."""
    
    def __init__(self):
        self.manager = None
    
    async def initialize(self):
        self.manager = get_mcp_manager()
        await self.manager.initialize()
    
    async def deploy_application(
        self,
        app_name: str,
        version: str,
        environment: str = "production"
    ) -> Dict[str, Any]:
        """One-click deployment with all safety checks."""
        
        # Build
        image_tag = f"{app_name}:{version}"
        await self._build_image(image_tag)
        
        # Scan
        if not await self._security_scan(image_tag):
            raise Exception("Security scan failed")
        
        # Deploy
        namespace = f"{app_name}-{environment}"
        await self._deploy_to_k8s(image_tag, namespace)
        
        # Monitor
        await self._setup_monitoring(app_name, namespace)
        
        # Notify
        await self._notify_team(app_name, version, environment)
        
        return {
            "app": app_name,
            "version": version,
            "environment": environment,
            "status": "deployed"
        }
    
    async def _build_image(self, image_tag: str):
        return await self.manager.call_tool(
            "docker.docker_build",
            {"dockerfile_path": ".", "image_tag": image_tag}
        )
    
    async def _security_scan(self, image_tag: str) -> bool:
        result = await self.manager.call_tool(
            "security-scanner.docker_security_scan",
            {"image": image_tag, "severity": "high"}
        )
        return result['total_vulnerabilities'] == 0
    
    # ... more helper methods
```

### 2. Repository Pattern

Abstract data storage operations:

```python
from abc import ABC, abstractmethod
from typing import List, Optional

class DeploymentRepository(ABC):
    """Abstract repository for deployment records."""
    
    @abstractmethod
    async def save_deployment(self, deployment: Dict[str, Any]) -> str:
        pass
    
    @abstractmethod
    async def get_deployment(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    async def list_deployments(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        pass

class S3DeploymentRepository(DeploymentRepository):
    """S3-backed deployment repository."""
    
    def __init__(self, bucket: str):
        self.bucket = bucket
        self.manager = None
    
    async def initialize(self):
        self.manager = get_mcp_manager()
        await self.manager.initialize()
    
    async def save_deployment(self, deployment: Dict[str, Any]) -> str:
        deployment_id = deployment.get('id', str(uuid.uuid4()))
        key = f"deployments/{deployment_id}.json"
        
        # Save to S3
        await self.manager.call_tool(
            "s3-storage.s3_upload_file",
            {
                "file_path": self._create_temp_file(deployment),
                "bucket": self.bucket,
                "key": key,
                "metadata": {
                    "app": deployment.get('app'),
                    "version": deployment.get('version'),
                    "timestamp": datetime.now().isoformat()
                }
            }
        )
        
        return deployment_id
    
    async def get_deployment(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        key = f"deployments/{deployment_id}.json"
        
        try:
            result = await self.manager.call_tool(
                "s3-storage.s3_download_file",
                {
                    "bucket": self.bucket,
                    "key": key,
                    "local_path": f"/tmp/{deployment_id}.json"
                }
            )
            
            with open(f"/tmp/{deployment_id}.json", 'r') as f:
                return json.load(f)
        except MCPError:
            return None
```

### 3. Strategy Pattern

Implement different deployment strategies:

```python
from abc import ABC, abstractmethod

class DeploymentStrategy(ABC):
    """Abstract deployment strategy."""
    
    @abstractmethod
    async def deploy(self, app: str, version: str, target: str) -> Dict[str, Any]:
        pass

class BlueGreenDeployment(DeploymentStrategy):
    """Blue-green deployment strategy."""
    
    async def deploy(self, app: str, version: str, target: str) -> Dict[str, Any]:
        manager = get_mcp_manager()
        await manager.initialize()
        
        # Deploy to green environment
        green_namespace = f"{app}-green"
        await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": f"./k8s/{app}/",
                "namespace": green_namespace
            }
        )
        
        # Run health checks
        await self._wait_for_healthy(manager, app, green_namespace)
        
        # Switch traffic
        await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": f"./k8s/{app}/service-green.yaml",
                "namespace": target
            }
        )
        
        # Clean up blue environment
        blue_namespace = f"{app}-blue"
        await manager.call_tool(
            "kubernetes.kubectl_delete",
            {
                "resource_type": "namespace",
                "name": blue_namespace
            }
        )
        
        return {"strategy": "blue-green", "status": "success"}

class CanaryDeployment(DeploymentStrategy):
    """Canary deployment strategy."""
    
    async def deploy(self, app: str, version: str, target: str) -> Dict[str, Any]:
        manager = get_mcp_manager()
        await manager.initialize()
        
        # Deploy canary version
        await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": f"./k8s/{app}/canary.yaml",
                "namespace": target
            }
        )
        
        # Monitor metrics
        for percentage in [10, 25, 50, 100]:
            await self._update_traffic_split(manager, app, target, percentage)
            await asyncio.sleep(300)  # 5 minutes
            
            if not await self._check_metrics(manager, app, target):
                await self._rollback(manager, app, target)
                return {"strategy": "canary", "status": "rollback"}
        
        return {"strategy": "canary", "status": "success"}

class RollingDeployment(DeploymentStrategy):
    """Rolling deployment strategy."""
    
    async def deploy(self, app: str, version: str, target: str) -> Dict[str, Any]:
        manager = get_mcp_manager()
        await manager.initialize()
        
        # Apply new deployment
        await manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": f"./k8s/{app}/deployment.yaml",
                "namespace": target
            }
        )
        
        # Monitor rollout
        result = await manager.call_tool(
            "kubernetes.kubectl_rollout_status",
            {
                "resource_type": "deployment",
                "name": app,
                "namespace": target,
                "timeout": 600
            }
        )
        
        return {"strategy": "rolling", "status": result['status']}

# Usage
strategy_map = {
    "blue-green": BlueGreenDeployment(),
    "canary": CanaryDeployment(),
    "rolling": RollingDeployment()
}

async def deploy_with_strategy(app: str, version: str, strategy_name: str):
    strategy = strategy_map.get(strategy_name, RollingDeployment())
    return await strategy.deploy(app, version, "production")
```

## Workflow Patterns

### 1. Pipeline Pattern

Chain operations together:

```python
from typing import Callable, List, Any

class Pipeline:
    """Chainable pipeline for MCP operations."""
    
    def __init__(self):
        self.steps: List[Callable] = []
        self.context = {}
    
    def add_step(self, step: Callable) -> 'Pipeline':
        self.steps.append(step)
        return self
    
    async def execute(self, initial_data: Dict[str, Any]) -> Dict[str, Any]:
        self.context = initial_data
        
        for step in self.steps:
            try:
                self.context = await step(self.context)
            except Exception as e:
                self.context['error'] = str(e)
                self.context['failed_step'] = step.__name__
                break
        
        return self.context

# Define pipeline steps
async def validate_inputs(context: Dict[str, Any]) -> Dict[str, Any]:
    """Validate deployment inputs."""
    required = ['app', 'version', 'environment']
    for field in required:
        if field not in context:
            raise ValueError(f"Missing required field: {field}")
    return context

async def build_container(context: Dict[str, Any]) -> Dict[str, Any]:
    """Build Docker container."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    result = await manager.call_tool(
        "docker.docker_build",
        {
            "dockerfile_path": context.get('dockerfile', '.'),
            "image_tag": f"{context['app']}:{context['version']}"
        }
    )
    
    context['image_id'] = result['image_id']
    return context

async def run_security_scan(context: Dict[str, Any]) -> Dict[str, Any]:
    """Run security scanning."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    scan_result = await manager.call_tool(
        "security-scanner.docker_security_scan",
        {
            "image": f"{context['app']}:{context['version']}",
            "severity": "high"
        }
    )
    
    if scan_result['total_vulnerabilities'] > 0:
        raise Exception(f"Found {scan_result['total_vulnerabilities']} vulnerabilities")
    
    context['security_scan'] = scan_result
    return context

async def deploy_to_kubernetes(context: Dict[str, Any]) -> Dict[str, Any]:
    """Deploy to Kubernetes."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    deploy_result = await manager.call_tool(
        "kubernetes.kubectl_apply",
        {
            "manifest_path": f"./k8s/{context['environment']}/",
            "namespace": context['environment']
        }
    )
    
    context['deployment'] = deploy_result
    return context

async def notify_team(context: Dict[str, Any]) -> Dict[str, Any]:
    """Send notifications."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    await manager.call_tool(
        "slack-notifications.send_notification",
        {
            "channel": "#deployments",
            "notification_type": "deployment_success",
            "title": f"Deployed {context['app']} v{context['version']}",
            "details": context
        }
    )
    
    return context

# Usage
pipeline = Pipeline()
pipeline.add_step(validate_inputs) \
        .add_step(build_container) \
        .add_step(run_security_scan) \
        .add_step(deploy_to_kubernetes) \
        .add_step(notify_team)

result = await pipeline.execute({
    "app": "myapp",
    "version": "1.2.3",
    "environment": "production"
})
```

### 2. Saga Pattern

Handle distributed transactions:

```python
from typing import List, Tuple, Callable

class Saga:
    """Saga pattern for distributed transactions."""
    
    def __init__(self):
        self.steps: List[Tuple[Callable, Callable]] = []
    
    def add_step(self, action: Callable, compensate: Callable) -> 'Saga':
        """Add a step with its compensation action."""
        self.steps.append((action, compensate))
        return self
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute saga with automatic rollback on failure."""
        completed_steps = []
        
        try:
            for action, compensate in self.steps:
                result = await action(context)
                completed_steps.append((action, compensate, result))
                context.update(result)
            
            return context
        
        except Exception as e:
            # Rollback in reverse order
            for action, compensate, result in reversed(completed_steps):
                try:
                    await compensate(context)
                except Exception as rollback_error:
                    print(f"Rollback failed for {action.__name__}: {rollback_error}")
            
            raise e

# Define saga steps
async def create_database(context: Dict[str, Any]) -> Dict[str, Any]:
    """Create database."""
    # Implementation
    return {"database_created": True, "db_name": f"{context['app']}_db"}

async def delete_database(context: Dict[str, Any]) -> None:
    """Delete database (compensation)."""
    # Implementation
    pass

async def deploy_backend(context: Dict[str, Any]) -> Dict[str, Any]:
    """Deploy backend services."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    result = await manager.call_tool(
        "kubernetes.kubectl_apply",
        {
            "manifest_path": "./k8s/backend/",
            "namespace": context['namespace']
        }
    )
    
    return {"backend_deployed": True, "backend_resources": result}

async def rollback_backend(context: Dict[str, Any]) -> None:
    """Rollback backend deployment."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    await manager.call_tool(
        "kubernetes.kubectl_delete",
        {
            "resource_type": "deployment",
            "name": "backend",
            "namespace": context['namespace']
        }
    )

# Usage
saga = Saga()
saga.add_step(create_database, delete_database) \
    .add_step(deploy_backend, rollback_backend)

try:
    result = await saga.execute({"app": "myapp", "namespace": "production"})
except Exception as e:
    print(f"Saga failed and rolled back: {e}")
```

## Error Handling Patterns

### 1. Circuit Breaker Pattern

Prevent cascading failures:

```python
from datetime import datetime, timedelta
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Circuit breaker for MCP calls."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: timedelta = timedelta(minutes=1),
        expected_exception: type = MCPError
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        
        if self.state == CircuitState.OPEN:
            if datetime.now() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _on_success(self):
        """Handle successful call."""
        self.failure_count = 0
        self.state = CircuitState.CLOSED
    
    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

# Usage
breaker = CircuitBreaker(failure_threshold=3)

async def safe_deploy():
    manager = get_mcp_manager()
    await manager.initialize()
    
    try:
        return await breaker.call(
            manager.call_tool,
            "kubernetes.kubectl_apply",
            {"manifest_path": "./k8s/"}
        )
    except Exception as e:
        print(f"Deployment failed: {e}")
        return None
```

### 2. Retry with Exponential Backoff

Handle transient failures:

```python
import random
from typing import TypeVar, Callable, Optional, Set

T = TypeVar('T')

async def retry_with_backoff(
    func: Callable[..., T],
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Optional[Set[type]] = None,
    **kwargs
) -> T:
    """
    Retry function with exponential backoff.
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries
        max_delay: Maximum delay between retries
        exponential_base: Base for exponential backoff
        jitter: Add randomization to prevent thundering herd
        retryable_exceptions: Set of exceptions that trigger retry
    """
    if retryable_exceptions is None:
        retryable_exceptions = {MCPError, asyncio.TimeoutError}
    
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        
        except Exception as e:
            last_exception = e
            
            # Check if exception is retryable
            if not any(isinstance(e, exc_type) for exc_type in retryable_exceptions):
                raise
            
            # Don't retry on last attempt
            if attempt == max_retries:
                raise
            
            # Calculate delay
            delay = min(
                base_delay * (exponential_base ** attempt),
                max_delay
            )
            
            # Add jitter
            if jitter:
                delay = delay * (0.5 + random.random())
            
            print(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {e}")
            await asyncio.sleep(delay)
    
    raise last_exception

# Usage
async def deploy_with_retry():
    manager = get_mcp_manager()
    await manager.initialize()
    
    return await retry_with_backoff(
        manager.call_tool,
        "kubernetes.kubectl_apply",
        {"manifest_path": "./k8s/"},
        max_retries=5,
        base_delay=2.0,
        retryable_exceptions={MCPError, ConnectionError}
    )
```

## Performance Patterns

### 1. Batch Processing

Process multiple operations efficiently:

```python
from typing import List, Dict, Any
import asyncio

class BatchProcessor:
    """Batch processor for MCP operations."""
    
    def __init__(self, batch_size: int = 10, max_concurrent: int = 5):
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_batch(
        self,
        items: List[Any],
        processor: Callable[[Any], Any]
    ) -> List[Dict[str, Any]]:
        """Process items in batches."""
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_results = await self._process_concurrent(batch, processor)
            results.extend(batch_results)
        
        return results
    
    async def _process_concurrent(
        self,
        batch: List[Any],
        processor: Callable[[Any], Any]
    ) -> List[Dict[str, Any]]:
        """Process batch concurrently."""
        tasks = []
        
        for item in batch:
            task = self._process_with_semaphore(processor, item)
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _process_with_semaphore(
        self,
        processor: Callable[[Any], Any],
        item: Any
    ) -> Dict[str, Any]:
        """Process single item with semaphore."""
        async with self.semaphore:
            try:
                result = await processor(item)
                return {"item": item, "result": result, "success": True}
            except Exception as e:
                return {"item": item, "error": str(e), "success": False}

# Usage
async def scan_images(images: List[str]):
    """Scan multiple Docker images for vulnerabilities."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    async def scan_single(image: str):
        return await manager.call_tool(
            "security-scanner.docker_security_scan",
            {"image": image, "severity": "moderate"}
        )
    
    processor = BatchProcessor(batch_size=5, max_concurrent=3)
    results = await processor.process_batch(images, scan_single)
    
    # Summarize results
    total_vulns = sum(
        r['result']['total_vulnerabilities']
        for r in results
        if r['success']
    )
    
    return {
        "total_images": len(images),
        "successful_scans": sum(1 for r in results if r['success']),
        "total_vulnerabilities": total_vulns
    }
```

### 2. Caching Pattern

Cache expensive operations:

```python
from functools import lru_cache
import hashlib
import json

class MCPCache:
    """Cache for MCP operations."""
    
    def __init__(self, ttl: timedelta = timedelta(minutes=5)):
        self.cache = {}
        self.ttl = ttl
    
    def _get_cache_key(self, tool: str, arguments: Dict[str, Any]) -> str:
        """Generate cache key from tool and arguments."""
        key_data = f"{tool}:{json.dumps(arguments, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def get_or_call(
        self,
        manager: Any,
        tool: str,
        arguments: Dict[str, Any]
    ) -> Any:
        """Get from cache or call tool."""
        cache_key = self._get_cache_key(tool, arguments)
        
        # Check cache
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if datetime.now() - entry['timestamp'] < self.ttl:
                return entry['result']
        
        # Call tool and cache result
        result = await manager.call_tool(tool, arguments)
        self.cache[cache_key] = {
            'result': result,
            'timestamp': datetime.now()
        }
        
        return result
    
    def invalidate(self, tool: Optional[str] = None):
        """Invalidate cache entries."""
        if tool:
            # Invalidate specific tool
            keys_to_remove = [
                k for k in self.cache.keys()
                if k.startswith(f"{tool}:")
            ]
            for key in keys_to_remove:
                del self.cache[key]
        else:
            # Clear all cache
            self.cache.clear()

# Usage
cache = MCPCache(ttl=timedelta(minutes=10))

async def get_prometheus_metrics():
    manager = get_mcp_manager()
    await manager.initialize()
    
    # This will be cached for 10 minutes
    return await cache.get_or_call(
        manager,
        "prometheus-monitoring.prometheus_query",
        {"query": "up{job='myapp'}"}
    )
```

## Security Patterns

### 1. Least Privilege Pattern

Grant minimal required permissions:

```python
from typing import Set, Dict, Any

class PermissionManager:
    """Manage MCP tool permissions."""
    
    def __init__(self):
        self.permissions: Dict[str, Set[str]] = {}
    
    def grant_permission(self, role: str, tool: str):
        """Grant permission to use a tool."""
        if role not in self.permissions:
            self.permissions[role] = set()
        self.permissions[role].add(tool)
    
    def check_permission(self, role: str, tool: str) -> bool:
        """Check if role has permission to use tool."""
        return tool in self.permissions.get(role, set())
    
    def create_restricted_manager(self, role: str):
        """Create MCP manager with restricted permissions."""
        allowed_tools = self.permissions.get(role, set())
        
        class RestrictedManager:
            def __init__(self, base_manager, allowed_tools):
                self.base_manager = base_manager
                self.allowed_tools = allowed_tools
            
            async def call_tool(self, tool: str, arguments: Dict[str, Any]):
                if tool not in self.allowed_tools:
                    raise PermissionError(f"Role '{role}' cannot use tool '{tool}'")
                return await self.base_manager.call_tool(tool, arguments)
        
        base_manager = get_mcp_manager()
        return RestrictedManager(base_manager, allowed_tools)

# Usage
permissions = PermissionManager()

# Define roles
permissions.grant_permission("developer", "docker.docker_build")
permissions.grant_permission("developer", "docker.docker_ps")
permissions.grant_permission("developer", "kubernetes.kubectl_get")

permissions.grant_permission("deployer", "kubernetes.kubectl_apply")
permissions.grant_permission("deployer", "kubernetes.kubectl_rollout_status")
permissions.grant_permission("deployer", "slack-notifications.send_notification")

permissions.grant_permission("admin", "kubernetes.kubectl_delete")
permissions.grant_permission("admin", "azure-devops.create_work_item")

# Create restricted manager
dev_manager = permissions.create_restricted_manager("developer")
```

### 2. Audit Logging Pattern

Log all operations for compliance:

```python
import json
from datetime import datetime

class AuditLogger:
    """Audit logger for MCP operations."""
    
    def __init__(self, storage_backend: str = "s3"):
        self.storage_backend = storage_backend
        self.buffer = []
        self.buffer_size = 100
    
    async def log_operation(
        self,
        user: str,
        tool: str,
        arguments: Dict[str, Any],
        result: Any,
        success: bool
    ):
        """Log an MCP operation."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "tool": tool,
            "arguments": self._sanitize_arguments(arguments),
            "success": success,
            "result_summary": self._summarize_result(result),
            "session_id": self._get_session_id()
        }
        
        self.buffer.append(entry)
        
        if len(self.buffer) >= self.buffer_size:
            await self._flush_buffer()
    
    def _sanitize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from arguments."""
        sanitized = arguments.copy()
        sensitive_keys = ['password', 'token', 'secret', 'key']
        
        for key in sanitized:
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
        
        return sanitized
    
    def _summarize_result(self, result: Any) -> Dict[str, Any]:
        """Create summary of result."""
        if isinstance(result, dict):
            return {
                "type": "success",
                "keys": list(result.keys())
            }
        elif isinstance(result, Exception):
            return {
                "type": "error",
                "error_type": type(result).__name__,
                "message": str(result)
            }
        else:
            return {"type": "unknown"}
    
    async def _flush_buffer(self):
        """Flush audit log buffer to storage."""
        if not self.buffer:
            return
        
        manager = get_mcp_manager()
        await manager.initialize()
        
        filename = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        await manager.call_tool(
            "s3-storage.s3_upload_file",
            {
                "file_path": self._create_temp_file(self.buffer),
                "bucket": "audit-logs",
                "key": f"mcp/{filename}"
            }
        )
        
        self.buffer.clear()

# Usage
audit_logger = AuditLogger()

async def audited_call(user: str, tool: str, arguments: Dict[str, Any]):
    """Call MCP tool with audit logging."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    try:
        result = await manager.call_tool(tool, arguments)
        await audit_logger.log_operation(user, tool, arguments, result, True)
        return result
    except Exception as e:
        await audit_logger.log_operation(user, tool, arguments, e, False)
        raise
```

## Event-Driven Patterns

### 1. Event Bus Pattern

Decouple components with events:

```python
from typing import Dict, List, Callable
import asyncio

class EventBus:
    """Event bus for MCP operations."""
    
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
    
    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe to an event type."""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)
    
    async def publish(self, event_type: str, data: Dict[str, Any]):
        """Publish an event."""
        if event_type in self.subscribers:
            tasks = []
            for handler in self.subscribers[event_type]:
                task = asyncio.create_task(handler(data))
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)

# Define event handlers
async def on_deployment_started(event: Dict[str, Any]):
    """Handle deployment started event."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    await manager.call_tool(
        "slack-notifications.post_message",
        {
            "channel": "#deployments",
            "text": f"🚀 Deployment started: {event['app']} v{event['version']}"
        }
    )

async def on_deployment_completed(event: Dict[str, Any]):
    """Handle deployment completed event."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Update metrics
    await manager.call_tool(
        "prometheus-monitoring.prometheus_query",
        {
            "query": f'deployment_info{{app="{event["app"]}",version="{event["version"]}"}}'
        }
    )
    
    # Create work item for post-deployment tasks
    await manager.call_tool(
        "azure-devops.create_work_item",
        {
            "project": "Operations",
            "work_item_type": "Task",
            "title": f"Post-deployment validation for {event['app']}",
            "description": f"Validate deployment of {event['app']} v{event['version']}"
        }
    )

async def on_security_issue_found(event: Dict[str, Any]):
    """Handle security issue event."""
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Send urgent notification
    await manager.call_tool(
        "slack-notifications.send_notification",
        {
            "channel": "#security-alerts",
            "notification_type": "security_alert",
            "title": "🚨 Security Issue Detected",
            "details": event,
            "color": "danger"
        }
    )

# Usage
event_bus = EventBus()

# Register handlers
event_bus.subscribe("deployment.started", on_deployment_started)
event_bus.subscribe("deployment.completed", on_deployment_completed)
event_bus.subscribe("security.issue_found", on_security_issue_found)

# Deployment with events
async def deploy_with_events(app: str, version: str):
    # Publish start event
    await event_bus.publish("deployment.started", {
        "app": app,
        "version": version,
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        # Perform deployment
        result = await deploy_application(app, version)
        
        # Publish completion event
        await event_bus.publish("deployment.completed", {
            "app": app,
            "version": version,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
    except SecurityException as e:
        # Publish security event
        await event_bus.publish("security.issue_found", {
            "app": app,
            "version": version,
            "issue": str(e),
            "timestamp": datetime.now().isoformat()
        })
        raise
```

### 2. Webhook Pattern

Integrate with external systems:

```python
class WebhookManager:
    """Manage webhooks for MCP events."""
    
    def __init__(self):
        self.webhooks: Dict[str, List[str]] = {}
    
    def register_webhook(self, event_type: str, url: str):
        """Register a webhook URL for an event type."""
        if event_type not in self.webhooks:
            self.webhooks[event_type] = []
        self.webhooks[event_type].append(url)
    
    async def trigger_webhooks(self, event_type: str, payload: Dict[str, Any]):
        """Trigger all webhooks for an event type."""
        urls = self.webhooks.get(event_type, [])
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                task = self._send_webhook(session, url, payload)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                "triggered": len(urls),
                "successful": sum(1 for r in results if not isinstance(r, Exception))
            }
    
    async def _send_webhook(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: Dict[str, Any]
    ):
        """Send webhook request."""
        headers = {
            "Content-Type": "application/json",
            "X-MCP-Event": payload.get("event_type", "unknown")
        }
        
        async with session.post(url, json=payload, headers=headers) as response:
            return {
                "url": url,
                "status": response.status,
                "response": await response.text()
            }

# Usage
webhook_manager = WebhookManager()

# Register webhooks
webhook_manager.register_webhook(
    "deployment.completed",
    "https://example.com/webhooks/deployment"
)
webhook_manager.register_webhook(
    "security.scan_completed",
    "https://security.example.com/webhooks/scan"
)

# Trigger webhooks after operations
async def deploy_with_webhooks(app: str, version: str):
    # Perform deployment
    result = await deploy_application(app, version)
    
    # Trigger webhooks
    await webhook_manager.trigger_webhooks("deployment.completed", {
        "event_type": "deployment.completed",
        "app": app,
        "version": version,
        "environment": "production",
        "timestamp": datetime.now().isoformat(),
        "result": result
    })
```

## Testing Patterns

### 1. Mock MCP Manager

Test without real infrastructure:

```python
class MockMCPManager:
    """Mock MCP manager for testing."""
    
    def __init__(self):
        self.call_history = []
        self.mock_responses = {}
    
    def set_mock_response(self, tool: str, response: Any):
        """Set mock response for a tool."""
        self.mock_responses[tool] = response
    
    async def call_tool(self, tool: str, arguments: Dict[str, Any]) -> Any:
        """Mock tool call."""
        self.call_history.append({
            "tool": tool,
            "arguments": arguments,
            "timestamp": datetime.now()
        })
        
        if tool in self.mock_responses:
            return self.mock_responses[tool]
        
        # Default mock responses
        if tool == "docker.docker_build":
            return {"image_id": "mock-image-123", "success": True}
        elif tool == "kubernetes.kubectl_apply":
            return {"applied_resources": ["deployment/app"], "status": "created"}
        elif tool == "security-scanner.docker_security_scan":
            return {"total_vulnerabilities": 0, "vulnerabilities": []}
        
        raise NotImplementedError(f"No mock for tool: {tool}")
    
    def assert_called_with(self, tool: str, arguments: Dict[str, Any]):
        """Assert tool was called with specific arguments."""
        for call in self.call_history:
            if call["tool"] == tool and call["arguments"] == arguments:
                return True
        
        raise AssertionError(
            f"Tool {tool} was not called with arguments {arguments}"
        )

# Usage in tests
async def test_deployment():
    # Create mock manager
    mock_manager = MockMCPManager()
    
    # Set specific mock response
    mock_manager.set_mock_response(
        "security-scanner.docker_security_scan",
        {"total_vulnerabilities": 2, "vulnerabilities": ["CVE-2021-1234"]}
    )
    
    # Run deployment with mock
    result = await deploy_with_manager(mock_manager, "myapp", "1.0.0")
    
    # Verify calls
    mock_manager.assert_called_with(
        "docker.docker_build",
        {"dockerfile_path": ".", "image_tag": "myapp:1.0.0"}
    )
    
    assert result["status"] == "failed"  # Due to vulnerabilities
```

### 2. Integration Test Pattern

Test with real services:

```python
import pytest

class IntegrationTestBase:
    """Base class for integration tests."""
    
    @classmethod
    async def setup_class(cls):
        """Set up test environment."""
        cls.manager = get_mcp_manager()
        await cls.manager.initialize()
        
        # Create test namespace
        cls.test_namespace = f"test-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        await cls.manager.call_tool(
            "desktop-commander.execute_command",
            {
                "command": f"kubectl create namespace {cls.test_namespace}"
            }
        )
    
    @classmethod
    async def teardown_class(cls):
        """Clean up test environment."""
        # Delete test namespace
        await cls.manager.call_tool(
            "kubernetes.kubectl_delete",
            {
                "resource_type": "namespace",
                "name": cls.test_namespace,
                "force": True
            }
        )
    
    async def deploy_test_app(self, app_name: str):
        """Deploy app to test namespace."""
        return await self.manager.call_tool(
            "kubernetes.kubectl_apply",
            {
                "manifest_path": f"./tests/fixtures/{app_name}/",
                "namespace": self.test_namespace
            }
        )

@pytest.mark.integration
class TestDeploymentIntegration(IntegrationTestBase):
    """Integration tests for deployment."""
    
    async def test_full_deployment_cycle(self):
        """Test complete deployment cycle."""
        # Deploy application
        deploy_result = await self.deploy_test_app("sample-app")
        assert deploy_result["status"] == "created"
        
        # Check deployment status
        status = await self.manager.call_tool(
            "kubernetes.kubectl_get",
            {
                "resource_type": "deployment",
                "name": "sample-app",
                "namespace": self.test_namespace
            }
        )
        
        assert status["items"][0]["status"]["replicas"] > 0
        
        # Scale deployment
        scale_result = await self.manager.call_tool(
            "kubernetes.kubectl_scale",
            {
                "resource_type": "deployment",
                "name": "sample-app",
                "replicas": 3,
                "namespace": self.test_namespace
            }
        )
        
        assert scale_result["success"] is True
```

## Conclusion

These integration patterns provide a foundation for building robust infrastructure automation with the CODE MCP API. Key takeaways:

1. **Use architectural patterns** to organize complex workflows
2. **Implement proper error handling** with retries and circuit breakers
3. **Optimize performance** with batching and caching
4. **Ensure security** with least privilege and audit logging
5. **Enable extensibility** with event-driven patterns
6. **Test thoroughly** with mocks and integration tests

For more examples and patterns, see:
- [API Reference](../reference/mcp_tools_reference.md)
- [Quick Start Guide](./quick_start_guide.md)
- [Example Repository](https://github.com/code-deployment/examples)