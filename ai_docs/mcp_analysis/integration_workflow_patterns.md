# Cross-MCP Server Integration Patterns and Complex Workflows

This document analyzes cross-MCP server integration patterns and complex workflows in the Claude Code deployment system, focusing on multi-server command chains, workflow automation patterns, error handling strategies, and performance optimizations.

## Table of Contents

1. [Multi-Server Command Chains](#multi-server-command-chains)
2. [Workflow Automation Patterns](#workflow-automation-patterns)
3. [Error Handling and Fallback Strategies](#error-handling-and-fallback-strategies)
4. [Performance Optimization Techniques](#performance-optimization-techniques)
5. [Complex Workflow Examples](#complex-workflow-examples)
6. [Integration Architecture Patterns](#integration-architecture-patterns)
7. [Best Practices and Recommendations](#best-practices-and-recommendations)

## Multi-Server Command Chains

### 1. Deployment Chain Pattern

The deployment chain demonstrates sophisticated multi-server coordination:

```python
# Security → Infrastructure → Deployment → Monitoring → Notification
async def deployment_chain():
    # 1. Security Assessment
    security_results = await mcp_manager.call_tool(
        "security-scanner.comprehensive_scan",
        {"scope": "full", "severity": "medium"},
        context_id
    )
    
    # 2. Infrastructure Preparation
    env_results = await mcp_manager.call_tool(
        "desktop-commander.execute_command",
        {"command": "mkdir -p deploy/{config,logs,backup}"},
        context_id
    )
    
    # 3. Docker Build
    build_results = await mcp_manager.call_tool(
        "docker.docker_build",
        {"dockerfile_path": "Dockerfile", "image_tag": "app:latest"},
        context_id
    )
    
    # 4. Kubernetes Deployment
    k8s_results = await mcp_manager.call_tool(
        "kubernetes.kubectl_apply",
        {"manifest_path": "k8s/", "namespace": "production"},
        context_id
    )
    
    # 5. Monitoring Setup
    monitor_results = await mcp_manager.call_tool(
        "prometheus-monitoring.setup_alerts",
        {"service": "app", "environment": "production"},
        context_id
    )
    
    # 6. Notification
    await mcp_manager.call_tool(
        "communication-hub.broadcast_deployment",
        {
            "environment": "production",
            "service": "app",
            "status": "completed",
            "details": {"security": len(security_results.get("findings", []))}
        },
        context_id
    )
```

### 2. Security Audit Chain Pattern

Multi-layer security validation across different tools:

```bash
# Bash command chain from CLAUDE.md
bandit -r src/ -f json | tee bandit_report.json && \
safety check --json | tee safety_report.json && \
pip-audit --format json | tee pip_audit.json && \
npm audit --json | tee npm_audit.json && \
trivy fs . --format json | tee trivy_report.json && \
semgrep --config=auto --json | tee semgrep_report.json && \
python scripts/consolidate_security_reports.py \
  --output=comprehensive_security_report.json
```

Equivalent MCP server chain:

```python
async def security_audit_chain():
    results = {}
    
    # Python security scan
    results["bandit"] = await mcp_manager.call_tool(
        "security-scanner.bandit_scan",
        {"path": "src/", "format": "json"},
        context_id
    )
    
    # Dependency vulnerability scan
    results["safety"] = await mcp_manager.call_tool(
        "security-scanner.python_safety_check",
        {"requirements_path": "requirements.txt"},
        context_id
    )
    
    # Container security scan
    results["trivy"] = await mcp_manager.call_tool(
        "security-scanner.container_scan",
        {"image": "app:latest", "format": "json"},
        context_id
    )
    
    # Static analysis
    results["semgrep"] = await mcp_manager.call_tool(
        "security-scanner.static_analysis",
        {"config": "auto", "path": "."},
        context_id
    )
    
    # Consolidate and report
    await mcp_manager.call_tool(
        "security-scanner.consolidate_reports",
        {"reports": results, "output": "comprehensive_security_report.json"},
        context_id
    )
```

### 3. Performance Optimization Chain

Memory and performance analysis with automated remediation:

```python
async def performance_optimization_chain():
    # Memory profiling
    memory_results = await mcp_manager.call_tool(
        "desktop-commander.execute_command",
        {"command": "pytest tests/memory/ --memray --memray-bin-path=.memray"},
        context_id
    )
    
    # Generate flamegraph
    await mcp_manager.call_tool(
        "desktop-commander.execute_command",
        {"command": "memray flamegraph .memray/*.bin -o memory_profile.html"},
        context_id
    )
    
    # Performance analysis
    analysis_results = await mcp_manager.call_tool(
        "desktop-commander.execute_command",
        {"command": "python scripts/analyze_memory_usage.py --detect-leaks"},
        context_id
    )
    
    # Auto-optimization if issues found
    if analysis_results.get("memory_leaks_detected"):
        await mcp_manager.call_tool(
            "desktop-commander.execute_command",
            {"command": "python scripts/auto_fix_memory_issues.py"},
            context_id
        )
        
        # Notification of auto-fix
        await mcp_manager.call_tool(
            "communication-hub.send_alert",
            {
                "message": "Memory leaks detected and auto-remediation applied",
                "severity": "medium",
                "metadata": {"analysis": analysis_results}
            },
            context_id
        )
```

## Workflow Automation Patterns

### 1. Event-Driven Workflow Pattern

```python
class EventDrivenWorkflow:
    """Event-driven workflow orchestration pattern."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.event_handlers = {}
        self.workflow_state = {}
    
    async def register_event_handler(self, event_type, handler):
        """Register event handler for workflow automation."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    async def trigger_event(self, event_type, event_data, context_id):
        """Trigger event and execute associated workflows."""
        handlers = self.event_handlers.get(event_type, [])
        
        for handler in handlers:
            try:
                await handler(event_data, context_id)
            except Exception as e:
                await self.mcp_manager.call_tool(
                    "communication-hub.send_alert",
                    {
                        "message": f"Workflow handler failed: {str(e)}",
                        "severity": "high",
                        "metadata": {"event_type": event_type, "handler": handler.__name__}
                    },
                    context_id
                )

# Example usage
async def deployment_success_handler(event_data, context_id):
    """Handle successful deployment event."""
    # Update monitoring
    await mcp_manager.call_tool(
        "prometheus-monitoring.update_deployment_status",
        {"status": "active", "version": event_data["version"]},
        context_id
    )
    
    # Backup configuration
    await mcp_manager.call_tool(
        "s3-storage.backup_config",
        {"source": "k8s/", "backup_name": f"deployment_{event_data['version']}"},
        context_id
    )
    
    # Notify stakeholders
    await mcp_manager.call_tool(
        "communication-hub.broadcast_deployment",
        {
            "environment": event_data["environment"],
            "service": event_data["service"],
            "version": event_data["version"],
            "status": "completed"
        },
        context_id
    )
```

### 2. Pipeline Pattern with Conditional Logic

```python
class ConditionalPipeline:
    """Conditional pipeline pattern for complex workflows."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.pipeline_steps = []
    
    def add_step(self, step_func, condition=None, rollback_func=None):
        """Add step to pipeline with optional condition and rollback."""
        self.pipeline_steps.append({
            "func": step_func,
            "condition": condition,
            "rollback": rollback_func
        })
    
    async def execute(self, context_id, initial_data=None):
        """Execute pipeline with conditional logic and rollback support."""
        executed_steps = []
        data = initial_data or {}
        
        try:
            for i, step in enumerate(self.pipeline_steps):
                # Check condition
                if step["condition"] and not await step["condition"](data, context_id):
                    continue
                
                # Execute step
                result = await step["func"](data, context_id)
                data.update(result)
                executed_steps.append((i, step))
                
                # Log progress
                await self.mcp_manager.call_tool(
                    "communication-hub.send_notification",
                    {
                        "message": f"Pipeline step {i+1} completed",
                        "channels": ["dashboard"],
                        "priority": "normal"
                    },
                    context_id
                )
        
        except Exception as e:
            # Rollback executed steps in reverse order
            for i, step in reversed(executed_steps):
                if step["rollback"]:
                    try:
                        await step["rollback"](data, context_id)
                    except Exception as rollback_error:
                        await self.mcp_manager.call_tool(
                            "communication-hub.send_alert",
                            {
                                "message": f"Rollback failed for step {i}: {rollback_error}",
                                "severity": "critical"
                            },
                            context_id
                        )
            raise
        
        return data

# Example: Deployment pipeline with conditions
async def setup_deployment_pipeline():
    pipeline = ConditionalPipeline(mcp_manager)
    
    # Security scan (always run)
    pipeline.add_step(
        step_func=security_scan_step,
        rollback_func=None
    )
    
    # Docker build (only if Dockerfile exists)
    pipeline.add_step(
        step_func=docker_build_step,
        condition=lambda data, ctx: Path("Dockerfile").exists(),
        rollback_func=docker_cleanup_step
    )
    
    # Kubernetes deployment (only if cluster available)
    pipeline.add_step(
        step_func=k8s_deploy_step,
        condition=check_k8s_availability,
        rollback_func=k8s_rollback_step
    )
    
    return pipeline
```

### 3. Parallel Execution Pattern

```python
async def parallel_deployment_workflow():
    """Execute multiple deployment tasks in parallel."""
    
    # Create parallel task groups
    security_tasks = [
        mcp_manager.call_tool(
            "security-scanner.bandit_scan",
            {"path": "src/"},
            context_id
        ),
        mcp_manager.call_tool(
            "security-scanner.npm_audit", 
            {"package_json_path": "package.json"},
            context_id
        ),
        mcp_manager.call_tool(
            "security-scanner.container_scan",
            {"dockerfile": "Dockerfile"},
            context_id
        )
    ]
    
    build_tasks = [
        mcp_manager.call_tool(
            "docker.docker_build",
            {"dockerfile_path": "Dockerfile", "image_tag": "app:latest"},
            context_id
        ),
        mcp_manager.call_tool(
            "desktop-commander.execute_command",
            {"command": "npm run build"},
            context_id
        )
    ]
    
    # Execute tasks in parallel with timeout
    try:
        security_results = await asyncio.gather(*security_tasks, timeout=300)
        build_results = await asyncio.gather(*build_tasks, timeout=600)
        
        # Combine results and proceed with deployment
        if all(result.get("success", False) for result in security_results + build_results):
            deployment_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {"manifest_path": "k8s/", "namespace": "production"},
                context_id
            )
    
    except asyncio.TimeoutError:
        # Handle timeout with graceful degradation
        await mcp_manager.call_tool(
            "communication-hub.send_alert",
            {
                "message": "Deployment workflow timed out",
                "severity": "high",
                "metadata": {"context_id": context_id}
            },
            context_id
        )
```

## Error Handling and Fallback Strategies

### 1. Circuit Breaker Pattern Implementation

The system implements circuit breakers for reliability:

```python
# From mcp/manager.py
async def call_tool(self, tool_name: str, arguments: Dict[str, Any], context_id: Optional[str] = None):
    """Call tool with circuit breaker protection."""
    
    # Get circuit breaker for this server/tool combination
    breaker_manager = get_circuit_breaker_manager()
    breaker = await breaker_manager.get_or_create(
        f"mcp_{server_name}_{actual_tool_name}",
        CircuitBreakerConfig(
            failure_threshold=3,
            timeout=60,
            failure_rate_threshold=0.5,
            minimum_calls=5,
            excluded_exceptions=[MCPToolNotFoundError, MCPServerNotFoundError],
            fallback=lambda: self._create_tool_fallback_response(
                server_name, actual_tool_name, arguments
            )
        )
    )
    
    try:
        result = await breaker.call(server.call_tool, actual_tool_name, arguments)
        return result
    except CircuitOpenError:
        # Return fallback response when circuit is open
        return self._create_tool_fallback_response(server_name, actual_tool_name, arguments)
```

### 2. Graceful Degradation Strategy

```python
class GracefulDegradationManager:
    """Manage graceful degradation across MCP servers."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.fallback_strategies = {}
    
    def register_fallback(self, primary_server, fallback_server, compatibility_map):
        """Register fallback server for primary server."""
        self.fallback_strategies[primary_server] = {
            "fallback": fallback_server,
            "mapping": compatibility_map
        }
    
    async def execute_with_fallback(self, server_name, tool_name, arguments, context_id):
        """Execute tool with automatic fallback to alternative server."""
        try:
            # Try primary server
            return await self.mcp_manager.call_tool(
                f"{server_name}.{tool_name}",
                arguments,
                context_id
            )
        
        except Exception as primary_error:
            # Check for registered fallback
            fallback_config = self.fallback_strategies.get(server_name)
            
            if fallback_config:
                fallback_server = fallback_config["fallback"]
                mapping = fallback_config["mapping"]
                
                # Map tool and arguments to fallback server
                fallback_tool = mapping.get(tool_name, tool_name)
                fallback_args = self._map_arguments(arguments, mapping)
                
                try:
                    result = await self.mcp_manager.call_tool(
                        f"{fallback_server}.{fallback_tool}",
                        fallback_args,
                        context_id
                    )
                    
                    # Log fallback usage
                    await self.mcp_manager.call_tool(
                        "communication-hub.send_notification",
                        {
                            "message": f"Fallback used: {server_name} → {fallback_server}",
                            "channels": ["dashboard"],
                            "priority": "normal"
                        },
                        context_id
                    )
                    
                    return result
                
                except Exception as fallback_error:
                    # Both primary and fallback failed
                    await self.mcp_manager.call_tool(
                        "communication-hub.send_alert",
                        {
                            "message": f"Both primary and fallback servers failed",
                            "severity": "high",
                            "metadata": {
                                "primary_server": server_name,
                                "fallback_server": fallback_server,
                                "primary_error": str(primary_error),
                                "fallback_error": str(fallback_error)
                            }
                        },
                        context_id
                    )
                    raise fallback_error
            
            else:
                # No fallback available
                raise primary_error

# Example fallback configuration
degradation_manager = GracefulDegradationManager(mcp_manager)

# If primary security scanner fails, use secondary
degradation_manager.register_fallback(
    primary_server="security-scanner",
    fallback_server="desktop-commander", 
    compatibility_map={
        "bandit_scan": "execute_command",
        "npm_audit": "execute_command"
    }
)
```

### 3. Retry Logic with Exponential Backoff

```python
class RetryManager:
    """Advanced retry logic for MCP server calls."""
    
    @staticmethod
    async def execute_with_retry(
        mcp_manager,
        tool_call_func,
        max_retries=3,
        base_delay=1.0,
        max_delay=60.0,
        backoff_factor=2.0,
        context_id=None
    ):
        """Execute MCP tool call with exponential backoff retry."""
        
        for attempt in range(max_retries + 1):
            try:
                return await tool_call_func()
            
            except Exception as e:
                if attempt == max_retries:
                    # Final attempt failed
                    await mcp_manager.call_tool(
                        "communication-hub.send_alert",
                        {
                            "message": f"Tool call failed after {max_retries} retries: {str(e)}",
                            "severity": "high",
                            "metadata": {"attempts": attempt + 1, "error": str(e)}
                        },
                        context_id
                    )
                    raise
                
                # Calculate delay with exponential backoff
                delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                
                await mcp_manager.call_tool(
                    "communication-hub.send_notification",
                    {
                        "message": f"Retrying tool call in {delay:.1f}s (attempt {attempt + 1}/{max_retries})",
                        "channels": ["dashboard"],
                        "priority": "low"
                    },
                    context_id
                )
                
                await asyncio.sleep(delay)

# Usage example
async def reliable_deployment():
    async def deploy_to_k8s():
        return await mcp_manager.call_tool(
            "kubernetes.kubectl_apply",
            {"manifest_path": "k8s/", "namespace": "production"},
            context_id
        )
    
    result = await RetryManager.execute_with_retry(
        mcp_manager=mcp_manager,
        tool_call_func=deploy_to_k8s,
        max_retries=3,
        base_delay=2.0,
        context_id=context_id
    )
```

### 4. Health Check and Recovery Pattern

```python
class HealthCheckManager:
    """Monitor MCP server health and trigger recovery."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.health_checks = {}
        self.recovery_actions = {}
    
    async def register_health_check(self, server_name, check_func, recovery_func=None):
        """Register health check for MCP server."""
        self.health_checks[server_name] = check_func
        if recovery_func:
            self.recovery_actions[server_name] = recovery_func
    
    async def monitor_health(self, context_id):
        """Continuously monitor server health."""
        while True:
            for server_name, check_func in self.health_checks.items():
                try:
                    is_healthy = await check_func(context_id)
                    
                    if not is_healthy:
                        await self._handle_unhealthy_server(server_name, context_id)
                
                except Exception as e:
                    await self.mcp_manager.call_tool(
                        "communication-hub.send_alert",
                        {
                            "message": f"Health check failed for {server_name}: {str(e)}",
                            "severity": "medium"
                        },
                        context_id
                    )
            
            await asyncio.sleep(30)  # Check every 30 seconds
    
    async def _handle_unhealthy_server(self, server_name, context_id):
        """Handle unhealthy server detection."""
        # Try recovery action
        recovery_func = self.recovery_actions.get(server_name)
        if recovery_func:
            try:
                await recovery_func(context_id)
                await self.mcp_manager.call_tool(
                    "communication-hub.send_notification",
                    {
                        "message": f"Recovery action executed for {server_name}",
                        "channels": ["dashboard"],
                        "priority": "normal"
                    },
                    context_id
                )
            except Exception as e:
                await self.mcp_manager.call_tool(
                    "communication-hub.send_alert",
                    {
                        "message": f"Recovery failed for {server_name}: {str(e)}",
                        "severity": "high"
                    },
                    context_id
                )

# Health check examples
async def docker_health_check(context_id):
    """Check Docker service health."""
    try:
        result = await mcp_manager.call_tool(
            "docker.docker_ps",
            {"all": False},
            context_id
        )
        return result.get("success", False)
    except:
        return False

async def docker_recovery(context_id):
    """Attempt Docker service recovery."""
    await mcp_manager.call_tool(
        "desktop-commander.execute_command",
        {"command": "sudo systemctl restart docker"},
        context_id
    )
```

## Performance Optimization Techniques

### 1. Connection Pooling and Resource Management

```python
class MCPResourceManager:
    """Optimize MCP server resource usage."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.connection_pools = {}
        self.resource_limits = {}
        self.active_connections = defaultdict(int)
    
    async def get_optimized_connection(self, server_name, context_id):
        """Get optimized connection with pooling."""
        # Check connection limits
        if self.active_connections[server_name] >= self.resource_limits.get(server_name, 10):
            # Wait for available connection
            await self._wait_for_available_connection(server_name)
        
        self.active_connections[server_name] += 1
        return server_name
    
    async def release_connection(self, server_name):
        """Release connection back to pool."""
        self.active_connections[server_name] = max(0, self.active_connections[server_name] - 1)
    
    async def execute_with_resource_management(self, server_name, tool_name, arguments, context_id):
        """Execute tool call with resource management."""
        connection = await self.get_optimized_connection(server_name, context_id)
        
        try:
            result = await self.mcp_manager.call_tool(
                f"{server_name}.{tool_name}",
                arguments,
                context_id
            )
            return result
        finally:
            await self.release_connection(server_name)
```

### 2. Caching Strategy

The system implements sophisticated caching:

```python
# From mcp/manager.py - TTL cache for contexts
self.contexts = create_ttl_dict(
    max_size=200,
    ttl=3600.0,  # 1 hour
    cleanup_interval=300.0  # 5 minutes
)

# Cache stats monitoring
def get_cache_stats(self) -> Dict[str, Any]:
    """Get cache statistics for monitoring."""
    try:
        stats = self.contexts.get_stats()
        
        # Calculate tool call statistics
        total_tool_calls = 0
        active_contexts = 0
        for context in self.contexts.items():
            if isinstance(context[1], MCPContext):
                active_contexts += 1
                total_tool_calls += len(context[1].tool_calls)
        
        return {
            "contexts_cache": stats.to_dict(),
            "active_contexts": active_contexts,
            "total_tool_calls": total_tool_calls,
            "cache_type": "TTLDict with LRU eviction"
        }
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {}
```

### 3. Batch Processing Optimization

```python
class BatchProcessor:
    """Optimize MCP operations through batching."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.batch_queues = defaultdict(list)
        self.batch_timers = {}
        self.batch_size_limits = {
            "notification": 10,
            "deployment": 5,
            "monitoring": 20
        }
    
    async def add_to_batch(self, batch_type, operation, context_id):
        """Add operation to batch queue."""
        self.batch_queues[batch_type].append(operation)
        
        # Set timer for batch processing if not already set
        if batch_type not in self.batch_timers:
            self.batch_timers[batch_type] = asyncio.create_task(
                self._process_batch_after_delay(batch_type, context_id)
            )
        
        # Process immediately if batch size limit reached
        if len(self.batch_queues[batch_type]) >= self.batch_size_limits.get(batch_type, 10):
            await self._process_batch(batch_type, context_id)
    
    async def _process_batch_after_delay(self, batch_type, context_id, delay=5.0):
        """Process batch after delay."""
        await asyncio.sleep(delay)
        await self._process_batch(batch_type, context_id)
    
    async def _process_batch(self, batch_type, context_id):
        """Process accumulated batch operations."""
        if batch_type not in self.batch_queues or not self.batch_queues[batch_type]:
            return
        
        operations = self.batch_queues[batch_type]
        self.batch_queues[batch_type] = []
        
        # Cancel timer
        if batch_type in self.batch_timers:
            self.batch_timers[batch_type].cancel()
            del self.batch_timers[batch_type]
        
        # Process operations in parallel
        try:
            results = await asyncio.gather(*[
                self._execute_operation(op, context_id) for op in operations
            ], return_exceptions=True)
            
            # Log batch completion
            await self.mcp_manager.call_tool(
                "communication-hub.send_notification",
                {
                    "message": f"Batch processed: {len(operations)} {batch_type} operations",
                    "channels": ["dashboard"],
                    "priority": "low"
                },
                context_id
            )
            
        except Exception as e:
            await self.mcp_manager.call_tool(
                "communication-hub.send_alert",
                {
                    "message": f"Batch processing failed for {batch_type}: {str(e)}",
                    "severity": "medium"
                },
                context_id
            )
```

### 4. Asynchronous Task Management

```python
class AsyncTaskManager:
    """Manage long-running asynchronous tasks across MCP servers."""
    
    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.running_tasks = {}
        self.task_results = {}
        self.task_callbacks = defaultdict(list)
    
    async def submit_long_running_task(self, task_id, server_name, tool_name, arguments, context_id):
        """Submit long-running task for background execution."""
        
        async def task_wrapper():
            try:
                result = await self.mcp_manager.call_tool(
                    f"{server_name}.{tool_name}",
                    arguments,
                    context_id
                )
                
                self.task_results[task_id] = {"success": True, "result": result}
                
                # Execute callbacks
                for callback in self.task_callbacks[task_id]:
                    try:
                        await callback(result)
                    except Exception as callback_error:
                        logger.error(f"Task callback failed: {callback_error}")
                
            except Exception as e:
                self.task_results[task_id] = {"success": False, "error": str(e)}
                
                await self.mcp_manager.call_tool(
                    "communication-hub.send_alert",
                    {
                        "message": f"Long-running task {task_id} failed: {str(e)}",
                        "severity": "medium",
                        "metadata": {"task_id": task_id, "server": server_name, "tool": tool_name}
                    },
                    context_id
                )
            
            finally:
                # Cleanup
                if task_id in self.running_tasks:
                    del self.running_tasks[task_id]
        
        task = asyncio.create_task(task_wrapper())
        self.running_tasks[task_id] = task
        
        return task_id
    
    async def get_task_status(self, task_id):
        """Get status of running task."""
        if task_id in self.running_tasks:
            return {"status": "running", "task": self.running_tasks[task_id]}
        elif task_id in self.task_results:
            return {"status": "completed", "result": self.task_results[task_id]}
        else:
            return {"status": "not_found"}
    
    def add_task_callback(self, task_id, callback_func):
        """Add callback for task completion."""
        self.task_callbacks[task_id].append(callback_func)
```

## Complex Workflow Examples

### 1. Full CI/CD Pipeline Workflow

```python
async def full_cicd_pipeline(mcp_manager, context_id):
    """Complete CI/CD pipeline using multiple MCP servers."""
    
    pipeline_results = {}
    
    try:
        # 1. Code Quality and Security Assessment
        print("📋 Running code quality and security assessment...")
        
        quality_tasks = [
            mcp_manager.call_tool("security-scanner.bandit_scan", {"path": "src/"}, context_id),
            mcp_manager.call_tool("security-scanner.npm_audit", {"package_json_path": "package.json"}, context_id),
            mcp_manager.call_tool("desktop-commander.execute_command", {"command": "black --check src/"}, context_id),
            mcp_manager.call_tool("desktop-commander.execute_command", {"command": "mypy src/"}, context_id)
        ]
        
        quality_results = await asyncio.gather(*quality_tasks, return_exceptions=True)
        pipeline_results["quality"] = quality_results
        
        # 2. Build and Test
        print("🔨 Building and testing application...")
        
        build_result = await mcp_manager.call_tool(
            "docker.docker_build",
            {"dockerfile_path": "Dockerfile", "image_tag": "app:latest"},
            context_id
        )
        pipeline_results["build"] = build_result
        
        if build_result.get("success"):
            test_result = await mcp_manager.call_tool(
                "docker.docker_run",
                {
                    "image": "app:latest",
                    "command": "pytest tests/ --cov=src/",
                    "volumes": [f"{os.getcwd()}:/app"]
                },
                context_id
            )
            pipeline_results["test"] = test_result
        
        # 3. Security Scanning
        print("🔒 Running security scans...")
        
        security_scan = await mcp_manager.call_tool(
            "security-scanner.container_scan",
            {"image": "app:latest", "format": "json"},
            context_id
        )
        pipeline_results["security_scan"] = security_scan
        
        # 4. Deployment Decision
        deploy_ready = (
            build_result.get("success", False) and
            pipeline_results.get("test", {}).get("success", False) and
            len(security_scan.get("vulnerabilities", [])) == 0
        )
        
        if deploy_ready:
            # 5. Deploy to Staging
            print("🚀 Deploying to staging...")
            
            staging_deploy = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {"manifest_path": "k8s/staging/", "namespace": "staging"},
                context_id
            )
            pipeline_results["staging_deploy"] = staging_deploy
            
            # 6. Integration Tests
            if staging_deploy.get("success"):
                print("🧪 Running integration tests...")
                
                integration_tests = await mcp_manager.call_tool(
                    "desktop-commander.execute_command",
                    {"command": "pytest tests/integration/ --env=staging"},
                    context_id
                )
                pipeline_results["integration_tests"] = integration_tests
                
                # 7. Production Deployment (if integration tests pass)
                if integration_tests.get("success"):
                    print("🎯 Deploying to production...")
                    
                    # Backup current production
                    backup_result = await mcp_manager.call_tool(
                        "s3-storage.backup_deployment",
                        {"environment": "production", "service": "app"},
                        context_id
                    )
                    
                    # Deploy to production
                    prod_deploy = await mcp_manager.call_tool(
                        "kubernetes.kubectl_apply",
                        {"manifest_path": "k8s/production/", "namespace": "production"},
                        context_id
                    )
                    pipeline_results["production_deploy"] = prod_deploy
                    
                    # 8. Health Checks and Monitoring
                    if prod_deploy.get("success"):
                        print("📊 Setting up monitoring and health checks...")
                        
                        monitoring_tasks = [
                            mcp_manager.call_tool(
                                "prometheus-monitoring.setup_alerts",
                                {"service": "app", "environment": "production"},
                                context_id
                            ),
                            mcp_manager.call_tool(
                                "desktop-commander.execute_command",
                                {"command": "kubectl wait --for=condition=ready pod -l app=app -n production --timeout=300s"},
                                context_id
                            )
                        ]
                        
                        monitoring_results = await asyncio.gather(*monitoring_tasks)
                        pipeline_results["monitoring"] = monitoring_results
        
        # 9. Comprehensive Notification
        print("📢 Sending deployment notifications...")
        
        overall_success = deploy_ready and pipeline_results.get("production_deploy", {}).get("success", False)
        
        await mcp_manager.call_tool(
            "communication-hub.broadcast_deployment",
            {
                "environment": "production" if overall_success else "staging",
                "service": "app",
                "version": "latest",
                "status": "completed" if overall_success else "failed",
                "details": {
                    "pipeline_steps": len(pipeline_results),
                    "security_issues": len(security_scan.get("vulnerabilities", [])),
                    "deploy_ready": deploy_ready
                }
            },
            context_id
        )
        
        return pipeline_results
        
    except Exception as e:
        # Pipeline failure handling
        await mcp_manager.call_tool(
            "communication-hub.send_alert",
            {
                "message": f"CI/CD pipeline failed: {str(e)}",
                "severity": "high",
                "metadata": {"context_id": context_id, "partial_results": pipeline_results}
            },
            context_id
        )
        raise
```

### 2. Disaster Recovery Workflow

```python
async def disaster_recovery_workflow(mcp_manager, context_id, incident_type):
    """Automated disaster recovery workflow."""
    
    recovery_results = {}
    
    try:
        # 1. Incident Assessment
        print(f"🚨 Assessing {incident_type} incident...")
        
        assessment = await mcp_manager.call_tool(
            "prometheus-monitoring.get_system_health",
            {"include_metrics": True, "time_range": "1h"},
            context_id
        )
        recovery_results["assessment"] = assessment
        
        # 2. Alert and Escalation
        await mcp_manager.call_tool(
            "communication-hub.send_alert",
            {
                "message": f"Disaster recovery initiated for {incident_type}",
                "severity": "critical",
                "escalation_policy": "critical",
                "metadata": {"incident_type": incident_type, "assessment": assessment}
            },
            context_id
        )
        
        # 3. Service Health Check
        print("🔍 Checking service health...")
        
        health_checks = [
            mcp_manager.call_tool("kubernetes.kubectl_get", {"resource_type": "pods", "namespace": "production"}, context_id),
            mcp_manager.call_tool("docker.docker_ps", {"all": False}, context_id),
            mcp_manager.call_tool("desktop-commander.execute_command", {"command": "systemctl status critical-services"}, context_id)
        ]
        
        health_results = await asyncio.gather(*health_checks, return_exceptions=True)
        recovery_results["health_checks"] = health_results
        
        # 4. Automated Recovery Actions
        print("🔧 Executing automated recovery actions...")
        
        if incident_type == "service_failure":
            # Restart failed services
            restart_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {"manifest_path": "k8s/production/", "namespace": "production"},
                context_id
            )
            recovery_results["restart"] = restart_result
            
        elif incident_type == "database_failure":
            # Switch to backup database
            db_failover = await mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "kubectl patch deployment app -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"app\",\"env\":[{\"name\":\"DATABASE_URL\",\"value\":\"${BACKUP_DATABASE_URL}\"}]}]}}}}'"},
                context_id
            )
            recovery_results["database_failover"] = db_failover
            
        elif incident_type == "infrastructure_failure":
            # Scale out to backup region
            scale_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {"manifest_path": "k8s/backup-region/", "namespace": "production"},
                context_id
            )
            recovery_results["scale_out"] = scale_result
        
        # 5. Data Backup and Recovery
        print("💾 Ensuring data backup and recovery...")
        
        backup_tasks = [
            mcp_manager.call_tool(
                "s3-storage.emergency_backup",
                {"source": "production-data", "priority": "high"},
                context_id
            ),
            mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "pg_dump $DATABASE_URL | gzip > /tmp/emergency_backup_$(date +%s).sql.gz"},
                context_id
            )
        ]
        
        backup_results = await asyncio.gather(*backup_tasks, return_exceptions=True)
        recovery_results["backups"] = backup_results
        
        # 6. Monitoring and Verification
        print("📊 Verifying recovery and setting up monitoring...")
        
        verification_tasks = [
            mcp_manager.call_tool(
                "prometheus-monitoring.verify_service_health",
                {"service": "app", "environment": "production", "timeout": 300},
                context_id
            ),
            mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "curl -f https://app.company.com/health"},
                context_id
            )
        ]
        
        verification_results = await asyncio.gather(*verification_tasks, return_exceptions=True)
        recovery_results["verification"] = verification_results
        
        # 7. Recovery Status Report
        recovery_success = all(
            result.get("success", False) for result in [
                recovery_results.get("restart", {}),
                recovery_results.get("database_failover", {}),
                recovery_results.get("scale_out", {})
            ] if result
        )
        
        await mcp_manager.call_tool(
            "communication-hub.send_notification",
            {
                "message": f"Disaster recovery {'completed successfully' if recovery_success else 'completed with issues'} for {incident_type}",
                "channels": ["slack", "email", "dashboard"],
                "priority": "critical",
                "template": "incident"
            },
            context_id
        )
        
        return recovery_results
        
    except Exception as e:
        await mcp_manager.call_tool(
            "communication-hub.send_alert",
            {
                "message": f"Disaster recovery workflow failed: {str(e)}",
                "severity": "critical",
                "metadata": {"incident_type": incident_type, "partial_results": recovery_results}
            },
            context_id
        )
        raise
```

## Integration Architecture Patterns

### 1. Hub-and-Spoke Pattern

The MCP Manager acts as a central hub coordinating all server interactions:

```
                    ┌─────────────────┐
                    │   MCP Manager   │
                    │   (Central Hub) │
                    └─────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────┐    ┌────────▼────┐    ┌────────▼────┐
│   Docker   │    │ Kubernetes  │    │   Security  │
│   Server   │    │   Server    │    │   Scanner   │
└────────────┘    └─────────────┘    └─────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────┐    ┌────────▼────┐    ┌────────▼────┐
│    S3      │    │Communication│    │ Prometheus  │
│  Storage   │    │     Hub     │    │ Monitoring  │
└────────────┘    └─────────────┘    └─────────────┘
```

### 2. Event-Driven Integration

```python
class EventBus:
    """Event bus for cross-MCP server communication."""
    
    def __init__(self):
        self.subscribers = defaultdict(list)
        self.event_history = []
    
    def subscribe(self, event_type, handler):
        """Subscribe to event type."""
        self.subscribers[event_type].append(handler)
    
    async def publish(self, event_type, event_data, context_id):
        """Publish event to all subscribers."""
        event = {
            "type": event_type,
            "data": event_data,
            "context_id": context_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.event_history.append(event)
        
        # Notify all subscribers
        for handler in self.subscribers[event_type]:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Event handler failed: {e}")

# Event-driven deployment workflow
event_bus = EventBus()

# Subscribe to deployment events
event_bus.subscribe("deployment.started", lambda e: setup_monitoring(e["data"]))
event_bus.subscribe("deployment.completed", lambda e: send_notifications(e["data"]))
event_bus.subscribe("deployment.failed", lambda e: trigger_rollback(e["data"]))

# Publish events during deployment
await event_bus.publish("deployment.started", {"service": "app", "version": "1.2.3"}, context_id)
```

### 3. Microservices Communication Pattern

Each MCP server acts as a microservice with defined interfaces:

```python
class MCPServiceRegistry:
    """Service registry for MCP server discovery and communication."""
    
    def __init__(self):
        self.services = {}
        self.service_dependencies = defaultdict(list)
        self.health_status = {}
    
    def register_service(self, service_name, server_instance, dependencies=None):
        """Register MCP server as service."""
        self.services[service_name] = server_instance
        if dependencies:
            self.service_dependencies[service_name] = dependencies
    
    async def call_service(self, service_name, operation, data, context_id):
        """Call service operation with dependency checking."""
        # Check service dependencies
        for dependency in self.service_dependencies[service_name]:
            if not self.health_status.get(dependency, False):
                raise ServiceUnavailableError(f"Dependency {dependency} unavailable")
        
        service = self.services.get(service_name)
        if not service:
            raise ServiceNotFoundError(f"Service {service_name} not found")
        
        return await service.call_tool(operation, data, context_id)
    
    async def health_check_all(self):
        """Check health of all registered services."""
        for service_name, service in self.services.items():
            try:
                # Attempt simple operation
                result = await service.get_server_info()
                self.health_status[service_name] = True
            except:
                self.health_status[service_name] = False
```

## Best Practices and Recommendations

### 1. Context Management

- **Context Isolation**: Each workflow should use isolated contexts to prevent interference
- **Context Cleanup**: Implement proper cleanup with TTL-based expiration
- **Context Sharing**: Share contexts carefully between related operations

```python
# Best practice: Context lifecycle management
async def managed_workflow(mcp_manager):
    context_id = f"workflow_{uuid.uuid4()}"
    context = mcp_manager.create_context(context_id)
    
    try:
        # Workflow operations
        await execute_workflow_steps(mcp_manager, context_id)
    finally:
        # Cleanup context
        if context_id in mcp_manager.contexts:
            del mcp_manager.contexts[context_id]
```

### 2. Error Handling Strategy

- **Graceful Degradation**: Always provide fallbacks for critical operations
- **Circuit Breakers**: Implement circuit breakers for external dependencies
- **Retry Logic**: Use exponential backoff for transient failures
- **Monitoring**: Track error rates and patterns

### 3. Performance Optimization

- **Batch Operations**: Group related operations for efficiency
- **Parallel Execution**: Use asyncio.gather for independent operations
- **Caching**: Cache frequently accessed data with appropriate TTL
- **Resource Limits**: Implement connection pooling and rate limiting

### 4. Security Considerations

- **Input Validation**: Validate all inputs before processing
- **Principle of Least Privilege**: Limit server permissions
- **Audit Logging**: Log all security-relevant operations
- **Secure Communication**: Use encrypted channels between servers

### 5. Monitoring and Observability

- **Comprehensive Logging**: Log all cross-server interactions
- **Metrics Collection**: Track performance and error metrics
- **Distributed Tracing**: Implement request tracing across servers
- **Health Monitoring**: Continuous health checking with alerting

### 6. Testing Strategies

- **Integration Testing**: Test complete workflows end-to-end
- **Chaos Engineering**: Test failure scenarios and recovery
- **Load Testing**: Verify performance under load
- **Security Testing**: Regular security assessments

## Conclusion

The Claude Code deployment system demonstrates sophisticated cross-MCP server integration patterns that enable complex, automated workflows. The key architectural patterns include:

1. **Centralized Orchestration** via the MCP Manager hub
2. **Event-Driven Communication** for loose coupling
3. **Circuit Breaker Protection** for reliability
4. **Graceful Degradation** with fallback strategies
5. **Performance Optimization** through caching and batching
6. **Comprehensive Error Handling** with recovery mechanisms

These patterns enable the system to execute complex deployment workflows automatically while maintaining reliability, performance, and security. The integration between multiple MCP servers creates a powerful automation platform that can handle enterprise-scale infrastructure management tasks.

The workflow examples demonstrate practical applications of these patterns, showing how multiple MCP servers can work together to provide sophisticated automation capabilities that would be difficult to achieve with individual tools or servers working in isolation.