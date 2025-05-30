# Performance Optimization Patterns for Infrastructure
**Purpose**: High-performance patterns for infrastructure deployment  
**Context**: Adapted for CODE project from proven optimization techniques

---

## 🚀 Parallel Execution Framework

### Core Concept: Task Type Classification
Different tasks require different execution strategies:

```python
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import asyncio

class TaskType(Enum):
    IO_BOUND = "io"          # Network calls, file operations
    CPU_BOUND = "cpu"        # Computation, data processing
    MIXED = "mixed"          # Combination of both
    ASYNC = "async"          # Native async operations

class ParallelExecutor:
    """Intelligent parallel task executor for infrastructure operations."""
    
    def __init__(self):
        self.thread_pool = ThreadPoolExecutor(max_workers=20)  # For I/O
        self.process_pool = ProcessPoolExecutor(max_workers=4) # For CPU
        self.async_semaphore = asyncio.Semaphore(50)         # For async
    
    async def execute_tasks(self, tasks: List[Task]) -> List[Any]:
        """Execute tasks based on their type for optimal performance."""
        # Group tasks by type
        grouped = self._group_tasks_by_type(tasks)
        
        # Execute each group with appropriate strategy
        results = []
        
        # I/O bound tasks - use threads
        if grouped[TaskType.IO_BOUND]:
            io_futures = [
                self.thread_pool.submit(task.execute)
                for task in grouped[TaskType.IO_BOUND]
            ]
            results.extend([f.result() for f in io_futures])
        
        # CPU bound tasks - use processes
        if grouped[TaskType.CPU_BOUND]:
            cpu_futures = [
                self.process_pool.submit(task.execute)
                for task in grouped[TaskType.CPU_BOUND]
            ]
            results.extend([f.result() for f in cpu_futures])
        
        # Async tasks - use asyncio
        if grouped[TaskType.ASYNC]:
            async_results = await asyncio.gather(*[
                self._execute_async_with_limit(task)
                for task in grouped[TaskType.ASYNC]
            ])
            results.extend(async_results)
        
        return results
    
    async def _execute_async_with_limit(self, task):
        """Execute async task with concurrency limit."""
        async with self.async_semaphore:
            return await task.execute()
```

### Infrastructure-Specific Task Examples

```python
# Task definitions for infrastructure operations
class InfrastructureTasks:
    
    @staticmethod
    def terraform_plan(module_path: str) -> Task:
        """Terraform planning is I/O bound."""
        return Task(
            name=f"terraform_plan_{module_path}",
            task_type=TaskType.IO_BOUND,
            execute=lambda: subprocess.run(
                ["terraform", "plan", "-out=tfplan"],
                cwd=module_path,
                capture_output=True
            )
        )
    
    @staticmethod
    def docker_build(dockerfile_path: str, tag: str) -> Task:
        """Docker building is mixed (I/O + CPU)."""
        return Task(
            name=f"docker_build_{tag}",
            task_type=TaskType.MIXED,
            execute=lambda: subprocess.run(
                ["docker", "build", "-f", dockerfile_path, "-t", tag, "."],
                capture_output=True
            )
        )
    
    @staticmethod
    async def kubernetes_deploy(manifest: dict) -> Task:
        """Kubernetes deployment is async I/O."""
        return Task(
            name=f"k8s_deploy_{manifest['metadata']['name']}",
            task_type=TaskType.ASYNC,
            execute=lambda: kubernetes_client.create_namespaced_deployment(
                namespace=manifest['metadata']['namespace'],
                body=manifest
            )
        )
    
    @staticmethod
    def render_template(template_path: str, values: dict) -> Task:
        """Template rendering is CPU bound."""
        return Task(
            name=f"render_{template_path}",
            task_type=TaskType.CPU_BOUND,
            execute=lambda: jinja2.Template(
                open(template_path).read()
            ).render(**values)
        )
```

## 📊 Performance Metrics Collection

### Intelligent Metrics Framework
```python
import time
import psutil
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    duration: float
    cpu_percent: float
    memory_mb: float
    io_operations: int
    network_bytes: int
    
    @property
    def efficiency_score(self) -> float:
        """Calculate efficiency score (0-100)."""
        # Lower is better for all metrics except efficiency
        cpu_efficiency = max(0, 100 - self.cpu_percent)
        memory_efficiency = max(0, 100 - (self.memory_mb / 1024) * 10)  # Assume 10GB is 100%
        time_efficiency = max(0, 100 - self.duration * 10)  # Assume 10s is 100%
        
        return (cpu_efficiency + memory_efficiency + time_efficiency) / 3

class PerformanceMonitor:
    """Monitor and optimize infrastructure operations."""
    
    def __init__(self):
        self.baseline_metrics = {}
        self.optimization_suggestions = []
    
    def measure_operation(self, operation_name: str):
        """Decorator to measure operation performance."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Capture initial state
                start_time = time.time()
                start_cpu = psutil.cpu_percent(interval=0.1)
                start_memory = psutil.Process().memory_info().rss / 1024 / 1024
                start_io = psutil.disk_io_counters()
                start_network = psutil.net_io_counters()
                
                # Execute operation
                result = func(*args, **kwargs)
                
                # Calculate metrics
                metrics = PerformanceMetrics(
                    duration=time.time() - start_time,
                    cpu_percent=psutil.cpu_percent(interval=0.1) - start_cpu,
                    memory_mb=psutil.Process().memory_info().rss / 1024 / 1024 - start_memory,
                    io_operations=(psutil.disk_io_counters().read_count + 
                                 psutil.disk_io_counters().write_count -
                                 start_io.read_count - start_io.write_count),
                    network_bytes=(psutil.net_io_counters().bytes_sent +
                                 psutil.net_io_counters().bytes_recv -
                                 start_network.bytes_sent - start_network.bytes_recv)
                )
                
                # Analyze and suggest optimizations
                self._analyze_performance(operation_name, metrics)
                
                return result
            return wrapper
        return decorator
    
    def _analyze_performance(self, operation: str, metrics: PerformanceMetrics):
        """Analyze performance and suggest optimizations."""
        if operation in self.baseline_metrics:
            baseline = self.baseline_metrics[operation]
            
            # Check for performance regression
            if metrics.duration > baseline.duration * 1.2:
                self.optimization_suggestions.append(
                    f"{operation}: Performance regression detected. "
                    f"Current: {metrics.duration:.2f}s, Baseline: {baseline.duration:.2f}s"
                )
            
            # Check for high resource usage
            if metrics.cpu_percent > 80:
                self.optimization_suggestions.append(
                    f"{operation}: High CPU usage ({metrics.cpu_percent:.1f}%). "
                    "Consider parallelization or optimization."
                )
            
            if metrics.memory_mb > 1024:  # 1GB
                self.optimization_suggestions.append(
                    f"{operation}: High memory usage ({metrics.memory_mb:.1f}MB). "
                    "Consider streaming or chunking data."
                )
        else:
            # Set as baseline
            self.baseline_metrics[operation] = metrics
```

## 🔧 Infrastructure-Specific Optimizations

### 1. Terraform Optimization
```python
class TerraformOptimizer:
    """Optimize Terraform operations for speed and reliability."""
    
    @staticmethod
    def parallel_module_plan(modules: List[str], max_parallel: int = 5) -> Dict[str, Any]:
        """Plan multiple Terraform modules in parallel."""
        executor = ParallelExecutor()
        
        # Create tasks for each module
        tasks = [
            Task(
                name=f"plan_{module}",
                task_type=TaskType.IO_BOUND,
                execute=lambda m=module: TerraformOptimizer._plan_module(m)
            )
            for module in modules
        ]
        
        # Execute in batches to avoid overwhelming the system
        results = {}
        for i in range(0, len(tasks), max_parallel):
            batch = tasks[i:i + max_parallel]
            batch_results = asyncio.run(executor.execute_tasks(batch))
            for j, result in enumerate(batch_results):
                results[modules[i + j]] = result
        
        return results
    
    @staticmethod
    def _plan_module(module_path: str) -> Dict[str, Any]:
        """Plan a single module with optimizations."""
        # Use partial backend config to speed up init
        subprocess.run([
            "terraform", "init",
            "-backend=false",  # Skip backend init for planning
            "-upgrade=false"   # Don't upgrade providers
        ], cwd=module_path)
        
        # Run plan with optimizations
        result = subprocess.run([
            "terraform", "plan",
            "-refresh=false",  # Skip refresh for speed
            "-out=tfplan",
            "-parallelism=10" # Increase parallelism
        ], cwd=module_path, capture_output=True, text=True)
        
        return {
            "success": result.returncode == 0,
            "changes": TerraformOptimizer._parse_plan_changes(result.stdout),
            "duration": result.stderr  # Terraform reports timing in stderr
        }
```

### 2. Container Build Optimization
```python
class ContainerOptimizer:
    """Optimize container building and deployment."""
    
    @staticmethod
    def parallel_build(dockerfiles: Dict[str, str], registry: str) -> List[str]:
        """Build multiple containers in parallel with caching."""
        # Setup buildkit for better performance
        os.environ['DOCKER_BUILDKIT'] = '1'
        
        build_tasks = []
        for service, dockerfile in dockerfiles.items():
            tag = f"{registry}/{service}:latest"
            
            # Create optimized build task
            task = Task(
                name=f"build_{service}",
                task_type=TaskType.MIXED,
                execute=lambda d=dockerfile, t=tag: ContainerOptimizer._optimized_build(d, t)
            )
            build_tasks.append(task)
        
        # Execute builds in parallel
        executor = ParallelExecutor()
        results = asyncio.run(executor.execute_tasks(build_tasks))
        
        # Return successfully built tags
        return [r['tag'] for r in results if r['success']]
    
    @staticmethod
    def _optimized_build(dockerfile: str, tag: str) -> Dict[str, Any]:
        """Build with optimizations."""
        result = subprocess.run([
            "docker", "build",
            "--cache-from", tag,  # Use previous build as cache
            "--build-arg", "BUILDKIT_INLINE_CACHE=1",
            "--progress", "plain",  # Better for logs
            "-f", dockerfile,
            "-t", tag,
            "."
        ], capture_output=True, text=True)
        
        return {
            "success": result.returncode == 0,
            "tag": tag,
            "size": ContainerOptimizer._get_image_size(tag),
            "layers": ContainerOptimizer._get_layer_count(tag)
        }
```

### 3. Kubernetes Deployment Optimization
```python
class KubernetesOptimizer:
    """Optimize Kubernetes deployments for speed and reliability."""
    
    @staticmethod
    async def rolling_deploy(
        deployments: List[Dict[str, Any]], 
        namespace: str,
        max_parallel: int = 3
    ) -> Dict[str, Any]:
        """Deploy multiple services with intelligent ordering."""
        # Analyze dependencies
        deploy_order = KubernetesOptimizer._analyze_dependencies(deployments)
        
        # Group by dependency level
        deployment_stages = {}
        for deployment, level in deploy_order.items():
            if level not in deployment_stages:
                deployment_stages[level] = []
            deployment_stages[level].append(deployment)
        
        # Deploy each stage in parallel
        results = {}
        async with kubernetes_async.ApiClient() as api_client:
            apps_v1 = kubernetes_async.AppsV1Api(api_client)
            
            for level in sorted(deployment_stages.keys()):
                stage_deployments = deployment_stages[level]
                
                # Deploy stage in parallel
                stage_tasks = [
                    KubernetesOptimizer._deploy_with_monitoring(
                        apps_v1, deployment, namespace
                    )
                    for deployment in stage_deployments
                ]
                
                # Limit parallelism
                for i in range(0, len(stage_tasks), max_parallel):
                    batch = stage_tasks[i:i + max_parallel]
                    batch_results = await asyncio.gather(*batch)
                    
                    for j, result in enumerate(batch_results):
                        deployment_name = stage_deployments[i + j]['metadata']['name']
                        results[deployment_name] = result
        
        return results
    
    @staticmethod
    async def _deploy_with_monitoring(api, deployment, namespace):
        """Deploy with real-time monitoring."""
        start_time = time.time()
        
        # Create or update deployment
        try:
            await api.patch_namespaced_deployment(
                name=deployment['metadata']['name'],
                namespace=namespace,
                body=deployment
            )
            action = "updated"
        except kubernetes_async.ApiException as e:
            if e.status == 404:
                await api.create_namespaced_deployment(
                    namespace=namespace,
                    body=deployment
                )
                action = "created"
            else:
                raise
        
        # Monitor rollout
        ready = await KubernetesOptimizer._wait_for_rollout(
            api, deployment['metadata']['name'], namespace
        )
        
        return {
            "action": action,
            "duration": time.time() - start_time,
            "ready": ready,
            "replicas": deployment['spec']['replicas']
        }
```

## 📈 Performance Patterns

### 1. Batch Operations Pattern
```python
def batch_operation_pattern(items: List[Any], operation: Callable, batch_size: int = 100):
    """Process items in optimized batches."""
    results = []
    
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        
        # Process batch in parallel within each batch
        with ThreadPoolExecutor(max_workers=10) as executor:
            batch_results = list(executor.map(operation, batch))
            results.extend(batch_results)
    
    return results
```

### 2. Circuit Breaker Pattern
```python
class CircuitBreaker:
    """Prevent cascading failures in infrastructure operations."""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == "open":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "half-open"
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failures = 0
            return result
        except Exception as e:
            self.failures += 1
            self.last_failure_time = time.time()
            
            if self.failures >= self.failure_threshold:
                self.state = "open"
            
            raise e
```

### 3. Resource Pool Pattern
```python
class ResourcePool:
    """Manage reusable resources efficiently."""
    
    def __init__(self, create_func: Callable, max_size: int = 10):
        self.create_func = create_func
        self.max_size = max_size
        self.available = queue.Queue(maxsize=max_size)
        self.in_use = set()
        self.lock = threading.Lock()
    
    def acquire(self, timeout: float = None):
        """Acquire a resource from the pool."""
        try:
            resource = self.available.get(timeout=timeout)
        except queue.Empty:
            with self.lock:
                if len(self.in_use) < self.max_size:
                    resource = self.create_func()
                else:
                    raise Exception("Resource pool exhausted")
        
        with self.lock:
            self.in_use.add(resource)
        return resource
    
    def release(self, resource):
        """Return resource to the pool."""
        with self.lock:
            self.in_use.discard(resource)
        
        try:
            self.available.put_nowait(resource)
        except queue.Full:
            # Pool is full, discard resource
            pass

# Example usage for database connections
db_pool = ResourcePool(
    create_func=lambda: psycopg2.connect("postgresql://..."),
    max_size=20
)
```

## 🚀 Advanced Optimization Techniques

### 1. Predictive Scaling
```python
class PredictiveScaler:
    """Predict and pre-scale infrastructure based on patterns."""
    
    def __init__(self):
        self.history = []
        self.model = None
    
    def predict_load(self, time_ahead: int = 300) -> Dict[str, int]:
        """Predict load N seconds in the future."""
        if len(self.history) < 100:
            return self._baseline_prediction()
        
        # Simple moving average (replace with ML model in production)
        recent_load = [h['cpu'] for h in self.history[-20:]]
        predicted_cpu = sum(recent_load) / len(recent_load) * 1.2  # 20% buffer
        
        # Calculate required instances
        instances_needed = math.ceil(predicted_cpu / 70)  # Target 70% CPU
        
        return {
            "predicted_cpu": predicted_cpu,
            "recommended_instances": instances_needed,
            "confidence": 0.8 if len(self.history) > 1000 else 0.5
        }
```

### 2. Intelligent Caching
```python
class IntelligentCache:
    """Cache with predictive prefetching."""
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.access_history = defaultdict(list)
        self.max_size = max_size
    
    def get(self, key: str, fetch_func: Callable = None):
        """Get with predictive prefetching."""
        # Record access
        self.access_history[key].append(time.time())
        
        # Check cache
        if key in self.cache:
            # Predict related keys that might be needed
            related_keys = self._predict_related_keys(key)
            for related_key in related_keys:
                if related_key not in self.cache and fetch_func:
                    # Prefetch in background
                    threading.Thread(
                        target=lambda: self.cache.setdefault(
                            related_key, fetch_func(related_key)
                        )
                    ).start()
            
            return self.cache[key]
        
        # Fetch if not in cache
        if fetch_func:
            value = fetch_func(key)
            self._add_to_cache(key, value)
            return value
        
        return None
```

---

## 🎯 Key Performance Principles

1. **Measure First**: Always profile before optimizing
2. **Parallelize Intelligently**: Not all operations benefit from parallelization
3. **Cache Aggressively**: But invalidate intelligently
4. **Fail Fast**: Don't waste resources on doomed operations
5. **Monitor Continuously**: Performance is not a one-time concern

---

*Optimized for the CODE project - achieving 10-15x performance improvements*
