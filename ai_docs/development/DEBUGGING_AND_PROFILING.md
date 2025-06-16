# Debugging and Performance Profiling Guide

**Version**: 2.0.0  
**Date**: December 08, 2025  
**For**: CODE Project Development Team

## Overview

This guide provides comprehensive debugging and performance profiling techniques for the Claude-Optimized Deployment Engine (CODE) project. It covers debugging strategies for AI systems, MCP servers, async code, and performance optimization techniques.

## Debugging Strategies

### 1. Logging and Observability

#### Structured Logging Setup
```python
# Example: Enhanced logging in Circle of Experts
import structlog
from src.core.logging_config import get_logger

logger = get_logger(__name__)

async def enhanced_expert_consultation(self, query: str, **kwargs):
    consultation_id = generate_consultation_id()
    
    logger.info(
        "Starting expert consultation",
        consultation_id=consultation_id,
        query_length=len(query),
        expert_count=kwargs.get('expert_count', 1),
        user_id=kwargs.get('user_context', {}).get('user_id'),
        performance_tracking=True
    )
    
    try:
        start_time = time.time()
        
        # Your consultation logic here
        result = await self._perform_consultation(query, **kwargs)
        
        duration = time.time() - start_time
        
        logger.info(
            "Expert consultation completed",
            consultation_id=consultation_id,
            duration_seconds=duration,
            consensus_achieved=result.get('consensus', False),
            expert_count_successful=len(result.get('successful_experts', [])),
            total_cost=result.get('cost_breakdown', {}).get('total', 0),
            memory_usage_mb=get_memory_usage()
        )
        
        return result
        
    except Exception as e:
        logger.error(
            "Expert consultation failed",
            consultation_id=consultation_id,
            error_type=type(e).__name__,
            error_message=str(e),
            query_hash=hashlib.md5(query.encode()).hexdigest(),
            stack_trace=traceback.format_exc() if logger.level <= logging.DEBUG else None
        )
        raise
```

#### Debug Mode Configuration
```python
# Environment variables for debugging
export DEBUG=true
export LOG_LEVEL=DEBUG
export PYTHONPATH=$PWD/src
export PERFORMANCE_PROFILING=true
export MEMORY_PROFILING=true
export ASYNC_DEBUG=true

# Enhanced debug configuration
DEBUG_CONFIG = {
    "log_level": "DEBUG",
    "enable_sql_logging": True,
    "enable_http_logging": True,
    "enable_ai_request_logging": True,
    "enable_mcp_protocol_logging": True,
    "log_performance_metrics": True,
    "log_memory_usage": True,
    "capture_stack_traces": True,
    "enable_circuit_breaker_logging": True
}
```

### 2. Interactive Debugging

#### Using Python Debugger (PDB)
```python
# Insert breakpoint in code
import pdb; pdb.set_trace()

# Or use the newer breakpoint() function (Python 3.7+)
breakpoint()

# For async code debugging
import asyncio
import pdb

class AsyncPDB(pdb.Pdb):
    def do_step(self, arg):
        # Handle async stepping
        super().do_step(arg)

# Usage in async functions
async def debug_expert_consultation():
    AsyncPDB().set_trace()
    result = await manager.quick_consult("Debug query")
    return result
```

#### VS Code Debugging Configuration
```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug CODE Application",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/src/__main__.py",
            "console": "integratedTerminal",
            "env": {
                "DEBUG": "true",
                "LOG_LEVEL": "DEBUG",
                "PYTHONPATH": "${workspaceFolder}/src"
            },
            "args": ["--debug"]
        },
        {
            "name": "Debug Circle of Experts",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": [
                "tests/integration/test_circle_of_experts.py",
                "-v",
                "-s"
            ],
            "console": "integratedTerminal",
            "env": {
                "DEBUG": "true",
                "LOG_LEVEL": "DEBUG"
            }
        },
        {
            "name": "Debug MCP Integration",
            "type": "python",
            "request": "launch",
            "module": "src.mcp.client",
            "args": ["--server", "docker", "--tool", "ps"],
            "console": "integratedTerminal"
        }
    ]
}
```

### 3. AI System Debugging

#### Expert Response Analysis
```python
# Debug helper for analyzing expert responses
class ExpertDebugger:
    def __init__(self):
        self.response_history = []
    
    async def debug_expert_consultation(self, manager, query: str, **kwargs):
        """Debug expert consultation with detailed analysis"""
        
        # Enable detailed logging
        kwargs['debug_mode'] = True
        kwargs['capture_intermediate_results'] = True
        
        logger.info(f"Debugging expert consultation: {query[:100]}...")
        
        result = await manager.quick_consult(query, **kwargs)
        
        # Analyze results
        self._analyze_expert_responses(result)
        self._analyze_consensus_mechanism(result)
        self._analyze_cost_efficiency(result)
        self._analyze_performance_metrics(result)
        
        return result
    
    def _analyze_expert_responses(self, result):
        """Analyze individual expert responses"""
        expert_responses = result.get('expert_responses', [])
        
        for response in expert_responses:
            logger.debug(
                "Expert response analysis",
                expert=response['expert'],
                confidence=response['confidence'],
                response_length=len(response['response']),
                cost=response.get('cost', 0),
                processing_time=response.get('processing_time', 0),
                tokens_used=response.get('tokens_used', 0)
            )
    
    def _analyze_consensus_mechanism(self, result):
        """Analyze consensus building process"""
        consensus_score = result.get('consensus_score', 0)
        consensus_threshold = result.get('consensus_threshold', 0.8)
        
        logger.debug(
            "Consensus analysis",
            consensus_achieved=result.get('consensus', False),
            consensus_score=consensus_score,
            consensus_threshold=consensus_threshold,
            agreement_points=result.get('agreement_points', []),
            disagreement_points=result.get('disagreement_points', [])
        )
    
    def _analyze_cost_efficiency(self, result):
        """Analyze cost efficiency of consultation"""
        cost_breakdown = result.get('cost_breakdown', {})
        
        logger.debug(
            "Cost efficiency analysis",
            total_cost=cost_breakdown.get('total', 0),
            cost_per_expert=cost_breakdown.get('by_expert', {}),
            tokens_per_dollar=self._calculate_tokens_per_dollar(result),
            cost_vs_quality_score=self._calculate_cost_quality_ratio(result)
        )
```

#### MCP Server Debugging
```python
# Debug MCP server interactions
class MCPDebugger:
    def __init__(self):
        self.request_history = []
        self.response_times = []
    
    async def debug_mcp_execution(self, client, server: str, tool: str, arguments: dict):
        """Debug MCP tool execution with detailed logging"""
        
        start_time = time.time()
        
        logger.info(
            "Debugging MCP execution",
            server=server,
            tool=tool,
            arguments=arguments,
            timestamp=start_time
        )
        
        try:
            # Enable protocol-level debugging
            client.enable_debug_mode()
            
            result = await client.execute_tool(server, tool, arguments)
            
            execution_time = time.time() - start_time
            
            logger.info(
                "MCP execution completed",
                server=server,
                tool=tool,
                execution_time=execution_time,
                result_size=len(str(result)),
                success=True
            )
            
            # Analyze result
            self._analyze_mcp_result(server, tool, result, execution_time)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            logger.error(
                "MCP execution failed",
                server=server,
                tool=tool,
                execution_time=execution_time,
                error_type=type(e).__name__,
                error_message=str(e),
                stack_trace=traceback.format_exc()
            )
            
            # Analyze failure
            self._analyze_mcp_failure(server, tool, e, execution_time)
            
            raise
    
    def _analyze_mcp_result(self, server: str, tool: str, result: any, execution_time: float):
        """Analyze MCP execution result"""
        logger.debug(
            "MCP result analysis",
            server=server,
            tool=tool,
            result_type=type(result).__name__,
            result_keys=list(result.keys()) if isinstance(result, dict) else None,
            execution_time=execution_time,
            performance_category=self._categorize_performance(execution_time)
        )
```

### 4. Async Code Debugging

#### Async Task Monitoring
```python
import asyncio
import weakref
from typing import Dict, Set

class AsyncTaskMonitor:
    def __init__(self):
        self.active_tasks: Set[asyncio.Task] = set()
        self.task_info: Dict[int, dict] = {}
    
    def monitor_task(self, task: asyncio.Task, name: str = None):
        """Monitor an async task"""
        task_id = id(task)
        
        self.active_tasks.add(task)
        self.task_info[task_id] = {
            'name': name or f'Task-{task_id}',
            'created_at': time.time(),
            'stack_trace': ''.join(traceback.format_stack()),
            'status': 'running'
        }
        
        # Add callback to clean up when task completes
        task.add_done_callback(self._task_completed)
        
        logger.debug(
            "Task monitoring started",
            task_id=task_id,
            task_name=self.task_info[task_id]['name'],
            total_active_tasks=len(self.active_tasks)
        )
    
    def _task_completed(self, task: asyncio.Task):
        """Handle task completion"""
        task_id = id(task)
        
        if task_id in self.task_info:
            duration = time.time() - self.task_info[task_id]['created_at']
            
            logger.debug(
                "Task completed",
                task_id=task_id,
                task_name=self.task_info[task_id]['name'],
                duration=duration,
                exception=str(task.exception()) if task.exception() else None
            )
            
            del self.task_info[task_id]
        
        self.active_tasks.discard(task)
    
    def get_active_tasks_summary(self):
        """Get summary of active tasks"""
        current_time = time.time()
        
        summary = {
            'total_active': len(self.active_tasks),
            'tasks': []
        }
        
        for task_id, info in self.task_info.items():
            duration = current_time - info['created_at']
            summary['tasks'].append({
                'id': task_id,
                'name': info['name'],
                'duration': duration,
                'status': info['status']
            })
        
        return summary

# Global task monitor
task_monitor = AsyncTaskMonitor()

# Decorator for monitoring async functions
def monitor_async(name: str = None):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            task = asyncio.current_task()
            if task:
                task_monitor.monitor_task(task, name or func.__name__)
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Usage example
@monitor_async("expert_consultation")
async def enhanced_expert_consultation(query: str):
    result = await manager.quick_consult(query)
    return result
```

## Performance Profiling

### 1. CPU Profiling

#### Using cProfile
```python
import cProfile
import pstats
import io
from contextlib import contextmanager

@contextmanager
def profile_performance(sort_by='cumulative', limit=20):
    """Context manager for profiling code performance"""
    profiler = cProfile.Profile()
    profiler.enable()
    
    try:
        yield profiler
    finally:
        profiler.disable()
        
        # Create string buffer for results
        string_buffer = io.StringIO()
        stats = pstats.Stats(profiler, stream=string_buffer)
        stats.sort_stats(sort_by)
        stats.print_stats(limit)
        
        # Log profiling results
        logger.info(
            "Performance profiling results",
            profile_data=string_buffer.getvalue()
        )

# Usage example
async def profile_expert_consultation():
    with profile_performance(sort_by='cumulative', limit=30) as profiler:
        manager = EnhancedExpertManager()
        result = await manager.quick_consult("Performance test query")
        return result
```

#### Advanced CPU Profiling
```python
import line_profiler
import memory_profiler

class PerformanceProfiler:
    def __init__(self):
        self.profiling_enabled = os.getenv('PERFORMANCE_PROFILING', 'false').lower() == 'true'
    
    def profile_cpu(self, func):
        """Decorator for CPU profiling"""
        if not self.profiling_enabled:
            return func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            profiler = line_profiler.LineProfiler()
            profiler.add_function(func)
            profiler.enable_by_count()
            
            try:
                result = func(*args, **kwargs)
                profiler.print_stats()
                return result
            finally:
                profiler.disable_by_count()
        
        return wrapper
    
    def profile_memory(self, func):
        """Decorator for memory profiling"""
        if not self.profiling_enabled:
            return func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Memory profiling logic
            import tracemalloc
            
            tracemalloc.start()
            
            try:
                result = func(*args, **kwargs)
                
                # Get memory statistics
                current, peak = tracemalloc.get_traced_memory()
                
                logger.info(
                    "Memory usage profile",
                    function=func.__name__,
                    current_memory_mb=current / 1024 / 1024,
                    peak_memory_mb=peak / 1024 / 1024
                )
                
                return result
            finally:
                tracemalloc.stop()
        
        return wrapper

# Global profiler instance
profiler = PerformanceProfiler()

# Usage
@profiler.profile_cpu
@profiler.profile_memory
async def profile_circle_of_experts(query: str):
    manager = EnhancedExpertManager()
    return await manager.quick_consult(query)
```

### 2. Memory Profiling

#### Memory Usage Monitoring
```python
import psutil
import gc
import tracemalloc

class MemoryProfiler:
    def __init__(self):
        self.snapshots = []
        self.baseline_memory = None
    
    def start_profiling(self):
        """Start memory profiling"""
        tracemalloc.start()
        gc.collect()  # Clean up before starting
        
        process = psutil.Process()
        self.baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        logger.info(
            "Memory profiling started",
            baseline_memory_mb=self.baseline_memory,
            gc_counts=gc.get_count()
        )
    
    def take_snapshot(self, label: str):
        """Take a memory snapshot"""
        if not tracemalloc.is_tracing():
            return
        
        snapshot = tracemalloc.take_snapshot()
        process = psutil.Process()
        current_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        self.snapshots.append({
            'label': label,
            'snapshot': snapshot,
            'memory_mb': current_memory,
            'memory_increase_mb': current_memory - self.baseline_memory,
            'timestamp': time.time()
        })
        
        logger.info(
            "Memory snapshot taken",
            label=label,
            current_memory_mb=current_memory,
            memory_increase_mb=current_memory - self.baseline_memory,
            gc_counts=gc.get_count()
        )
    
    def analyze_memory_growth(self):
        """Analyze memory growth between snapshots"""
        if len(self.snapshots) < 2:
            return
        
        for i in range(1, len(self.snapshots)):
            prev_snapshot = self.snapshots[i-1]
            curr_snapshot = self.snapshots[i]
            
            # Compare snapshots
            top_stats = curr_snapshot['snapshot'].compare_to(
                prev_snapshot['snapshot'], 'lineno'
            )
            
            logger.info(
                "Memory growth analysis",
                from_label=prev_snapshot['label'],
                to_label=curr_snapshot['label'],
                memory_growth_mb=curr_snapshot['memory_mb'] - prev_snapshot['memory_mb'],
                top_allocations=[
                    {
                        'file': stat.traceback.format()[-1],
                        'size_diff_mb': stat.size_diff / 1024 / 1024,
                        'count_diff': stat.count_diff
                    }
                    for stat in top_stats[:5]
                ]
            )
    
    def stop_profiling(self):
        """Stop memory profiling and generate report"""
        if tracemalloc.is_tracing():
            self.analyze_memory_growth()
            tracemalloc.stop()
        
        process = psutil.Process()
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        logger.info(
            "Memory profiling completed",
            baseline_memory_mb=self.baseline_memory,
            final_memory_mb=final_memory,
            total_increase_mb=final_memory - self.baseline_memory,
            snapshots_taken=len(self.snapshots)
        )

# Usage example
async def profile_memory_intensive_operation():
    profiler = MemoryProfiler()
    profiler.start_profiling()
    
    try:
        # Initialize system
        profiler.take_snapshot("initialization")
        manager = EnhancedExpertManager()
        
        # Load experts
        profiler.take_snapshot("experts_loaded")
        
        # Perform consultations
        for i in range(5):
            result = await manager.quick_consult(f"Query {i}")
            profiler.take_snapshot(f"consultation_{i}")
        
        return "Completed"
        
    finally:
        profiler.stop_profiling()
```

### 3. Database Performance Profiling

#### SQL Query Analysis
```python
import sqlalchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

class DatabaseProfiler:
    def __init__(self):
        self.query_stats = []
        self.slow_query_threshold = 0.1  # 100ms
    
    def enable_sql_logging(self):
        """Enable SQL query profiling"""
        
        @event.listens_for(Engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()
            
            logger.debug(
                "SQL query starting",
                query=statement[:200] + "..." if len(statement) > 200 else statement,
                parameters=parameters if len(str(parameters)) < 500 else "Large parameters"
            )
        
        @event.listens_for(Engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            execution_time = time.time() - context._query_start_time
            
            query_info = {
                'statement': statement,
                'execution_time': execution_time,
                'row_count': cursor.rowcount,
                'timestamp': time.time()
            }
            
            self.query_stats.append(query_info)
            
            log_level = "warning" if execution_time > self.slow_query_threshold else "debug"
            
            logger.log(
                getattr(logging, log_level.upper()),
                "SQL query completed",
                execution_time=execution_time,
                row_count=cursor.rowcount,
                query=statement[:100] + "..." if len(statement) > 100 else statement,
                slow_query=execution_time > self.slow_query_threshold
            )
    
    def get_performance_summary(self):
        """Get database performance summary"""
        if not self.query_stats:
            return {}
        
        execution_times = [stat['execution_time'] for stat in self.query_stats]
        slow_queries = [stat for stat in self.query_stats if stat['execution_time'] > self.slow_query_threshold]
        
        return {
            'total_queries': len(self.query_stats),
            'avg_execution_time': sum(execution_times) / len(execution_times),
            'max_execution_time': max(execution_times),
            'min_execution_time': min(execution_times),
            'slow_queries_count': len(slow_queries),
            'slow_queries_percentage': len(slow_queries) / len(self.query_stats) * 100,
            'top_slow_queries': sorted(slow_queries, key=lambda x: x['execution_time'], reverse=True)[:5]
        }

# Global database profiler
db_profiler = DatabaseProfiler()

# Enable in development
if os.getenv('DEBUG', 'false').lower() == 'true':
    db_profiler.enable_sql_logging()
```

### 4. API Performance Profiling

#### Request/Response Profiling
```python
from fastapi import Request, Response
import time

class APIProfiler:
    def __init__(self):
        self.request_stats = []
    
    async def profile_request(self, request: Request, call_next):
        """Middleware for profiling API requests"""
        start_time = time.time()
        
        # Get request info
        request_info = {
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'query_params': dict(request.query_params),
            'headers': dict(request.headers),
            'client_ip': request.client.host if request.client else None,
            'start_time': start_time
        }
        
        logger.info(
            "API request started",
            method=request_info['method'],
            path=request_info['path'],
            client_ip=request_info['client_ip']
        )
        
        try:
            response: Response = await call_next(request)
            
            duration = time.time() - start_time
            
            # Log response info
            logger.info(
                "API request completed",
                method=request_info['method'],
                path=request_info['path'],
                status_code=response.status_code,
                duration=duration,
                client_ip=request_info['client_ip']
            )
            
            # Store stats
            self.request_stats.append({
                **request_info,
                'status_code': response.status_code,
                'duration': duration,
                'response_headers': dict(response.headers) if hasattr(response, 'headers') else {}
            })
            
            # Add performance headers
            response.headers["X-Process-Time"] = str(duration)
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            logger.error(
                "API request failed",
                method=request_info['method'],
                path=request_info['path'],
                duration=duration,
                error_type=type(e).__name__,
                error_message=str(e),
                client_ip=request_info['client_ip']
            )
            
            raise
    
    def get_api_performance_summary(self, time_window_hours: int = 24):
        """Get API performance summary"""
        cutoff_time = time.time() - (time_window_hours * 3600)
        recent_requests = [req for req in self.request_stats if req['start_time'] > cutoff_time]
        
        if not recent_requests:
            return {}
        
        durations = [req['duration'] for req in recent_requests]
        status_codes = [req['status_code'] for req in recent_requests]
        
        return {
            'total_requests': len(recent_requests),
            'avg_response_time': sum(durations) / len(durations),
            'max_response_time': max(durations),
            'min_response_time': min(durations),
            'p95_response_time': sorted(durations)[int(len(durations) * 0.95)],
            'p99_response_time': sorted(durations)[int(len(durations) * 0.99)],
            'status_code_distribution': {
                code: status_codes.count(code) for code in set(status_codes)
            },
            'slowest_endpoints': self._get_slowest_endpoints(recent_requests)
        }
    
    def _get_slowest_endpoints(self, requests, limit=5):
        """Get slowest API endpoints"""
        endpoint_stats = {}
        
        for req in requests:
            path = req['path']
            if path not in endpoint_stats:
                endpoint_stats[path] = []
            endpoint_stats[path].append(req['duration'])
        
        # Calculate average duration per endpoint
        endpoint_averages = {
            path: sum(durations) / len(durations)
            for path, durations in endpoint_stats.items()
        }
        
        # Sort by average duration
        slowest = sorted(endpoint_averages.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {
                'path': path,
                'avg_duration': avg_duration,
                'request_count': len(endpoint_stats[path]),
                'max_duration': max(endpoint_stats[path])
            }
            for path, avg_duration in slowest[:limit]
        ]
```

## Performance Optimization Techniques

### 1. Async Optimization

#### Connection Pooling
```python
import aiohttp
import asyncio
from typing import Optional

class OptimizedHTTPClient:
    def __init__(self, max_connections: int = 100, max_connections_per_host: int = 30):
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_connections_per_host,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        self.timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=self.timeout,
                headers={
                    'User-Agent': 'CODE/2.0.0',
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate'
                }
            )
        return self._session
    
    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
        await self.connector.close()

# Global HTTP client
http_client = OptimizedHTTPClient()

# Use in expert implementations
class OptimizedOpenAIExpert:
    async def query(self, prompt: str, **kwargs):
        session = await http_client.get_session()
        
        async with session.post(
            "https://api.openai.com/v1/chat/completions",
            json=self._build_request(prompt, **kwargs),
            headers=self._get_headers()
        ) as response:
            result = await response.json()
            return self._process_response(result)
```

#### Task Batching and Concurrency Control
```python
import asyncio
from asyncio import Semaphore
from typing import List, Callable, Any

class ConcurrencyManager:
    def __init__(self, max_concurrent: int = 10):
        self.semaphore = Semaphore(max_concurrent)
        self.active_tasks = set()
    
    async def execute_with_limit(self, coro):
        """Execute coroutine with concurrency limit"""
        async with self.semaphore:
            return await coro
    
    async def batch_execute(self, 
                           tasks: List[Callable], 
                           batch_size: int = 5,
                           delay_between_batches: float = 0.1) -> List[Any]:
        """Execute tasks in batches with concurrency control"""
        results = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            
            # Execute batch with concurrency control
            batch_coroutines = [
                self.execute_with_limit(task()) 
                for task in batch
            ]
            
            batch_results = await asyncio.gather(*batch_coroutines, return_exceptions=True)
            results.extend(batch_results)
            
            # Delay between batches to prevent overwhelming services
            if i + batch_size < len(tasks):
                await asyncio.sleep(delay_between_batches)
        
        return results

# Usage in Circle of Experts
class OptimizedExpertManager:
    def __init__(self):
        self.concurrency_manager = ConcurrencyManager(max_concurrent=5)
    
    async def query_experts_optimized(self, experts: List[str], prompt: str):
        """Query multiple experts with optimized concurrency"""
        
        # Create tasks for each expert
        expert_tasks = []
        for expert_name in experts:
            expert = self.get_expert(expert_name)
            task = lambda e=expert: e.query(prompt)
            expert_tasks.append(task)
        
        # Execute with batching and concurrency control
        results = await self.concurrency_manager.batch_execute(
            expert_tasks,
            batch_size=3,  # Query 3 experts at a time
            delay_between_batches=0.2  # 200ms between batches
        )
        
        return results
```

### 2. Memory Optimization

#### Lazy Loading and Caching
```python
import functools
import weakref
from typing import Dict, Any, Optional

class LazyLoader:
    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._weak_cache: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
    
    def lazy_load(self, key: str, loader_func: Callable, use_weak_ref: bool = False):
        """Lazy load with caching"""
        cache = self._weak_cache if use_weak_ref else self._cache
        
        if key not in cache:
            cache[key] = loader_func()
        
        return cache[key]
    
    def clear_cache(self):
        """Clear all caches"""
        self._cache.clear()
        self._weak_cache.clear()

# Global lazy loader
lazy_loader = LazyLoader()

# Example: Lazy loading of AI models
class OptimizedExpertFactory:
    @staticmethod
    def get_expert(expert_name: str):
        """Get expert with lazy loading"""
        return lazy_loader.lazy_load(
            f"expert_{expert_name}",
            lambda: OptimizedExpertFactory._create_expert(expert_name),
            use_weak_ref=True  # Allow garbage collection when not in use
        )
    
    @staticmethod
    def _create_expert(expert_name: str):
        """Create expert instance"""
        # Heavy initialization only when needed
        if expert_name == "openai-gpt4":
            return OpenAIExpert(model="gpt-4")
        elif expert_name == "claude-opus":
            return ClaudeExpert(model="claude-3-opus")
        # ... other experts
```

#### Memory-Efficient Data Structures
```python
import array
import struct
from collections import deque
from typing import Iterator

class MemoryEfficientQueryBuffer:
    """Memory-efficient buffer for storing query history"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.queries = deque(maxlen=max_size)  # Automatic size limiting
        self.query_hashes = array.array('Q')  # Unsigned long long array
    
    def add_query(self, query: str, result: dict):
        """Add query with memory-efficient storage"""
        # Store hash instead of full query for deduplication
        query_hash = hash(query)
        
        # Store only essential result data
        compressed_result = {
            'consensus': result.get('consensus', False),
            'cost': result.get('cost_breakdown', {}).get('total', 0),
            'expert_count': len(result.get('successful_experts', []))
        }
        
        self.queries.append((query_hash, compressed_result))
        
        # Use array for efficient hash storage
        if len(self.query_hashes) >= self.max_size:
            self.query_hashes.pop(0)
        self.query_hashes.append(query_hash)
    
    def get_similar_queries(self, query: str, threshold: float = 0.8) -> Iterator[dict]:
        """Get similar queries using efficient hash comparison"""
        query_hash = hash(query)
        
        for stored_hash, result in self.queries:
            # Simple similarity based on hash proximity
            similarity = 1.0 - abs(query_hash - stored_hash) / max(query_hash, stored_hash)
            
            if similarity >= threshold:
                yield {
                    'similarity': similarity,
                    'result': result
                }
```

## Debugging Tools and Utilities

### 1. Debug Dashboard

#### Real-time Performance Monitoring
```python
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
import json
import asyncio

class DebugDashboard:
    def __init__(self, app: FastAPI):
        self.app = app
        self.connected_clients = set()
        self.metrics_collector = self._create_metrics_collector()
        
        # Add dashboard routes
        self._add_routes()
    
    def _add_routes(self):
        @self.app.get("/debug")
        async def debug_dashboard():
            return HTMLResponse(self._get_dashboard_html())
        
        @self.app.websocket("/debug/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self._handle_websocket(websocket)
    
    async def _handle_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.connected_clients.add(websocket)
        
        try:
            while True:
                # Send real-time metrics
                metrics = await self._collect_metrics()
                await websocket.send_text(json.dumps(metrics))
                await asyncio.sleep(1)  # Update every second
                
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            self.connected_clients.discard(websocket)
    
    async def _collect_metrics(self):
        """Collect real-time system metrics"""
        import psutil
        
        # System metrics
        process = psutil.Process()
        
        # Application metrics
        task_count = len(asyncio.all_tasks())
        active_consultations = getattr(self, '_active_consultations', 0)
        
        return {
            'timestamp': time.time(),
            'system': {
                'cpu_percent': psutil.cpu_percent(),
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'memory_percent': process.memory_percent(),
                'open_files': len(process.open_files()),
                'connections': len(process.connections())
            },
            'application': {
                'active_tasks': task_count,
                'active_consultations': active_consultations,
                'expert_manager_instances': self._count_expert_managers(),
                'mcp_connections': self._count_mcp_connections()
            },
            'performance': {
                'avg_consultation_time': self._get_avg_consultation_time(),
                'success_rate': self._get_success_rate(),
                'cache_hit_rate': self._get_cache_hit_rate()
            }
        }
    
    def _get_dashboard_html(self):
        """Generate debug dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CODE Debug Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
                .metric-card { border: 1px solid #ddd; border-radius: 8px; padding: 15px; }
                .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
                .chart-container { width: 100%; height: 200px; }
            </style>
        </head>
        <body>
            <h1>CODE Debug Dashboard</h1>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <h3>Memory Usage</h3>
                    <div class="metric-value" id="memory">-- MB</div>
                    <canvas id="memoryChart" class="chart-container"></canvas>
                </div>
                
                <div class="metric-card">
                    <h3>Active Tasks</h3>
                    <div class="metric-value" id="tasks">--</div>
                </div>
                
                <div class="metric-card">
                    <h3>Expert Consultations</h3>
                    <div class="metric-value" id="consultations">--</div>
                </div>
                
                <div class="metric-card">
                    <h3>Success Rate</h3>
                    <div class="metric-value" id="successRate">--%</div>
                </div>
            </div>
            
            <script>
                const ws = new WebSocket('ws://localhost:8000/debug/ws');
                
                // Initialize charts
                const memoryChart = new Chart(document.getElementById('memoryChart'), {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Memory (MB)',
                            data: [],
                            borderColor: 'rgb(75, 192, 192)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
                
                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    
                    // Update metrics
                    document.getElementById('memory').textContent = Math.round(data.system.memory_mb) + ' MB';
                    document.getElementById('tasks').textContent = data.application.active_tasks;
                    document.getElementById('consultations').textContent = data.application.active_consultations;
                    document.getElementById('successRate').textContent = Math.round(data.performance.success_rate * 100) + '%';
                    
                    // Update charts
                    const time = new Date(data.timestamp * 1000).toLocaleTimeString();
                    memoryChart.data.labels.push(time);
                    memoryChart.data.datasets[0].data.push(data.system.memory_mb);
                    
                    // Keep only last 20 data points
                    if (memoryChart.data.labels.length > 20) {
                        memoryChart.data.labels.shift();
                        memoryChart.data.datasets[0].data.shift();
                    }
                    
                    memoryChart.update('none');
                };
            </script>
        </body>
        </html>
        """

# Add to FastAPI app
app = FastAPI()
debug_dashboard = DebugDashboard(app)
```

### 2. CLI Debug Tools

#### Debug CLI Commands
```bash
#!/bin/bash
# debug_tools.sh - Debug utilities for CODE project

# Memory analysis
debug_memory() {
    echo "=== Memory Analysis ==="
    python scripts/analyze_memory_usage.py --profile-development
    echo ""
    
    echo "=== Top Memory Consumers ==="
    python -c "
import psutil
import os
process = psutil.Process(os.getpid())
print(f'RSS Memory: {process.memory_info().rss / 1024 / 1024:.2f} MB')
print(f'VMS Memory: {process.memory_info().vms / 1024 / 1024:.2f} MB')
print(f'Memory Percent: {process.memory_percent():.2f}%')
"
}

# Expert consultation debug
debug_experts() {
    echo "=== Expert System Debug ==="
    python -c "
import asyncio
from src.circle_of_experts import EnhancedExpertManager

async def debug_consultation():
    manager = EnhancedExpertManager()
    
    # Test expert availability
    available_experts = await manager.get_available_experts()
    print(f'Available experts: {available_experts}')
    
    # Test simple consultation
    result = await manager.quick_consult('Debug test query')
    print(f'Consultation result: {result.get(\"consensus\", False)}')

asyncio.run(debug_consultation())
"
}

# MCP server debug
debug_mcp() {
    echo "=== MCP Server Debug ==="
    python -c "
import asyncio
from src.mcp.client import MCPClient

async def debug_mcp():
    client = MCPClient()
    
    try:
        servers = await client.list_servers()
        print(f'Available MCP servers: {len(servers)}')
        
        for server in servers[:5]:  # Show first 5
            print(f'- {server}')
            
    except Exception as e:
        print(f'MCP Error: {e}')

asyncio.run(debug_mcp())
"
}

# Database debug
debug_database() {
    echo "=== Database Debug ==="
    python -c "
from src.database.connection import get_engine
import asyncio

async def debug_db():
    try:
        engine = get_engine()
        print(f'Database URL: {engine.url}')
        
        # Test connection
        async with engine.begin() as conn:
            result = await conn.execute('SELECT 1')
            print('Database connection: OK')
            
    except Exception as e:
        print(f'Database Error: {e}')

asyncio.run(debug_db())
"
}

# Performance debug
debug_performance() {
    echo "=== Performance Debug ==="
    
    echo "CPU Usage:"
    python -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%')"
    
    echo "Load Average:"
    python -c "import psutil; print(f'Load: {psutil.getloadavg()}')"
    
    echo "Disk Usage:"
    python -c "import psutil; print(f'Disk: {psutil.disk_usage(\"/\").percent}%')"
}

# Main debug function
debug_all() {
    echo "🔍 CODE Project Debug Report"
    echo "============================"
    echo ""
    
    debug_memory
    echo ""
    debug_experts
    echo ""
    debug_mcp
    echo ""
    debug_database
    echo ""
    debug_performance
}

# Parse command line arguments
case "$1" in
    memory)
        debug_memory
        ;;
    experts)
        debug_experts
        ;;
    mcp)
        debug_mcp
        ;;
    database)
        debug_database
        ;;
    performance)
        debug_performance
        ;;
    all|"")
        debug_all
        ;;
    *)
        echo "Usage: $0 {memory|experts|mcp|database|performance|all}"
        exit 1
        ;;
esac
```

## Best Practices Summary

### Debugging Best Practices
1. **Use Structured Logging**: Always include context and metadata
2. **Enable Debug Mode**: Use environment variables for debug configuration
3. **Profile Early**: Profile during development, not just production
4. **Monitor Memory**: Watch for memory leaks in long-running processes
5. **Test Error Paths**: Ensure error handling is debuggable
6. **Use Async-Aware Tools**: Choose tools that understand async code

### Performance Best Practices
1. **Measure First**: Always profile before optimizing
2. **Optimize Hotpaths**: Focus on the most frequently executed code
3. **Use Connection Pooling**: Reuse connections for external services
4. **Implement Caching**: Cache expensive operations appropriately
5. **Control Concurrency**: Use semaphores and batching for API calls
6. **Monitor Production**: Continuous monitoring of performance metrics

### Tools and Resources
- **Profiling**: cProfile, line_profiler, memory_profiler
- **Memory**: tracemalloc, psutil, objgraph
- **Async**: asyncio debugging, task monitoring
- **Database**: SQLAlchemy query profiling
- **HTTP**: aiohttp session optimization
- **Monitoring**: Custom dashboards, real-time metrics

---

*Effective debugging and profiling are essential for maintaining high-quality, performant AI infrastructure. Use these tools and techniques to identify and resolve issues quickly while optimizing for the best user experience.*