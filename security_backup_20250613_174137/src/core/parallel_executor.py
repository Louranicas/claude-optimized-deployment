"""
Parallel Task Executor for CODE
Handles intelligent parallel execution of deployment tasks
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Callable, Optional, Set
import multiprocessing as mp
from functools import wraps
import time
import psutil
import resource
from weakref import WeakValueDictionary

from src.core.logging_config import get_logger, get_performance_logger, performance_logged

__all__ = [
    "TaskType",
    "Task",
    "TaskResult",
    "ParallelExecutor",
    "task_type"
]


# Configure logging for Claude context
logger = get_logger(__name__)
perf_logger = get_performance_logger(__name__)


class TaskType(Enum):
    """Task execution types for optimal resource allocation"""
    IO_BOUND = "io_bound"      # API calls, file operations
    CPU_BOUND = "cpu_bound"     # Computation, rendering
    MIXED = "mixed"             # Combination of both
    ASYNC = "async"             # Pure async operations


@dataclass
class Task:
    """
    CLAUDE-CONTEXT: Represents a single executable task
    INPUT: Task name, function, dependencies, and type
    OUTPUT: Task result after execution
    """
    name: str
    func: Callable
    args: tuple = ()
    kwargs: dict = None
    dependencies: Set[str] = None
    task_type: TaskType = TaskType.ASYNC
    timeout: Optional[float] = None
    retry_count: int = 3
    
    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}
        if self.dependencies is None:
            self.dependencies = set()


@dataclass
class TaskResult:
    """Result of task execution"""
    task_name: str
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    duration: float = 0.0
    retries: int = 0


class ParallelExecutor:
    """
    CLAUDE-CONTEXT: Orchestrates parallel execution of tasks
    FEATURES:
    - Intelligent task scheduling based on type
    - Dependency resolution
    - Retry logic with exponential backoff
    - Resource management
    - Progress tracking
    """
    
    def __init__(self, 
                 max_workers_thread: int = 10,
                 max_workers_process: int = None,
                 enable_progress: bool = True,
                 max_concurrent_tasks: int = 10,
                 memory_limit_mb: int = 1024):
        """
        Initialize parallel executor with resource pools
        
        Args:
            max_workers_thread: Max thread pool workers
            max_workers_process: Max process pool workers (defaults to CPU count)
            enable_progress: Show progress updates
            max_concurrent_tasks: Maximum concurrent tasks to prevent memory overload
            memory_limit_mb: Memory limit per task in MB
        """
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers_thread)
        self.process_pool = ProcessPoolExecutor(
            max_workers=max_workers_process or mp.cpu_count()
        )
        self.enable_progress = enable_progress
        self._results: Dict[str, TaskResult] = {}
        
        # Memory and concurrency management
        self.max_concurrent_tasks = max_concurrent_tasks
        self.memory_limit_mb = memory_limit_mb
        self._task_semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self._active_tasks: WeakValueDictionary = WeakValueDictionary()
        self._memory_pressure_threshold = 0.85  # 85% memory usage triggers pressure
        
        logger.info(f"ParallelExecutor initialized with {max_concurrent_tasks} max concurrent tasks and {memory_limit_mb}MB memory limit")
        
    async def execute_tasks(self, tasks: List[Task]) -> Dict[str, TaskResult]:
        """
        Execute tasks in parallel with dependency resolution
        
        CLAUDE-CONTEXT: Main entry point for parallel execution
        ALGORITHM:
        1. Build dependency graph
        2. Execute in topological order
        3. Parallelize independent tasks
        4. Handle failures and retries
        """
        # Build task map
        task_map = {task.name: task for task in tasks}
        
        # Validate dependencies
        self._validate_dependencies(task_map)
        
        # Execute in stages based on dependencies
        completed = set()
        
        while len(completed) < len(tasks):
            # Find tasks ready to execute
            ready_tasks = [
                task for task in tasks
                if task.name not in completed
                and task.dependencies.issubset(completed)
            ]
            
            if not ready_tasks:
                raise RuntimeError("Circular dependency detected")
            
            # Execute ready tasks in parallel
            stage_results = await self._execute_stage(ready_tasks)
            
            # Update completed set and results
            for task_name, result in stage_results.items():
                if result.success:
                    completed.add(task_name)
                self._results[task_name] = result
                
            # Check for failures
            failures = [r for r in stage_results.values() if not r.success]
            if failures:
                logger.error(f"Stage execution failed: {[f.task_name for f in failures]}")
                # Continue with tasks that don't depend on failed ones
        
        return self._results
    
    async def _execute_stage(self, tasks: List[Task]) -> Dict[str, TaskResult]:
        """Execute a stage of independent tasks in parallel with memory pressure monitoring"""
        logger.info(f"Executing stage with {len(tasks)} tasks")
        
        with perf_logger.track_operation("stage_execution", task_count=len(tasks)):
            # Check memory pressure before starting
            if self._check_memory_pressure():
                logger.warning("Memory pressure detected, reducing concurrency")
                self._task_semaphore = asyncio.Semaphore(max(1, self.max_concurrent_tasks // 2))
            
            # Group tasks by type for optimal execution
            grouped = self._group_tasks_by_type(tasks)
            
            # Execute each group with appropriate strategy and concurrency control
            all_futures = []
            
            for task_type, task_list in grouped.items():
                if task_type == TaskType.ASYNC:
                    futures = [self._execute_async_task_with_limits(task) for task in task_list]
                elif task_type == TaskType.IO_BOUND:
                    futures = [self._execute_thread_task_with_limits(task) for task in task_list]
                elif task_type == TaskType.CPU_BOUND:
                    futures = [self._execute_process_task_with_limits(task) for task in task_list]
                else:  # MIXED
                    futures = [self._execute_mixed_task_with_limits(task) for task in task_list]
                
                all_futures.extend(futures)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*all_futures, return_exceptions=True)
            
            # Clean up task references
            for task in tasks:
                self._active_tasks.pop(task.name, None)
            
            # Map results back to task names
            return {
                task.name: result 
                for task, result in zip(tasks, results)
            }
    
    def _check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure"""
        try:
            memory = psutil.virtual_memory()
            memory_usage = memory.percent / 100.0
            
            if memory_usage > self._memory_pressure_threshold:
                logger.warning(f"Memory pressure detected: {memory_usage:.1%} usage")
                return True
            return False
        except Exception as e:
            logger.warning(f"Failed to check memory pressure: {e}")
            return False
    
    async def _execute_async_task_with_limits(self, task: Task) -> TaskResult:
        """Execute async task with concurrency and memory limits"""
        async with self._task_semaphore:
            # Track active task
            self._active_tasks[task.name] = task
            return await self._execute_async_task(task)
    
    async def _execute_thread_task_with_limits(self, task: Task) -> TaskResult:
        """Execute thread task with concurrency and memory limits"""
        async with self._task_semaphore:
            # Track active task
            self._active_tasks[task.name] = task
            return await self._execute_thread_task(task)
    
    async def _execute_process_task_with_limits(self, task: Task) -> TaskResult:
        """Execute process task with concurrency and memory limits"""
        async with self._task_semaphore:
            # Track active task
            self._active_tasks[task.name] = task
            return await self._execute_process_task(task)
    
    async def _execute_mixed_task_with_limits(self, task: Task) -> TaskResult:
        """Execute mixed task with concurrency and memory limits"""
        async with self._task_semaphore:
            # Track active task
            self._active_tasks[task.name] = task
            return await self._execute_mixed_task(task)
    
    async def _execute_async_task(self, task: Task) -> TaskResult:
        """Execute pure async task with memory monitoring"""
        start_time = time.time()
        initial_memory = self._get_current_memory_usage()
        
        for attempt in range(task.retry_count):
            try:
                # Check memory before execution
                if self._check_memory_pressure():
                    logger.warning(f"Skipping task {task.name} due to memory pressure")
                    return TaskResult(
                        task_name=task.name,
                        success=False,
                        error=Exception("Task skipped due to memory pressure"),
                        duration=time.time() - start_time,
                        retries=attempt
                    )
                
                if asyncio.iscoroutinefunction(task.func):
                    result = await task.func(*task.args, **task.kwargs)
                else:
                    # Wrap sync function in async
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, task.func, *task.args, **task.kwargs
                    )
                
                # Check memory usage after execution
                final_memory = self._get_current_memory_usage()
                memory_used = final_memory - initial_memory
                
                if memory_used > self.memory_limit_mb:
                    logger.warning(f"Task {task.name} exceeded memory limit: {memory_used}MB > {self.memory_limit_mb}MB")
                
                return TaskResult(
                    task_name=task.name,
                    success=True,
                    result=result,
                    duration=time.time() - start_time,
                    retries=attempt
                )
                
            except Exception as e:
                logger.warning(f"Task {task.name} failed (attempt {attempt + 1}): {e}")
                
                # Clean up any allocated memory between retries
                self._cleanup_task_memory(task.name)
                
                if attempt == task.retry_count - 1:
                    return TaskResult(
                        task_name=task.name,
                        success=False,
                        error=e,
                        duration=time.time() - start_time,
                        retries=attempt + 1
                    )
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
    
    async def _execute_thread_task(self, task: Task) -> TaskResult:
        """Execute I/O bound task in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.thread_pool,
            self._sync_task_wrapper,
            task
        )
    
    async def _execute_process_task(self, task: Task) -> TaskResult:
        """Execute CPU bound task in process pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.process_pool,
            self._sync_task_wrapper,
            task
        )
    
    async def _execute_mixed_task(self, task: Task) -> TaskResult:
        """Execute mixed task with hybrid approach"""
        # Analyze task characteristics and choose best executor
        # This is a simplified version - could be enhanced with ML
        if "api" in task.name.lower() or "fetch" in task.name.lower():
            return await self._execute_thread_task(task)
        else:
            return await self._execute_process_task(task)
    
    def _get_current_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except Exception:
            return 0.0
    
    def _cleanup_task_memory(self, task_name: str) -> None:
        """Clean up memory associated with a task"""
        try:
            # Force garbage collection
            import gc
            gc.collect()
            
            # Remove task from active tracking
            self._active_tasks.pop(task_name, None)
            
        except Exception as e:
            logger.debug(f"Memory cleanup failed for task {task_name}: {e}")
    
    def _sync_task_wrapper(self, task: Task) -> TaskResult:
        """Wrapper for synchronous task execution with memory monitoring"""
        start_time = time.time()
        initial_memory = self._get_current_memory_usage()
        
        for attempt in range(task.retry_count):
            try:
                # Check memory before execution
                memory = psutil.virtual_memory()
                if memory.percent > 85:  # 85% memory usage
                    logger.warning(f"Skipping task {task.name} due to memory pressure")
                    return TaskResult(
                        task_name=task.name,
                        success=False,
                        error=Exception("Task skipped due to memory pressure"),
                        duration=time.time() - start_time,
                        retries=attempt
                    )
                
                result = task.func(*task.args, **task.kwargs)
                
                # Check memory usage after execution
                final_memory = self._get_current_memory_usage()
                memory_used = final_memory - initial_memory
                
                if memory_used > self.memory_limit_mb:
                    logger.warning(f"Task {task.name} exceeded memory limit: {memory_used}MB > {self.memory_limit_mb}MB")
                
                return TaskResult(
                    task_name=task.name,
                    success=True,
                    result=result,
                    duration=time.time() - start_time,
                    retries=attempt
                )
            except Exception as e:
                # Clean up memory between retries
                self._cleanup_task_memory(task.name)
                
                if attempt == task.retry_count - 1:
                    return TaskResult(
                        task_name=task.name,
                        success=False,
                        error=e,
                        duration=time.time() - start_time,
                        retries=attempt + 1
                    )
                time.sleep(2 ** attempt)
    
    def _group_tasks_by_type(self, tasks: List[Task]) -> Dict[TaskType, List[Task]]:
        """Group tasks by their execution type"""
        grouped = {}
        for task in tasks:
            if task.task_type not in grouped:
                grouped[task.task_type] = []
            grouped[task.task_type].append(task)
        return grouped
    
    def _validate_dependencies(self, task_map: Dict[str, Task]):
        """Validate task dependencies exist and check for cycles"""
        for task in task_map.values():
            for dep in task.dependencies:
                if dep not in task_map:
                    raise ValueError(f"Task {task.name} depends on unknown task {dep}")
        
        # TODO: Implement cycle detection using DFS
    
    def get_execution_report(self) -> Dict[str, Any]:
        """Generate execution report for analysis with memory metrics"""
        successful = [r for r in self._results.values() if r.success]
        failed = [r for r in self._results.values() if not r.success]
        
        # Get current memory state
        try:
            memory = psutil.virtual_memory()
            memory_info = {
                "current_usage_percent": memory.percent,
                "available_mb": memory.available / 1024 / 1024,
                "total_mb": memory.total / 1024 / 1024
            }
        except Exception:
            memory_info = {"error": "Unable to retrieve memory information"}
        
        return {
            "total_tasks": len(self._results),
            "successful": len(successful),
            "failed": len(failed),
            "total_duration": sum(r.duration for r in self._results.values()),
            "average_duration": sum(r.duration for r in self._results.values()) / len(self._results) if self._results else 0,
            "total_retries": sum(r.retries for r in self._results.values()),
            "memory_info": memory_info,
            "active_tasks": len(self._active_tasks),
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "memory_limit_mb": self.memory_limit_mb,
            "failures": [
                {
                    "task": r.task_name,
                    "error": str(r.error),
                    "duration": r.duration
                }
                for r in failed
            ]
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup resources"""
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)


# Decorator for marking task types
def task_type(task_type: TaskType):
    """Decorator to mark function task type for optimal execution"""
    def decorator(func):
        func._task_type = task_type
        return func
    return decorator


# Example usage for Claude context
if __name__ == "__main__":
    async def example_deployment():
        """
        CLAUDE-CONTEXT: Example parallel deployment workflow
        Shows how to use ParallelExecutor for infrastructure deployment
        """
        
        # Define deployment tasks
        tasks = [
            # Network provisioning (I/O bound)
            Task(
                name="provision_vpc",
                func=lambda: "VPC created",
                task_type=TaskType.IO_BOUND
            ),
            Task(
                name="provision_subnets",
                func=lambda: "Subnets created",
                dependencies={"provision_vpc"},
                task_type=TaskType.IO_BOUND
            ),
            
            # Container building (CPU bound)
            Task(
                name="build_api_image",
                func=lambda: "API image built",
                task_type=TaskType.CPU_BOUND
            ),
            Task(
                name="build_web_image",
                func=lambda: "Web image built",
                task_type=TaskType.CPU_BOUND
            ),
            
            # Kubernetes deployment (Mixed)
            Task(
                name="deploy_kubernetes",
                func=lambda: "K8s deployed",
                dependencies={"provision_subnets", "build_api_image", "build_web_image"},
                task_type=TaskType.MIXED
            ),
            
            # Monitoring setup (Async)
            Task(
                name="setup_monitoring",
                func=lambda: "Monitoring configured",
                dependencies={"deploy_kubernetes"},
                task_type=TaskType.ASYNC
            )
        ]
        
        # Execute deployment
        async with ParallelExecutor() as executor:
            results = await executor.execute_tasks(tasks)
            report = executor.get_execution_report()
            
            logger.info(f"Deployment completed: {report['successful']}/{report['total_tasks']} tasks successful")
            logger.info(f"Total duration: {report['total_duration']:.2f}s")
            
            if report['failed'] > 0:
                logger.error(f"Failures: {report['failures']}")
    
    # Run example
    asyncio.run(example_deployment())
