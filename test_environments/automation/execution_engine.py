"""
Test Execution Engine - Core test execution and lifecycle management.

This module provides the execution engine for running tests with timeout handling,
retry logic, resource management, and result collection.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Lock, Event
from typing import Dict, List, Optional, Any, Callable, Union
from uuid import uuid4

import psutil
from prometheus_client import Counter, Histogram, Gauge, Summary

logger = logging.getLogger(__name__)

# Metrics
test_executions = Counter('test_executions_total', 'Total test executions', ['test_type', 'status'])
test_duration = Histogram('test_duration_seconds', 'Test execution duration', ['test_type'])
active_tests = Gauge('active_tests_count', 'Currently active tests')
execution_errors = Counter('execution_errors_total', 'Execution errors', ['error_type'])
resource_allocation = Gauge('resource_allocation', 'Resource allocation', ['resource_type'])


class TestType(Enum):
    """Test execution types."""
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    STRESS = "stress"
    CHAOS = "chaos"
    SECURITY = "security"
    E2E = "e2e"


class ExecutionStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass
class TestResult:
    """Test execution result."""
    test_name: str
    success: bool
    start_time: datetime
    end_time: datetime
    duration: float
    output: str = ""
    error: str = ""
    exit_code: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    resource_usage: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestExecution:
    """Test execution context."""
    id: str
    test_name: str
    test_type: TestType
    command: Union[str, List[str], Callable]
    status: ExecutionStatus = ExecutionStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    timeout: int = 3600  # seconds
    retry_count: int = 0
    max_retries: int = 2
    working_dir: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    artifacts_dir: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    process: Optional[subprocess.Popen] = None
    resource_monitor: Optional['ResourceMonitor'] = None


class ResourceMonitor:
    """Monitor resource usage during test execution."""
    
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.measurements: List[Dict[str, Any]] = []
        self._stop_event = Event()
        self._monitor_thread = None
        
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        import threading
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return aggregated metrics."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            
        if not self.measurements:
            return {}
            
        # Aggregate measurements
        cpu_values = [m['cpu_percent'] for m in self.measurements]
        memory_values = [m['memory_mb'] for m in self.measurements]
        
        return {
            'peak_cpu_percent': max(cpu_values) if cpu_values else 0,
            'avg_cpu_percent': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            'peak_memory_mb': max(memory_values) if memory_values else 0,
            'avg_memory_mb': sum(memory_values) / len(memory_values) if memory_values else 0,
            'total_measurements': len(self.measurements),
            'duration_seconds': self.measurements[-1]['timestamp'] - self.measurements[0]['timestamp']
            if len(self.measurements) >= 2 else 0
        }
        
    def _monitor_loop(self) -> None:
        """Monitor resource usage loop."""
        try:
            psutil_process = psutil.Process(self.process.pid)
            start_time = time.time()
            
            while not self._stop_event.is_set():
                try:
                    # Get process and children resource usage
                    children = psutil_process.children(recursive=True)
                    all_processes = [psutil_process] + children
                    
                    total_cpu = 0
                    total_memory = 0
                    
                    for proc in all_processes:
                        if proc.is_running():
                            cpu_percent = proc.cpu_percent()
                            memory_info = proc.memory_info()
                            total_cpu += cpu_percent
                            total_memory += memory_info.rss // (1024 * 1024)  # MB
                            
                    measurement = {
                        'timestamp': time.time() - start_time,
                        'cpu_percent': total_cpu,
                        'memory_mb': total_memory,
                        'process_count': len(all_processes)
                    }
                    
                    self.measurements.append(measurement)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process may have ended
                    break
                    
                time.sleep(1)  # Sample every second
                
        except Exception as e:
            logger.warning(f"Resource monitoring error: {e}")


class TestExecutor:
    """Individual test executor with timeout and resource management."""
    
    def __init__(self, execution: TestExecution):
        self.execution = execution
        self._start_time = None
        self._end_time = None
        
    async def execute(self) -> TestResult:
        """Execute the test and return result."""
        self.execution.status = ExecutionStatus.RUNNING
        self.execution.start_time = datetime.now()
        self._start_time = time.time()
        
        active_tests.inc()
        
        try:
            if callable(self.execution.command):
                result = await self._execute_callable()
            elif isinstance(self.execution.command, (str, list)):
                result = await self._execute_subprocess()
            else:
                raise ValueError(f"Unsupported command type: {type(self.execution.command)}")
                
            self.execution.status = ExecutionStatus.COMPLETED
            test_executions.labels(
                test_type=self.execution.test_type.value,
                status='completed'
            ).inc()
            
            return result
            
        except asyncio.TimeoutError:
            self.execution.status = ExecutionStatus.TIMEOUT
            test_executions.labels(
                test_type=self.execution.test_type.value,
                status='timeout'
            ).inc()
            execution_errors.labels(error_type='timeout').inc()
            
            return TestResult(
                test_name=self.execution.test_name,
                success=False,
                start_time=self.execution.start_time,
                end_time=datetime.now(),
                duration=time.time() - self._start_time,
                error=f"Test timeout after {self.execution.timeout} seconds"
            )
            
        except Exception as e:
            self.execution.status = ExecutionStatus.FAILED
            test_executions.labels(
                test_type=self.execution.test_type.value,
                status='failed'
            ).inc()
            execution_errors.labels(error_type='execution_error').inc()
            
            return TestResult(
                test_name=self.execution.test_name,
                success=False,
                start_time=self.execution.start_time,
                end_time=datetime.now(),
                duration=time.time() - self._start_time,
                error=str(e)
            )
            
        finally:
            self.execution.end_time = datetime.now()
            self._end_time = time.time()
            active_tests.dec()
            
            # Record duration
            duration = self._end_time - self._start_time
            test_duration.labels(test_type=self.execution.test_type.value).observe(duration)
            
    async def _execute_callable(self) -> TestResult:
        """Execute a callable test."""
        start_time = datetime.now()
        
        try:
            # Execute with timeout
            if asyncio.iscoroutinefunction(self.execution.command):
                result = await asyncio.wait_for(
                    self.execution.command(),
                    timeout=self.execution.timeout
                )
            else:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self.execution.command),
                    timeout=self.execution.timeout
                )
                
            end_time = datetime.now()
            
            return TestResult(
                test_name=self.execution.test_name,
                success=True,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                output=str(result) if result else "Test completed successfully"
            )
            
        except Exception as e:
            end_time = datetime.now()
            return TestResult(
                test_name=self.execution.test_name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                error=str(e)
            )
            
    async def _execute_subprocess(self) -> TestResult:
        """Execute a subprocess test."""
        start_time = datetime.now()
        
        # Prepare command
        if isinstance(self.execution.command, str):
            cmd = self.execution.command
            shell = True
        else:
            cmd = self.execution.command
            shell = False
            
        # Prepare environment
        env = os.environ.copy()
        env.update(self.execution.environment)
        
        # Create artifacts directory
        if self.execution.artifacts_dir:
            Path(self.execution.artifacts_dir).mkdir(parents=True, exist_ok=True)
            
        try:
            # Start process
            process = await asyncio.create_subprocess_shell(
                cmd if shell else ' '.join(cmd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.execution.working_dir,
                env=env,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            self.execution.process = process
            
            # Start resource monitoring
            if hasattr(process, 'pid') and process.pid:
                try:
                    # Convert asyncio subprocess to psutil-compatible process
                    import subprocess
                    sync_process = subprocess.Popen(
                        cmd if shell else cmd,
                        shell=shell,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=self.execution.working_dir,
                        env=env
                    )
                    
                    resource_monitor = ResourceMonitor(sync_process)
                    resource_monitor.start_monitoring()
                    self.execution.resource_monitor = resource_monitor
                except Exception as e:
                    logger.warning(f"Could not start resource monitoring: {e}")
                    
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.execution.timeout
                )
            except asyncio.TimeoutError:
                # Kill process tree
                await self._kill_process_tree(process)
                raise
                
            end_time = datetime.now()
            
            # Stop resource monitoring
            resource_usage = {}
            if self.execution.resource_monitor:
                resource_usage = self.execution.resource_monitor.stop_monitoring()
                
            # Collect artifacts
            artifacts = []
            if self.execution.artifacts_dir:
                artifacts = self._collect_artifacts(self.execution.artifacts_dir)
                
            return TestResult(
                test_name=self.execution.test_name,
                success=process.returncode == 0,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                output=stdout.decode('utf-8', errors='replace') if stdout else "",
                error=stderr.decode('utf-8', errors='replace') if stderr else "",
                exit_code=process.returncode,
                resource_usage=resource_usage,
                artifacts=artifacts
            )
            
        except Exception as e:
            end_time = datetime.now()
            
            # Stop resource monitoring
            if self.execution.resource_monitor:
                self.execution.resource_monitor.stop_monitoring()
                
            return TestResult(
                test_name=self.execution.test_name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                error=str(e)
            )
            
    async def _kill_process_tree(self, process: asyncio.subprocess.Process) -> None:
        """Kill process and all its children."""
        try:
            if process.returncode is None:
                if os.name != 'nt':
                    # Unix: kill process group
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    
                    # Wait a bit for graceful shutdown
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        # Force kill
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    # Windows: terminate process
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                        
        except (ProcessLookupError, PermissionError, OSError) as e:
            logger.warning(f"Error killing process: {e}")
            
    def _collect_artifacts(self, artifacts_dir: str) -> List[str]:
        """Collect test artifacts."""
        artifacts = []
        try:
            artifacts_path = Path(artifacts_dir)
            if artifacts_path.exists():
                for file_path in artifacts_path.rglob('*'):
                    if file_path.is_file():
                        artifacts.append(str(file_path))
        except Exception as e:
            logger.warning(f"Error collecting artifacts: {e}")
            
        return artifacts
        
    def cancel(self) -> None:
        """Cancel test execution."""
        if self.execution.process:
            asyncio.create_task(self._kill_process_tree(self.execution.process))
        self.execution.status = ExecutionStatus.CANCELLED


class ExecutionEngine:
    """Main test execution engine."""
    
    def __init__(self, max_workers: int = 10, max_processes: int = 4):
        self.max_workers = max_workers
        self.max_processes = max_processes
        
        self._thread_executor = ThreadPoolExecutor(max_workers=max_workers)
        self._process_executor = ProcessPoolExecutor(max_workers=max_processes)
        
        self.executions: Dict[str, TestExecution] = {}
        self.executors: Dict[str, TestExecutor] = {}
        self._lock = Lock()
        
        logger.info(f"Execution engine initialized with {max_workers} workers and {max_processes} processes")
        
    async def execute_test(self, test_name: str, timeout: int = 3600,
                          retry_count: int = 2, metadata: Optional[Dict[str, Any]] = None) -> TestResult:
        """Execute a single test."""
        execution_id = str(uuid4())
        
        # Create execution context
        execution = TestExecution(
            id=execution_id,
            test_name=test_name,
            test_type=self._detect_test_type(test_name),
            command=self._resolve_test_command(test_name),
            timeout=timeout,
            max_retries=retry_count,
            metadata=metadata or {}
        )
        
        with self._lock:
            self.executions[execution_id] = execution
            
        # Execute with retries
        for attempt in range(retry_count + 1):
            execution.retry_count = attempt
            
            if attempt > 0:
                execution.status = ExecutionStatus.RETRYING
                logger.info(f"Retrying test {test_name} (attempt {attempt + 1})")
                
            executor = TestExecutor(execution)
            
            with self._lock:
                self.executors[execution_id] = executor
                
            try:
                result = await executor.execute()
                
                if result.success:
                    return result
                elif attempt == retry_count:
                    # Last attempt failed
                    return result
                else:
                    # Wait before retry
                    await asyncio.sleep(min(2 ** attempt, 30))  # Exponential backoff
                    
            except Exception as e:
                logger.error(f"Test execution error: {e}")
                if attempt == retry_count:
                    return TestResult(
                        test_name=test_name,
                        success=False,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        duration=0,
                        error=str(e)
                    )
            finally:
                with self._lock:
                    self.executors.pop(execution_id, None)
                    
        # Should not reach here
        return TestResult(
            test_name=test_name,
            success=False,
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration=0,
            error="Unknown execution error"
        )
        
    def _detect_test_type(self, test_name: str) -> TestType:
        """Detect test type from test name."""
        test_name_lower = test_name.lower()
        
        if 'stress' in test_name_lower or 'load' in test_name_lower:
            return TestType.STRESS
        elif 'chaos' in test_name_lower:
            return TestType.CHAOS
        elif 'performance' in test_name_lower or 'perf' in test_name_lower:
            return TestType.PERFORMANCE
        elif 'integration' in test_name_lower or 'e2e' in test_name_lower:
            return TestType.INTEGRATION
        elif 'security' in test_name_lower:
            return TestType.SECURITY
        else:
            return TestType.UNIT
            
    def _resolve_test_command(self, test_name: str) -> Union[str, List[str], Callable]:
        """Resolve test command from test name."""
        # This would be configurable in a real implementation
        
        # Check if it's a Python test
        if test_name.endswith('.py') or 'test_' in test_name:
            return f"python -m pytest {test_name} -v"
            
        # Check if it's a shell script
        if test_name.endswith('.sh'):
            return f"bash {test_name}"
            
        # Check if it's a callable (function name)
        if hasattr(self, test_name):
            return getattr(self, test_name)
            
        # Default: assume it's a command
        return test_name
        
    async def execute_test_suite(self, tests: List[str], parallel: bool = True,
                                max_parallel: int = 4) -> List[TestResult]:
        """Execute multiple tests."""
        if parallel:
            return await self._execute_parallel(tests, max_parallel)
        else:
            return await self._execute_sequential(tests)
            
    async def _execute_parallel(self, tests: List[str], max_parallel: int) -> List[TestResult]:
        """Execute tests in parallel."""
        semaphore = asyncio.Semaphore(max_parallel)
        
        async def run_test(test_name: str) -> TestResult:
            async with semaphore:
                return await self.execute_test(test_name)
                
        tasks = [run_test(test) for test in tests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(TestResult(
                    test_name=tests[i],
                    success=False,
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    duration=0,
                    error=str(result)
                ))
            else:
                processed_results.append(result)
                
        return processed_results
        
    async def _execute_sequential(self, tests: List[str]) -> List[TestResult]:
        """Execute tests sequentially."""
        results = []
        for test in tests:
            result = await self.execute_test(test)
            results.append(result)
        return results
        
    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a test execution."""
        with self._lock:
            executor = self.executors.get(execution_id)
            if executor:
                executor.cancel()
                return True
        return False
        
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status."""
        with self._lock:
            execution = self.executions.get(execution_id)
            if not execution:
                return None
                
            return {
                'id': execution.id,
                'test_name': execution.test_name,
                'test_type': execution.test_type.value,
                'status': execution.status.value,
                'start_time': execution.start_time.isoformat() if execution.start_time else None,
                'end_time': execution.end_time.isoformat() if execution.end_time else None,
                'retry_count': execution.retry_count,
                'max_retries': execution.max_retries
            }
            
    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get all active executions."""
        with self._lock:
            active = []
            for execution_id, execution in self.executions.items():
                if execution.status in [ExecutionStatus.RUNNING, ExecutionStatus.RETRYING]:
                    active.append(self.get_execution_status(execution_id))
            return active
            
    def shutdown(self) -> None:
        """Shutdown the execution engine."""
        logger.info("Shutting down execution engine...")
        
        # Cancel all active executions
        with self._lock:
            for execution_id in list(self.executors.keys()):
                self.cancel_execution(execution_id)
                
        # Shutdown executors
        self._thread_executor.shutdown(wait=True, timeout=30)
        self._process_executor.shutdown(wait=True, timeout=30)
        
        logger.info("Execution engine shutdown complete")


# Example stress test functions
def example_cpu_stress_test():
    """Example CPU stress test."""
    import math
    start = time.time()
    
    # CPU intensive calculation
    while time.time() - start < 30:  # Run for 30 seconds
        for i in range(1000):
            math.sqrt(i * i + 1)
            
    return "CPU stress test completed"


def example_memory_stress_test():
    """Example memory stress test."""
    memory_blocks = []
    
    try:
        # Allocate memory in 10MB chunks
        for i in range(100):
            block = bytearray(10 * 1024 * 1024)  # 10MB
            memory_blocks.append(block)
            time.sleep(0.1)
            
        return "Memory stress test completed"
    finally:
        # Cleanup
        del memory_blocks


# Example usage
if __name__ == "__main__":
    async def main():
        engine = ExecutionEngine()
        
        # Execute a test
        result = await engine.execute_test("example_cpu_stress_test")
        print(f"Test result: {result.success}, Duration: {result.duration:.2f}s")
        
        # Execute multiple tests
        tests = ["example_cpu_stress_test", "example_memory_stress_test"]
        results = await engine.execute_test_suite(tests, parallel=True)
        
        for result in results:
            print(f"Test {result.test_name}: {result.success}, Duration: {result.duration:.2f}s")
            
        engine.shutdown()
        
    asyncio.run(main())