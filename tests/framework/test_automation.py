"""
Test Automation Framework

This module provides automated test execution, parallel processing, 
continuous testing pipeline, and comprehensive reporting for the CODE project.
"""

import asyncio
import concurrent.futures
import json
import logging
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union, Tuple
import yaml

import psutil
import pytest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .test_orchestrator import TestOrchestrator, TestConfiguration
from .ffi_integration_tester import FFIIntegrationTester

logger = logging.getLogger(__name__)


class TestExecutionMode(Enum):
    """Test execution mode enumeration."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DISTRIBUTED = "distributed"
    CONTINUOUS = "continuous"


class TestPriority(Enum):
    """Test priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TestEnvironment(Enum):
    """Test environment types."""
    DEVELOPMENT = "development"
    CI = "ci"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class TestJobConfig:
    """Configuration for test job execution."""
    job_id: str
    test_types: List[str]
    execution_mode: TestExecutionMode
    priority: TestPriority
    environment: TestEnvironment
    max_workers: int = 8
    timeout_minutes: int = 60
    retry_count: int = 2
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class TestExecutionResult:
    """Result of test execution."""
    job_config: TestJobConfig
    success: bool
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    test_results: Dict[str, Any]
    resource_usage: Dict[str, float]
    error_message: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)


class ResourceManager:
    """Manages system resources for test execution."""
    
    def __init__(self, max_cpu_percent: float = 80.0, max_memory_percent: float = 80.0):
        self.max_cpu_percent = max_cpu_percent
        self.max_memory_percent = max_memory_percent
        self.active_processes = []
        
    def can_start_job(self, estimated_cpu: float, estimated_memory_mb: float) -> bool:
        """Check if system has resources for new job."""
        current_cpu = psutil.cpu_percent(interval=1)
        current_memory = psutil.virtual_memory()
        current_memory_percent = current_memory.percent
        
        projected_cpu = current_cpu + estimated_cpu
        projected_memory_mb = (current_memory.used / (1024 * 1024)) + estimated_memory_mb
        projected_memory_percent = (projected_memory_mb * 1024 * 1024) / current_memory.total * 100
        
        return (projected_cpu <= self.max_cpu_percent and 
                projected_memory_percent <= self.max_memory_percent)
    
    def register_process(self, process_id: str, pid: int):
        """Register a running process."""
        self.active_processes.append({
            'process_id': process_id,
            'pid': pid,
            'start_time': time.time()
        })
    
    def unregister_process(self, process_id: str):
        """Unregister a completed process."""
        self.active_processes = [p for p in self.active_processes if p['process_id'] != process_id]
    
    def get_resource_usage(self) -> Dict[str, float]:
        """Get current system resource usage."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used_mb': memory.used / (1024 * 1024),
            'disk_percent': disk.percent,
            'active_processes': len(self.active_processes)
        }


class TestArtifactManager:
    """Manages test artifacts and reports."""
    
    def __init__(self, base_path: str = "tests/artifacts"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
    def create_job_directory(self, job_id: str) -> Path:
        """Create directory for test job artifacts."""
        job_dir = self.base_path / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        return job_dir
    
    def save_test_report(self, job_id: str, report: Dict[str, Any]) -> str:
        """Save test report to job directory."""
        job_dir = self.create_job_directory(job_id)
        report_path = job_dir / "test_report.json"
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return str(report_path)
    
    def save_coverage_report(self, job_id: str, coverage_data: Dict[str, Any]) -> str:
        """Save code coverage report."""
        job_dir = self.create_job_directory(job_id)
        coverage_path = job_dir / "coverage_report.json"
        
        with open(coverage_path, 'w') as f:
            json.dump(coverage_data, f, indent=2)
        
        return str(coverage_path)
    
    def save_performance_metrics(self, job_id: str, metrics: Dict[str, Any]) -> str:
        """Save performance metrics."""
        job_dir = self.create_job_directory(job_id)
        metrics_path = job_dir / "performance_metrics.json"
        
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)
        
        return str(metrics_path)
    
    def cleanup_old_artifacts(self, days_old: int = 7):
        """Clean up old test artifacts."""
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        for job_dir in self.base_path.iterdir():
            if job_dir.is_dir():
                try:
                    dir_mtime = job_dir.stat().st_mtime
                    if dir_mtime < cutoff_time:
                        shutil.rmtree(job_dir)
                        logger.info(f"Cleaned up old artifacts: {job_dir}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup {job_dir}: {e}")


class ContinuousTestingWatcher(FileSystemEventHandler):
    """File system watcher for continuous testing."""
    
    def __init__(self, test_automation):
        self.test_automation = test_automation
        self.last_trigger = {}
        self.debounce_seconds = 5
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        
        # Check if file should trigger tests
        if self._should_trigger_tests(file_path):
            current_time = time.time()
            last_time = self.last_trigger.get(file_path, 0)
            
            # Debounce rapid file changes
            if current_time - last_time > self.debounce_seconds:
                self.last_trigger[file_path] = current_time
                asyncio.create_task(self._trigger_tests(file_path))
    
    def _should_trigger_tests(self, file_path: str) -> bool:
        """Determine if file change should trigger tests."""
        path = Path(file_path)
        
        # Trigger on Python and Rust source files
        if path.suffix in ['.py', '.rs']:
            return True
            
        # Trigger on configuration files
        if path.name in ['Cargo.toml', 'pyproject.toml', 'requirements.txt']:
            return True
            
        return False
    
    async def _trigger_tests(self, file_path: str):
        """Trigger appropriate tests based on changed file."""
        logger.info(f"File changed: {file_path}, triggering tests")
        
        # Determine which tests to run based on file path
        test_types = self._determine_test_types(file_path)
        
        # Create and execute test job
        job_config = TestJobConfig(
            job_id=f"continuous_{int(time.time())}",
            test_types=test_types,
            execution_mode=TestExecutionMode.PARALLEL,
            priority=TestPriority.HIGH,
            environment=TestEnvironment.DEVELOPMENT,
            max_workers=4,
            timeout_minutes=10
        )
        
        await self.test_automation.execute_test_job(job_config)
    
    def _determine_test_types(self, file_path: str) -> List[str]:
        """Determine which test types to run based on changed file."""
        path = Path(file_path)
        
        if 'rust_core' in path.parts:
            return ['rust_unit', 'ffi', 'performance']
        elif 'src' in path.parts:
            return ['python_unit', 'integration']
        elif 'tests' in path.parts:
            return ['all']
        else:
            return ['unit']  # Default to unit tests


class TestAutomation:
    """Main test automation framework."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.resource_manager = ResourceManager(
            max_cpu_percent=self.config.get('max_cpu_percent', 80.0),
            max_memory_percent=self.config.get('max_memory_percent', 80.0)
        )
        self.artifact_manager = TestArtifactManager(
            self.config.get('artifacts_path', 'tests/artifacts')
        )
        self.continuous_watcher = None
        self.job_queue = asyncio.Queue()
        self.running_jobs = {}
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load test automation configuration."""
        default_config = {
            'max_cpu_percent': 80.0,
            'max_memory_percent': 80.0,
            'artifacts_path': 'tests/artifacts',
            'max_parallel_jobs': 4,
            'default_timeout_minutes': 30,
            'watch_paths': ['src', 'rust_core', 'tests'],
            'test_discovery_patterns': ['test_*.py', '*_test.py', 'test*.rs']
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    user_config = yaml.safe_load(f)
                else:
                    user_config = json.load(f)
            default_config.update(user_config)
        
        return default_config
    
    async def execute_test_job(self, job_config: TestJobConfig) -> TestExecutionResult:
        """Execute a single test job."""
        logger.info(f"Starting test job: {job_config.job_id}")
        
        start_time = datetime.now()
        job_dir = self.artifact_manager.create_job_directory(job_config.job_id)
        
        # Set up environment variables
        env = os.environ.copy()
        env.update(job_config.environment_vars)
        env['TEST_JOB_ID'] = job_config.job_id
        env['TEST_ARTIFACTS_DIR'] = str(job_dir)
        
        result = TestExecutionResult(
            job_config=job_config,
            success=False,
            start_time=start_time,
            end_time=start_time,
            duration_seconds=0.0,
            test_results={},
            resource_usage={}
        )
        
        try:
            # Execute tests based on execution mode
            if job_config.execution_mode == TestExecutionMode.PARALLEL:
                test_results = await self._execute_parallel_tests(job_config, env)
            elif job_config.execution_mode == TestExecutionMode.SEQUENTIAL:
                test_results = await self._execute_sequential_tests(job_config, env)
            elif job_config.execution_mode == TestExecutionMode.DISTRIBUTED:
                test_results = await self._execute_distributed_tests(job_config, env)
            else:
                raise ValueError(f"Unsupported execution mode: {job_config.execution_mode}")
            
            result.test_results = test_results
            result.success = all(
                test_result.get('success', False) 
                for test_result in test_results.values()
            )
            
            # Save test artifacts
            artifacts = []
            artifacts.append(self.artifact_manager.save_test_report(job_config.job_id, test_results))
            
            # Generate coverage report if available
            if 'coverage' in test_results:
                artifacts.append(self.artifact_manager.save_coverage_report(
                    job_config.job_id, test_results['coverage']
                ))
            
            # Generate performance metrics if available
            performance_data = {
                'resource_usage': self.resource_manager.get_resource_usage(),
                'test_durations': {
                    test_name: test_result.get('duration_seconds', 0)
                    for test_name, test_result in test_results.items()
                }
            }
            artifacts.append(self.artifact_manager.save_performance_metrics(
                job_config.job_id, performance_data
            ))
            
            result.artifacts = artifacts
            
        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Test job {job_config.job_id} failed: {e}")
        
        finally:
            end_time = datetime.now()
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.resource_usage = self.resource_manager.get_resource_usage()
        
        logger.info(f"Test job {job_config.job_id} completed: success={result.success}, duration={result.duration_seconds:.2f}s")
        return result
    
    async def _execute_parallel_tests(self, job_config: TestJobConfig, env: Dict[str, str]) -> Dict[str, Any]:
        """Execute tests in parallel."""
        test_results = {}
        
        # Create test tasks based on test types
        tasks = []
        
        for test_type in job_config.test_types:
            if test_type == 'rust_unit':
                tasks.append(self._run_rust_unit_tests(env))
            elif test_type == 'python_unit':
                tasks.append(self._run_python_unit_tests(env))
            elif test_type == 'integration':
                tasks.append(self._run_integration_tests(env))
            elif test_type == 'ffi':
                tasks.append(self._run_ffi_tests(env))
            elif test_type == 'performance':
                tasks.append(self._run_performance_tests(env))
            elif test_type == 'security':
                tasks.append(self._run_security_tests(env))
            elif test_type == 'e2e':
                tasks.append(self._run_e2e_tests(env))
            elif test_type == 'all':
                # Add all test types
                tasks.extend([
                    self._run_rust_unit_tests(env),
                    self._run_python_unit_tests(env),
                    self._run_integration_tests(env),
                    self._run_ffi_tests(env)
                ])
        
        # Execute tasks with limited concurrency
        semaphore = asyncio.Semaphore(job_config.max_workers)
        
        async def run_with_semaphore(task, test_name):
            async with semaphore:
                return test_name, await task
        
        # Run tasks with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[
                    run_with_semaphore(task, f"test_{i}") 
                    for i, task in enumerate(tasks)
                ]),
                timeout=job_config.timeout_minutes * 60
            )
            
            for test_name, result in results:
                test_results[test_name] = result
                
        except asyncio.TimeoutError:
            logger.error(f"Test job {job_config.job_id} timed out")
            test_results['error'] = 'Test execution timed out'
        
        return test_results
    
    async def _execute_sequential_tests(self, job_config: TestJobConfig, env: Dict[str, str]) -> Dict[str, Any]:
        """Execute tests sequentially."""
        test_results = {}
        
        for test_type in job_config.test_types:
            logger.info(f"Running {test_type} tests")
            
            try:
                if test_type == 'rust_unit':
                    result = await self._run_rust_unit_tests(env)
                elif test_type == 'python_unit':
                    result = await self._run_python_unit_tests(env)
                elif test_type == 'integration':
                    result = await self._run_integration_tests(env)
                elif test_type == 'ffi':
                    result = await self._run_ffi_tests(env)
                elif test_type == 'performance':
                    result = await self._run_performance_tests(env)
                elif test_type == 'security':
                    result = await self._run_security_tests(env)
                elif test_type == 'e2e':
                    result = await self._run_e2e_tests(env)
                else:
                    result = {'success': False, 'error': f'Unknown test type: {test_type}'}
                
                test_results[test_type] = result
                
                # Stop on first failure if configured
                if not result.get('success', False) and job_config.priority == TestPriority.CRITICAL:
                    break
                    
            except Exception as e:
                test_results[test_type] = {'success': False, 'error': str(e)}
                logger.error(f"Test type {test_type} failed: {e}")
        
        return test_results
    
    async def _execute_distributed_tests(self, job_config: TestJobConfig, env: Dict[str, str]) -> Dict[str, Any]:
        """Execute tests in distributed mode (placeholder)."""
        # This would implement distributed test execution across multiple machines
        # For now, fall back to parallel execution
        logger.warning("Distributed test execution not implemented, falling back to parallel")
        return await self._execute_parallel_tests(job_config, env)
    
    async def _run_rust_unit_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run Rust unit tests."""
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_exec(
                'cargo', 'test', '--manifest-path', 'rust_core/Cargo.toml',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            duration = time.time() - start_time
            
            return {
                'success': process.returncode == 0,
                'duration_seconds': duration,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'exit_code': process.returncode
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_python_unit_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run Python unit tests."""
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_exec(
                'python', '-m', 'pytest', 'tests/unit/', '-v', '--json-report', '--json-report-file=/tmp/pytest_report.json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            duration = time.time() - start_time
            
            # Try to load pytest JSON report
            test_details = {}
            try:
                with open('/tmp/pytest_report.json') as f:
                    test_details = json.load(f)
            except Exception:
                pass
            
            return {
                'success': process.returncode == 0,
                'duration_seconds': duration,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'exit_code': process.returncode,
                'test_details': test_details
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_integration_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run integration tests."""
        start_time = time.time()
        
        try:
            # Use the test orchestrator for comprehensive integration testing
            orchestrator = TestOrchestrator()
            report = await orchestrator.run_all_tests()
            
            duration = time.time() - start_time
            
            return {
                'success': report['summary']['status'] == 'PASS',
                'duration_seconds': duration,
                'report': report
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_ffi_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run FFI integration tests."""
        start_time = time.time()
        
        try:
            tester = FFIIntegrationTester()
            report = await tester.run_comprehensive_test_suite()
            
            duration = time.time() - start_time
            
            return {
                'success': report['summary']['success_rate'] >= 0.9,
                'duration_seconds': duration,
                'report': report
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_performance_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run performance tests."""
        start_time = time.time()
        
        try:
            # Run Rust benchmarks
            process = await asyncio.create_subprocess_exec(
                'cargo', 'bench', '--manifest-path', 'rust_core/Cargo.toml',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            duration = time.time() - start_time
            
            return {
                'success': process.returncode == 0,
                'duration_seconds': duration,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'exit_code': process.returncode
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_security_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run security tests."""
        start_time = time.time()
        
        try:
            # Run bandit for Python security analysis
            process = await asyncio.create_subprocess_exec(
                'bandit', '-r', 'src/', '-f', 'json', '-o', '/tmp/bandit_report.json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            duration = time.time() - start_time
            
            # Load bandit report
            security_report = {}
            try:
                with open('/tmp/bandit_report.json') as f:
                    security_report = json.load(f)
            except Exception:
                pass
            
            return {
                'success': process.returncode == 0,
                'duration_seconds': duration,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'security_report': security_report
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    async def _run_e2e_tests(self, env: Dict[str, str]) -> Dict[str, Any]:
        """Run end-to-end tests."""
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_exec(
                'python', '-m', 'pytest', 'tests/e2e/', '-v',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            duration = time.time() - start_time
            
            return {
                'success': process.returncode == 0,
                'duration_seconds': duration,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'exit_code': process.returncode
            }
            
        except Exception as e:
            return {
                'success': False,
                'duration_seconds': time.time() - start_time,
                'error': str(e)
            }
    
    def start_continuous_testing(self):
        """Start continuous testing with file watching."""
        if self.continuous_watcher:
            logger.warning("Continuous testing already started")
            return
        
        self.continuous_watcher = ContinuousTestingWatcher(self)
        observer = Observer()
        
        for watch_path in self.config['watch_paths']:
            if Path(watch_path).exists():
                observer.schedule(self.continuous_watcher, watch_path, recursive=True)
                logger.info(f"Watching {watch_path} for changes")
        
        observer.start()
        logger.info("Continuous testing started")
        
        return observer
    
    def stop_continuous_testing(self, observer):
        """Stop continuous testing."""
        if observer:
            observer.stop()
            observer.join()
            self.continuous_watcher = None
            logger.info("Continuous testing stopped")
    
    async def run_test_pipeline(self, pipeline_config: Dict[str, Any]) -> Dict[str, TestExecutionResult]:
        """Run a complete test pipeline with multiple jobs."""
        pipeline_results = {}
        
        for stage_name, stage_config in pipeline_config.items():
            logger.info(f"Running pipeline stage: {stage_name}")
            
            job_config = TestJobConfig(
                job_id=f"pipeline_{stage_name}_{int(time.time())}",
                **stage_config
            )
            
            result = await self.execute_test_job(job_config)
            pipeline_results[stage_name] = result
            
            # Stop pipeline on critical failure
            if not result.success and job_config.priority == TestPriority.CRITICAL:
                logger.error(f"Pipeline failed at stage: {stage_name}")
                break
        
        return pipeline_results


async def main():
    """Main entry point for test automation."""
    automation = TestAutomation()
    
    # Example: Run comprehensive test suite
    job_config = TestJobConfig(
        job_id=f"comprehensive_{int(time.time())}",
        test_types=['rust_unit', 'python_unit', 'integration', 'ffi', 'performance'],
        execution_mode=TestExecutionMode.PARALLEL,
        priority=TestPriority.HIGH,
        environment=TestEnvironment.DEVELOPMENT,
        max_workers=8,
        timeout_minutes=30
    )
    
    result = await automation.execute_test_job(job_config)
    
    print(f"Test Automation Results:")
    print(f"  Job ID: {result.job_config.job_id}")
    print(f"  Success: {result.success}")
    print(f"  Duration: {result.duration_seconds:.2f} seconds")
    print(f"  Artifacts: {len(result.artifacts)} files")
    
    if result.error_message:
        print(f"  Error: {result.error_message}")


if __name__ == "__main__":
    asyncio.run(main())