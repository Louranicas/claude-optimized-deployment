"""
Test Orchestrator - Central test execution orchestration system.

This module provides the main orchestration engine for automated test execution,
managing test suites, resources, and execution lifecycle.
"""

import asyncio
import json
import logging
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from uuid import uuid4

import psutil
import yaml
from prometheus_client import Counter, Histogram, Gauge, Summary

from .scheduler import TestScheduler, ScheduleStrategy
from .execution_engine import ExecutionEngine, TestExecutor
from .result_processor import ResultProcessor, TestResult
from .report_generator import ReportGenerator, ReportFormat


logger = logging.getLogger(__name__)


# Metrics
test_executions = Counter('test_executions_total', 'Total test executions', ['suite', 'status'])
test_duration = Histogram('test_duration_seconds', 'Test execution duration', ['suite', 'test_type'])
active_tests = Gauge('active_tests', 'Currently running tests', ['suite'])
orchestration_errors = Counter('orchestration_errors_total', 'Orchestration errors', ['error_type'])
resource_usage = Gauge('resource_usage_percent', 'Resource usage percentage', ['resource_type'])


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TestPriority(Enum):
    """Test execution priority."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class TestSuite:
    """Test suite configuration."""
    id: str
    name: str
    tests: List[str]
    priority: TestPriority = TestPriority.MEDIUM
    timeout: int = 3600  # seconds
    parallel: bool = True
    max_parallel: int = 4
    retry_count: int = 2
    dependencies: List[str] = field(default_factory=list)
    resources: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    schedule: Optional[str] = None
    notifications: List[str] = field(default_factory=list)


@dataclass
class TestExecution:
    """Test execution context."""
    id: str
    suite: TestSuite
    status: TestStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: List[TestResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    resource_allocation: Dict[str, Any] = field(default_factory=dict)


class TestOrchestrator:
    """Main test orchestration engine."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.scheduler = TestScheduler(strategy=ScheduleStrategy.RESOURCE_AWARE)
        self.execution_engine = ExecutionEngine(
            max_workers=self.config.get('max_workers', 10),
            max_processes=self.config.get('max_processes', 4)
        )
        self.result_processor = ResultProcessor()
        self.report_generator = ReportGenerator()
        
        self.test_suites: Dict[str, TestSuite] = {}
        self.executions: Dict[str, TestExecution] = {}
        self.active_executions: Set[str] = set()
        self.execution_history: List[TestExecution] = []
        
        self._executor = ThreadPoolExecutor(max_workers=self.config.get('orchestrator_threads', 5))
        self._process_executor = ProcessPoolExecutor(max_workers=self.config.get('orchestrator_processes', 2))
        self._shutdown = False
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load orchestrator configuration."""
        default_config = {
            'max_workers': 10,
            'max_processes': 4,
            'orchestrator_threads': 5,
            'orchestrator_processes': 2,
            'resource_limits': {
                'cpu_percent': 80,
                'memory_percent': 75,
                'disk_percent': 90
            },
            'execution_timeout': 7200,
            'report_formats': ['html', 'json', 'pdf'],
            'notification_channels': ['slack', 'email', 'webhook']
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
                
        return default_config
        
    def register_suite(self, suite: TestSuite) -> None:
        """Register a test suite."""
        self.test_suites[suite.id] = suite
        logger.info(f"Registered test suite: {suite.name} (ID: {suite.id})")
        
    def schedule_suite(self, suite_id: str, immediate: bool = False,
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """Schedule a test suite for execution."""
        if suite_id not in self.test_suites:
            raise ValueError(f"Unknown test suite: {suite_id}")
            
        suite = self.test_suites[suite_id]
        execution_id = str(uuid4())
        
        execution = TestExecution(
            id=execution_id,
            suite=suite,
            status=TestStatus.PENDING,
            metadata=metadata or {}
        )
        
        self.executions[execution_id] = execution
        
        if immediate:
            self._executor.submit(self._execute_suite, execution_id)
        else:
            self.scheduler.schedule_test(
                execution_id,
                suite.priority,
                suite.resources,
                lambda: self._execute_suite(execution_id)
            )
            
        logger.info(f"Scheduled test suite {suite.name} for execution (ID: {execution_id})")
        return execution_id
        
    async def _execute_suite(self, execution_id: str) -> None:
        """Execute a test suite."""
        execution = self.executions.get(execution_id)
        if not execution:
            logger.error(f"Execution {execution_id} not found")
            return
            
        try:
            # Update status
            execution.status = TestStatus.RUNNING
            execution.start_time = datetime.now()
            self.active_executions.add(execution_id)
            active_tests.labels(suite=execution.suite.name).inc()
            
            # Check resource availability
            if not self._check_resources(execution.suite.resources):
                execution.status = TestStatus.FAILED
                execution.errors.append("Insufficient resources available")
                return
                
            # Allocate resources
            execution.resource_allocation = self._allocate_resources(execution.suite.resources)
            
            # Execute tests
            if execution.suite.parallel:
                results = await self._execute_parallel(execution)
            else:
                results = await self._execute_sequential(execution)
                
            execution.results = results
            
            # Process results
            processed_results = self.result_processor.process_results(results)
            execution.metadata['processed_results'] = processed_results
            
            # Determine final status
            if all(r.success for r in results):
                execution.status = TestStatus.COMPLETED
            else:
                execution.status = TestStatus.FAILED
                
        except asyncio.TimeoutError:
            execution.status = TestStatus.TIMEOUT
            execution.errors.append(f"Suite execution timeout after {execution.suite.timeout}s")
            orchestration_errors.labels(error_type='timeout').inc()
            
        except Exception as e:
            execution.status = TestStatus.FAILED
            execution.errors.append(str(e))
            orchestration_errors.labels(error_type='execution_error').inc()
            logger.exception(f"Error executing suite {execution.suite.name}")
            
        finally:
            # Cleanup
            execution.end_time = datetime.now()
            self.active_executions.discard(execution_id)
            active_tests.labels(suite=execution.suite.name).dec()
            
            # Release resources
            self._release_resources(execution.resource_allocation)
            
            # Record metrics
            duration = (execution.end_time - execution.start_time).total_seconds()
            test_duration.labels(
                suite=execution.suite.name,
                test_type='suite'
            ).observe(duration)
            test_executions.labels(
                suite=execution.suite.name,
                status=execution.status.value
            ).inc()
            
            # Generate reports
            await self._generate_reports(execution)
            
            # Send notifications
            await self._send_notifications(execution)
            
            # Archive execution
            self.execution_history.append(execution)
            
    async def _execute_parallel(self, execution: TestExecution) -> List[TestResult]:
        """Execute tests in parallel."""
        results = []
        semaphore = asyncio.Semaphore(execution.suite.max_parallel)
        
        async def run_test(test_name: str) -> TestResult:
            async with semaphore:
                return await self.execution_engine.execute_test(
                    test_name,
                    execution.suite.timeout,
                    execution.suite.retry_count,
                    execution.metadata
                )
                
        tasks = [run_test(test) for test in execution.suite.tests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(TestResult(
                    test_name=execution.suite.tests[i],
                    success=False,
                    error=str(result),
                    duration=0
                ))
            else:
                processed_results.append(result)
                
        return processed_results
        
    async def _execute_sequential(self, execution: TestExecution) -> List[TestResult]:
        """Execute tests sequentially."""
        results = []
        
        for test in execution.suite.tests:
            try:
                result = await self.execution_engine.execute_test(
                    test,
                    execution.suite.timeout,
                    execution.suite.retry_count,
                    execution.metadata
                )
                results.append(result)
                
                # Stop on failure if configured
                if not result.success and execution.suite.stop_on_failure:
                    break
                    
            except Exception as e:
                results.append(TestResult(
                    test_name=test,
                    success=False,
                    error=str(e),
                    duration=0
                ))
                
        return results
        
    def _check_resources(self, required: Dict[str, Any]) -> bool:
        """Check if required resources are available."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        resource_usage.labels(resource_type='cpu').set(cpu_percent)
        resource_usage.labels(resource_type='memory').set(memory_percent)
        resource_usage.labels(resource_type='disk').set(disk_percent)
        
        limits = self.config['resource_limits']
        
        if cpu_percent > limits['cpu_percent']:
            logger.warning(f"CPU usage too high: {cpu_percent}%")
            return False
            
        if memory_percent > limits['memory_percent']:
            logger.warning(f"Memory usage too high: {memory_percent}%")
            return False
            
        if disk_percent > limits['disk_percent']:
            logger.warning(f"Disk usage too high: {disk_percent}%")
            return False
            
        return True
        
    def _allocate_resources(self, required: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate resources for test execution."""
        allocation = {
            'cpu_cores': required.get('cpu_cores', 1),
            'memory_mb': required.get('memory_mb', 512),
            'disk_mb': required.get('disk_mb', 1024),
            'network_bandwidth': required.get('network_bandwidth', 'default'),
            'allocated_at': datetime.now().isoformat()
        }
        
        # In a real implementation, this would interact with resource managers
        logger.info(f"Allocated resources: {allocation}")
        return allocation
        
    def _release_resources(self, allocation: Dict[str, Any]) -> None:
        """Release allocated resources."""
        if not allocation:
            return
            
        # In a real implementation, this would interact with resource managers
        logger.info(f"Released resources: {allocation}")
        
    async def _generate_reports(self, execution: TestExecution) -> None:
        """Generate execution reports."""
        try:
            for format_type in self.config['report_formats']:
                report_path = await self.report_generator.generate_report(
                    execution,
                    ReportFormat(format_type),
                    output_dir=Path(self.config.get('report_dir', './reports'))
                )
                execution.metadata[f'report_{format_type}'] = str(report_path)
                logger.info(f"Generated {format_type} report: {report_path}")
                
        except Exception as e:
            logger.error(f"Error generating reports: {e}")
            orchestration_errors.labels(error_type='report_generation').inc()
            
    async def _send_notifications(self, execution: TestExecution) -> None:
        """Send execution notifications."""
        if not execution.suite.notifications:
            return
            
        notification_data = {
            'execution_id': execution.id,
            'suite_name': execution.suite.name,
            'status': execution.status.value,
            'duration': (execution.end_time - execution.start_time).total_seconds()
            if execution.end_time and execution.start_time else 0,
            'total_tests': len(execution.suite.tests),
            'passed_tests': sum(1 for r in execution.results if r.success),
            'failed_tests': sum(1 for r in execution.results if not r.success),
            'errors': execution.errors,
            'reports': {k: v for k, v in execution.metadata.items() if k.startswith('report_')}
        }
        
        for channel in execution.suite.notifications:
            try:
                # In a real implementation, this would send to actual channels
                logger.info(f"Sending notification to {channel}: {notification_data}")
            except Exception as e:
                logger.error(f"Error sending notification to {channel}: {e}")
                
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status."""
        execution = self.executions.get(execution_id)
        if not execution:
            return None
            
        return {
            'id': execution.id,
            'suite': execution.suite.name,
            'status': execution.status.value,
            'start_time': execution.start_time.isoformat() if execution.start_time else None,
            'end_time': execution.end_time.isoformat() if execution.end_time else None,
            'progress': {
                'total': len(execution.suite.tests),
                'completed': len(execution.results),
                'passed': sum(1 for r in execution.results if r.success),
                'failed': sum(1 for r in execution.results if not r.success)
            },
            'errors': execution.errors,
            'metadata': execution.metadata
        }
        
    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a test execution."""
        execution = self.executions.get(execution_id)
        if not execution or execution.status not in [TestStatus.PENDING, TestStatus.RUNNING]:
            return False
            
        execution.status = TestStatus.CANCELLED
        execution.end_time = datetime.now()
        self.active_executions.discard(execution_id)
        
        # Cancel in execution engine
        self.execution_engine.cancel_execution(execution_id)
        
        logger.info(f"Cancelled execution {execution_id}")
        return True
        
    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get all active executions."""
        return [
            self.get_execution_status(exec_id)
            for exec_id in self.active_executions
        ]
        
    def get_execution_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get execution history."""
        history = []
        for execution in self.execution_history[-limit:]:
            history.append({
                'id': execution.id,
                'suite': execution.suite.name,
                'status': execution.status.value,
                'start_time': execution.start_time.isoformat() if execution.start_time else None,
                'end_time': execution.end_time.isoformat() if execution.end_time else None,
                'duration': (execution.end_time - execution.start_time).total_seconds()
                if execution.end_time and execution.start_time else 0,
                'test_count': len(execution.suite.tests),
                'passed': sum(1 for r in execution.results if r.success),
                'failed': sum(1 for r in execution.results if not r.success)
            })
        return history
        
    def shutdown(self) -> None:
        """Shutdown the orchestrator."""
        logger.info("Shutting down test orchestrator...")
        self._shutdown = True
        
        # Cancel active executions
        for exec_id in list(self.active_executions):
            self.cancel_execution(exec_id)
            
        # Shutdown executors
        self._executor.shutdown(wait=True, timeout=30)
        self._process_executor.shutdown(wait=True, timeout=30)
        
        # Shutdown components
        self.scheduler.shutdown()
        self.execution_engine.shutdown()
        
        logger.info("Test orchestrator shutdown complete")


# Example usage
if __name__ == "__main__":
    # Create orchestrator
    orchestrator = TestOrchestrator()
    
    # Register test suites
    stress_suite = TestSuite(
        id="stress-001",
        name="Stress Test Suite",
        tests=[
            "test_high_load",
            "test_memory_pressure",
            "test_cpu_intensive",
            "test_io_intensive"
        ],
        priority=TestPriority.HIGH,
        timeout=1800,
        parallel=True,
        max_parallel=2,
        resources={
            'cpu_cores': 4,
            'memory_mb': 4096
        },
        tags={'stress', 'performance'},
        notifications=['slack', 'email']
    )
    
    orchestrator.register_suite(stress_suite)
    
    # Schedule execution
    execution_id = orchestrator.schedule_suite("stress-001", immediate=True)
    
    # Monitor execution
    import asyncio
    
    async def monitor():
        while True:
            status = orchestrator.get_execution_status(execution_id)
            if status:
                print(f"Status: {status['status']}, Progress: {status['progress']}")
                if status['status'] in ['completed', 'failed', 'cancelled']:
                    break
            await asyncio.sleep(5)
            
    asyncio.run(monitor())