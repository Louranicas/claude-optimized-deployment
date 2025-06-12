"""
Test Scheduler - Intelligent test scheduling and resource management.

This module provides intelligent scheduling capabilities for test execution,
including resource-aware scheduling, priority management, and optimization.
"""

import asyncio
import heapq
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock, Event, Thread
from typing import Dict, List, Optional, Callable, Any, Tuple
from uuid import uuid4

import psutil
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# Metrics
scheduled_tests = Counter('scheduled_tests_total', 'Total scheduled tests', ['priority'])
scheduling_delays = Histogram('scheduling_delay_seconds', 'Test scheduling delays')
queue_size = Gauge('scheduler_queue_size', 'Current queue size', ['priority'])
resource_conflicts = Counter('resource_conflicts_total', 'Resource conflicts detected')
scheduling_decisions = Counter('scheduling_decisions_total', 'Scheduling decisions', ['strategy', 'outcome'])


class ScheduleStrategy(Enum):
    """Test scheduling strategies."""
    FIFO = "fifo"  # First In, First Out
    PRIORITY = "priority"  # Priority-based scheduling
    RESOURCE_AWARE = "resource_aware"  # Resource-aware scheduling
    LOAD_BALANCED = "load_balanced"  # Load-balanced scheduling
    INTELLIGENT = "intelligent"  # AI-driven intelligent scheduling


class ResourceType(Enum):
    """System resource types."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    GPU = "gpu"


@dataclass
class ResourceRequirement:
    """Resource requirement specification."""
    cpu_cores: int = 1
    memory_mb: int = 512
    disk_mb: int = 1024
    network_bandwidth: str = "default"
    gpu_count: int = 0
    exclusive: bool = False  # Requires exclusive access
    
    def __hash__(self) -> int:
        return hash((self.cpu_cores, self.memory_mb, self.disk_mb, 
                    self.network_bandwidth, self.gpu_count, self.exclusive))


@dataclass
class ScheduledTest:
    """Scheduled test representation."""
    id: str
    priority: int
    resources: ResourceRequirement
    callback: Callable
    scheduled_time: datetime
    estimated_duration: int = 3600  # seconds
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 2
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __lt__(self, other: 'ScheduledTest') -> bool:
        # Higher priority (lower number) comes first
        if self.priority != other.priority:
            return self.priority < other.priority
        # Earlier scheduled time comes first
        return self.scheduled_time < other.scheduled_time


@dataclass
class ResourceUsage:
    """Current resource usage tracking."""
    cpu_percent: float = 0.0
    memory_mb: int = 0
    disk_mb: int = 0
    network_active: bool = False
    gpu_usage: Dict[int, float] = field(default_factory=dict)
    active_tests: Set[str] = field(default_factory=set)


class TestScheduler:
    """Intelligent test scheduler with resource awareness."""
    
    def __init__(self, strategy: ScheduleStrategy = ScheduleStrategy.INTELLIGENT):
        self.strategy = strategy
        self.queue: List[ScheduledTest] = []
        self.running_tests: Dict[str, ScheduledTest] = {}
        self.completed_tests: Dict[str, ScheduledTest] = {}
        self.failed_tests: Dict[str, ScheduledTest] = {}
        
        self.resource_usage = ResourceUsage()
        self.resource_limits = self._get_resource_limits()
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        
        self._lock = Lock()
        self._shutdown_event = Event()
        self._scheduler_thread = Thread(target=self._scheduler_loop, daemon=True)
        self._resource_monitor_thread = Thread(target=self._resource_monitor_loop, daemon=True)
        
        # Performance tracking
        self.scheduling_history: deque = deque(maxlen=1000)
        self.performance_metrics: Dict[str, float] = {}
        
        # Start background threads
        self._scheduler_thread.start()
        self._resource_monitor_thread.start()
        
        logger.info(f"Test scheduler initialized with strategy: {strategy.value}")
        
    def _get_resource_limits(self) -> Dict[str, Any]:
        """Get system resource limits."""
        cpu_count = psutil.cpu_count()
        memory_mb = psutil.virtual_memory().total // (1024 * 1024)
        disk_mb = psutil.disk_usage('/').total // (1024 * 1024)
        
        return {
            'cpu_cores': cpu_count,
            'memory_mb': int(memory_mb * 0.8),  # Reserve 20% for system
            'disk_mb': int(disk_mb * 0.9),      # Reserve 10% for system
            'max_concurrent_tests': min(cpu_count * 2, 16)
        }
        
    def schedule_test(self, test_id: str, priority: int, 
                     resources: Dict[str, Any], callback: Callable,
                     dependencies: Optional[List[str]] = None,
                     estimated_duration: int = 3600,
                     tags: Optional[List[str]] = None) -> None:
        """Schedule a test for execution."""
        resource_req = ResourceRequirement(
            cpu_cores=resources.get('cpu_cores', 1),
            memory_mb=resources.get('memory_mb', 512),
            disk_mb=resources.get('disk_mb', 1024),
            network_bandwidth=resources.get('network_bandwidth', 'default'),
            gpu_count=resources.get('gpu_count', 0),
            exclusive=resources.get('exclusive', False)
        )
        
        scheduled_test = ScheduledTest(
            id=test_id,
            priority=priority,
            resources=resource_req,
            callback=callback,
            scheduled_time=datetime.now(),
            estimated_duration=estimated_duration,
            dependencies=dependencies or [],
            tags=tags or []
        )
        
        with self._lock:
            heapq.heappush(self.queue, scheduled_test)
            
            # Update dependency graph
            for dep in scheduled_test.dependencies:
                self.dependency_graph[test_id].add(dep)
                
            # Update metrics
            scheduled_tests.labels(priority=str(priority)).inc()
            queue_size.labels(priority=str(priority)).set(
                sum(1 for t in self.queue if t.priority == priority)
            )
            
        logger.info(f"Scheduled test {test_id} with priority {priority}")
        
    def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        while not self._shutdown_event.is_set():
            try:
                self._process_queue()
                time.sleep(1)  # Check every second
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                time.sleep(5)  # Wait longer on error
                
    def _process_queue(self) -> None:
        """Process the test queue based on scheduling strategy."""
        with self._lock:
            if not self.queue:
                return
                
            # Check if we can schedule any tests
            available_tests = self._get_schedulable_tests()
            
            for test in available_tests:
                if self._can_schedule_test(test):
                    # Remove from queue
                    self.queue.remove(test)
                    heapq.heapify(self.queue)
                    
                    # Start execution
                    self._execute_test(test)
                    break  # Schedule one at a time for now
                    
    def _get_schedulable_tests(self) -> List[ScheduledTest]:
        """Get tests that can be scheduled based on dependencies."""
        schedulable = []
        
        for test in self.queue:
            # Check if all dependencies are completed
            if self._dependencies_satisfied(test):
                schedulable.append(test)
                
        # Sort based on strategy
        if self.strategy == ScheduleStrategy.FIFO:
            schedulable.sort(key=lambda t: t.scheduled_time)
        elif self.strategy == ScheduleStrategy.PRIORITY:
            schedulable.sort(key=lambda t: (t.priority, t.scheduled_time))
        elif self.strategy == ScheduleStrategy.RESOURCE_AWARE:
            schedulable = self._sort_by_resource_efficiency(schedulable)
        elif self.strategy == ScheduleStrategy.LOAD_BALANCED:
            schedulable = self._sort_by_load_balance(schedulable)
        elif self.strategy == ScheduleStrategy.INTELLIGENT:
            schedulable = self._intelligent_sort(schedulable)
            
        return schedulable
        
    def _dependencies_satisfied(self, test: ScheduledTest) -> bool:
        """Check if test dependencies are satisfied."""
        for dep_id in test.dependencies:
            if dep_id not in self.completed_tests:
                return False
        return True
        
    def _can_schedule_test(self, test: ScheduledTest) -> bool:
        """Check if test can be scheduled based on resource availability."""
        # Check concurrent test limits
        if len(self.running_tests) >= self.resource_limits['max_concurrent_tests']:
            return False
            
        # Check resource availability
        current_cpu = sum(t.resources.cpu_cores for t in self.running_tests.values())
        current_memory = sum(t.resources.memory_mb for t in self.running_tests.values())
        current_disk = sum(t.resources.disk_mb for t in self.running_tests.values())
        
        if (current_cpu + test.resources.cpu_cores > self.resource_limits['cpu_cores'] or
            current_memory + test.resources.memory_mb > self.resource_limits['memory_mb'] or
            current_disk + test.resources.disk_mb > self.resource_limits['disk_mb']):
            
            resource_conflicts.inc()
            return False
            
        # Check exclusive access requirements
        if test.resources.exclusive and self.running_tests:
            return False
            
        if any(t.resources.exclusive for t in self.running_tests.values()):
            return False
            
        return True
        
    def _sort_by_resource_efficiency(self, tests: List[ScheduledTest]) -> List[ScheduledTest]:
        """Sort tests by resource efficiency."""
        def efficiency_score(test: ScheduledTest) -> float:
            # Calculate resource utilization efficiency
            cpu_ratio = test.resources.cpu_cores / self.resource_limits['cpu_cores']
            memory_ratio = test.resources.memory_mb / self.resource_limits['memory_mb']
            disk_ratio = test.resources.disk_mb / self.resource_limits['disk_mb']
            
            # Prefer tests that use resources more efficiently
            efficiency = (cpu_ratio + memory_ratio + disk_ratio) / 3
            
            # Factor in priority (lower priority number = higher priority)
            priority_factor = 1.0 / (test.priority + 1)
            
            return efficiency * priority_factor
            
        return sorted(tests, key=efficiency_score, reverse=True)
        
    def _sort_by_load_balance(self, tests: List[ScheduledTest]) -> List[ScheduledTest]:
        """Sort tests to balance system load."""
        def load_balance_score(test: ScheduledTest) -> float:
            # Calculate how well this test balances current load
            current_cpu_usage = self.resource_usage.cpu_percent
            current_memory_usage = (
                sum(t.resources.memory_mb for t in self.running_tests.values()) /
                self.resource_limits['memory_mb'] * 100
            )
            
            # Prefer tests that balance the load
            cpu_impact = test.resources.cpu_cores / self.resource_limits['cpu_cores'] * 100
            memory_impact = test.resources.memory_mb / self.resource_limits['memory_mb'] * 100
            
            # Balance score (lower is better for overloaded resources)
            cpu_balance = abs(current_cpu_usage + cpu_impact - 50)  # Target 50% usage
            memory_balance = abs(current_memory_usage + memory_impact - 50)
            
            balance_score = -(cpu_balance + memory_balance)  # Negative for reverse sort
            
            # Factor in priority
            priority_factor = 1.0 / (test.priority + 1)
            
            return balance_score * priority_factor
            
        return sorted(tests, key=load_balance_score, reverse=True)
        
    def _intelligent_sort(self, tests: List[ScheduledTest]) -> List[ScheduledTest]:
        """Intelligent sorting using historical performance data."""
        def intelligent_score(test: ScheduledTest) -> float:
            # Base score from priority
            priority_score = 1.0 / (test.priority + 1)
            
            # Resource efficiency score
            efficiency_score = self._calculate_efficiency_score(test)
            
            # Historical performance score
            performance_score = self._get_performance_score(test)
            
            # Time-based urgency score
            time_waiting = (datetime.now() - test.scheduled_time).total_seconds()
            urgency_score = min(time_waiting / 3600, 2.0)  # Cap at 2 hours
            
            # Combine scores with weights
            total_score = (
                priority_score * 0.4 +
                efficiency_score * 0.3 +
                performance_score * 0.2 +
                urgency_score * 0.1
            )
            
            return total_score
            
        return sorted(tests, key=intelligent_score, reverse=True)
        
    def _calculate_efficiency_score(self, test: ScheduledTest) -> float:
        """Calculate resource efficiency score."""
        cpu_ratio = test.resources.cpu_cores / self.resource_limits['cpu_cores']
        memory_ratio = test.resources.memory_mb / self.resource_limits['memory_mb']
        
        # Prefer balanced resource usage
        balance = 1.0 - abs(cpu_ratio - memory_ratio)
        utilization = (cpu_ratio + memory_ratio) / 2
        
        return balance * utilization
        
    def _get_performance_score(self, test: ScheduledTest) -> float:
        """Get performance score based on historical data."""
        # In a real implementation, this would use ML models or historical analysis
        
        # For now, use simple heuristics based on tags and patterns
        score = 0.5  # Default score
        
        if 'fast' in test.tags:
            score += 0.3
        if 'slow' in test.tags:
            score -= 0.2
        if 'critical' in test.tags:
            score += 0.4
        if 'experimental' in test.tags:
            score -= 0.1
            
        return max(0.0, min(1.0, score))
        
    def _execute_test(self, test: ScheduledTest) -> None:
        """Execute a scheduled test."""
        self.running_tests[test.id] = test
        
        # Update metrics
        scheduling_delay = (datetime.now() - test.scheduled_time).total_seconds()
        scheduling_delays.observe(scheduling_delay)
        scheduling_decisions.labels(
            strategy=self.strategy.value,
            outcome='scheduled'
        ).inc()
        
        # Execute asynchronously
        asyncio.create_task(self._run_test_async(test))
        
        logger.info(f"Started executing test {test.id}")
        
    async def _run_test_async(self, test: ScheduledTest) -> None:
        """Run test asynchronously."""
        try:
            start_time = time.time()
            
            # Execute the test callback
            if asyncio.iscoroutinefunction(test.callback):
                await test.callback()
            else:
                # Run in thread pool for blocking functions
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, test.callback)
                
            # Test completed successfully
            execution_time = time.time() - start_time
            
            with self._lock:
                self.running_tests.pop(test.id, None)
                self.completed_tests[test.id] = test
                
            # Update performance metrics
            self.performance_metrics[test.id] = execution_time
            self.scheduling_history.append({
                'test_id': test.id,
                'execution_time': execution_time,
                'estimated_time': test.estimated_duration,
                'accuracy': abs(execution_time - test.estimated_duration) / test.estimated_duration
            })
            
            logger.info(f"Test {test.id} completed in {execution_time:.2f}s")
            
        except Exception as e:
            # Test failed
            logger.error(f"Test {test.id} failed: {e}")
            
            with self._lock:
                self.running_tests.pop(test.id, None)
                
                # Retry if possible
                if test.retry_count < test.max_retries:
                    test.retry_count += 1
                    test.scheduled_time = datetime.now() + timedelta(seconds=30)  # Retry delay
                    heapq.heappush(self.queue, test)
                    logger.info(f"Rescheduling test {test.id} (retry {test.retry_count})")
                else:
                    self.failed_tests[test.id] = test
                    
    def _resource_monitor_loop(self) -> None:
        """Monitor system resources."""
        while not self._shutdown_event.is_set():
            try:
                self.resource_usage.cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                self.resource_usage.memory_mb = memory_info.used // (1024 * 1024)
                
                # Update running tests
                self.resource_usage.active_tests = set(self.running_tests.keys())
                
            except Exception as e:
                logger.error(f"Resource monitor error: {e}")
                
            time.sleep(5)  # Update every 5 seconds
            
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status."""
        with self._lock:
            return {
                'pending_tests': len(self.queue),
                'running_tests': len(self.running_tests),
                'completed_tests': len(self.completed_tests),
                'failed_tests': len(self.failed_tests),
                'resource_usage': {
                    'cpu_percent': self.resource_usage.cpu_percent,
                    'memory_mb': self.resource_usage.memory_mb,
                    'active_tests': list(self.resource_usage.active_tests)
                },
                'strategy': self.strategy.value
            }
            
    def get_test_status(self, test_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific test."""
        # Check running tests
        if test_id in self.running_tests:
            test = self.running_tests[test_id]
            return {
                'id': test.id,
                'status': 'running',
                'priority': test.priority,
                'scheduled_time': test.scheduled_time.isoformat(),
                'estimated_duration': test.estimated_duration
            }
            
        # Check completed tests
        if test_id in self.completed_tests:
            test = self.completed_tests[test_id]
            return {
                'id': test.id,
                'status': 'completed',
                'priority': test.priority,
                'scheduled_time': test.scheduled_time.isoformat(),
                'execution_time': self.performance_metrics.get(test_id, 0)
            }
            
        # Check failed tests
        if test_id in self.failed_tests:
            test = self.failed_tests[test_id]
            return {
                'id': test.id,
                'status': 'failed',
                'priority': test.priority,
                'retry_count': test.retry_count,
                'max_retries': test.max_retries
            }
            
        # Check pending tests
        with self._lock:
            for test in self.queue:
                if test.id == test_id:
                    return {
                        'id': test.id,
                        'status': 'pending',
                        'priority': test.priority,
                        'scheduled_time': test.scheduled_time.isoformat(),
                        'position_in_queue': self.queue.index(test) + 1
                    }
                    
        return None
        
    def cancel_test(self, test_id: str) -> bool:
        """Cancel a test execution."""
        # Cancel pending test
        with self._lock:
            for i, test in enumerate(self.queue):
                if test.id == test_id:
                    del self.queue[i]
                    heapq.heapify(self.queue)
                    logger.info(f"Cancelled pending test {test_id}")
                    return True
                    
        # Cancel running test (would need integration with execution engine)
        if test_id in self.running_tests:
            # In a real implementation, this would signal the running test to stop
            logger.info(f"Cancellation requested for running test {test_id}")
            return True
            
        return False
        
    def update_strategy(self, strategy: ScheduleStrategy) -> None:
        """Update scheduling strategy."""
        self.strategy = strategy
        logger.info(f"Updated scheduling strategy to: {strategy.value}")
        
    def get_performance_analysis(self) -> Dict[str, Any]:
        """Get performance analysis of scheduling decisions."""
        if not self.scheduling_history:
            return {'message': 'No historical data available'}
            
        total_tests = len(self.scheduling_history)
        avg_accuracy = sum(h['accuracy'] for h in self.scheduling_history) / total_tests
        
        return {
            'total_scheduled_tests': total_tests,
            'average_estimation_accuracy': avg_accuracy,
            'strategy_performance': {
                'current_strategy': self.strategy.value,
                'avg_scheduling_delay': sum(
                    h.get('scheduling_delay', 0) for h in self.scheduling_history
                ) / total_tests if total_tests > 0 else 0
            },
            'resource_efficiency': {
                'avg_cpu_utilization': self.resource_usage.cpu_percent,
                'current_memory_usage': self.resource_usage.memory_mb,
                'concurrent_tests': len(self.running_tests)
            }
        }
        
    def shutdown(self) -> None:
        """Shutdown the scheduler."""
        logger.info("Shutting down test scheduler...")
        self._shutdown_event.set()
        
        # Cancel all pending tests
        with self._lock:
            for test in self.queue:
                logger.info(f"Cancelling pending test {test.id}")
            self.queue.clear()
            
        # Wait for threads to finish
        if self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=10)
            
        if self._resource_monitor_thread.is_alive():
            self._resource_monitor_thread.join(timeout=10)
            
        logger.info("Test scheduler shutdown complete")


# Example usage
if __name__ == "__main__":
    def dummy_test():
        time.sleep(2)
        print("Test completed")
        
    scheduler = TestScheduler(ScheduleStrategy.INTELLIGENT)
    
    # Schedule some tests
    scheduler.schedule_test(
        "test1", priority=1, 
        resources={'cpu_cores': 2, 'memory_mb': 1024},
        callback=dummy_test
    )
    
    scheduler.schedule_test(
        "test2", priority=2,
        resources={'cpu_cores': 1, 'memory_mb': 512},
        callback=dummy_test,
        dependencies=['test1']
    )
    
    # Monitor status
    time.sleep(10)
    status = scheduler.get_queue_status()
    print(f"Queue status: {status}")
    
    scheduler.shutdown()